import json
import logging
import threading
import uuid
from abc import ABC, abstractmethod
from typing import Optional
import paho.mqtt.client as mqtt
from MQTT.client import MQTTClient
from MQTT.events import Event
from knowledge.registry import IncidentRegistry

logger = logging.getLogger(__name__)

class Worker(ABC):

    def __init__(
        self,
        *,
        worker_name: str,
        input_topic: str,
        group: Optional[str] = None,
        client_id: Optional[str] = None,
        qos: int = 1,
        registry: Optional[IncidentRegistry] = None,
        poll_interval: float = 0.5,
        heartbeat_interval: float = 30.0,
    ):
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")
        if heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be greater than zero")

        self.worker_name = worker_name
        self.input_topic = input_topic
        self.group = group
        self.qos = qos
        self.poll_interval = poll_interval
        self.heartbeat_interval = heartbeat_interval
        self.worker_id = (client_id or f"{worker_name}-{uuid.uuid4().hex[:8]}")
        self.mqtt = MQTTClient(client_id=self.worker_id, manual_ack=True)
        self.registry = registry or IncidentRegistry()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None


    # MQTT TOPIC ----------------------------------------------------------------------------------------------------------------------------------------------------------     
    @property
    def subscription_topic(self) -> str:
        if self.group:
            return f"$share/{self.group}/{self.input_topic}"

        return self.input_topic

    # LIFECYCLE ----------------------------------------------------------------------------------------------------------------------------------------------------------     
    def start(self) -> None:
        logger.info("Starting worker name=%s id=%s", self.worker_name, self.worker_id)
        self.mqtt.connect()
        self.mqtt.subscribe(self.subscription_topic, qos=self.qos, callback=self._on_message)
        self._worker_thread = threading.Thread(target=self._process_events, name=f"worker-{self.worker_name}", daemon=True)
        self._worker_thread.start()
        logger.info("Worker started name=%s topic=%s", self.worker_name, self.subscription_topic)

    def run(self) -> None:
        self.start()
        logger.info("Worker %s waiting for events...", self.worker_name)

        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=1)

        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received by worker=%s", self.worker_name)

        finally:
            self.stop()

    def stop(self) -> None:
        if self._stop_event.is_set():
            return

        logger.info("Stopping worker name=%s id=%s", self.worker_name, self.worker_id)
        self._stop_event.set()

        if self._worker_thread is not None:
            self._worker_thread.join(timeout=5)

        self.mqtt.disconnect()

    # MESSAGE HANDLING ----------------------------------------------------------------------------------------------------------------------------------------------------------     
    def _on_message(
        self,
        message: mqtt.MQTTMessage,
    ) -> None:

        try:
            payload = message.payload.decode("utf-8")
            data = json.loads(payload)
            event = Event.from_dict(data)

        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            logger.exception("Failed to decode/parse MQTT message on topic=%s", message.topic)
            return

        try:
            inserted = self.registry.receive_event(event)
            if not inserted:
                logger.info("Duplicate event ignored event_id=%s", event.event_id)

        except Exception:
            logger.exception("Failed to persist event event_id=%s", event.event_id)
            raise

    def _process_events(self) -> None:
        while not self._stop_event.is_set():
            try:
                event = self.registry.claim_pending_event(event_type=self.input_topic)
            except Exception:
                logger.exception("Worker=%s failed to claim a pending event", self.worker_name)
                self._stop_event.wait(self.poll_interval)
                continue

            if event is None:
                self._stop_event.wait(self.poll_interval)
                continue

            heartbeat_stop = threading.Event()
            heartbeat_thread = threading.Thread(
                target=self._heartbeat_event,
                args=(event.event_id, heartbeat_stop),
                name=f"heartbeat-{self.worker_name}",
                daemon=True,
            )
            heartbeat_thread.start()
            try:
                self.handle_event(event)
                self.registry.mark_event_processed(event.event_id)

            except Exception as exc:
                logger.exception("Worker=%s failed processing event=%s", self.worker_name, event.event_id)
                try:
                    self.registry.mark_event_failed(event.event_id, str(exc))
                except Exception:
                    logger.exception("Worker=%s failed to record processing failure event=%s", self.worker_name, event.event_id)
            finally:
                heartbeat_stop.set()
                heartbeat_thread.join(timeout=self.heartbeat_interval + 1)

    def _heartbeat_event(self, event_id: str, stop_event: threading.Event) -> None:
        while not stop_event.wait(self.heartbeat_interval):
            try:
                if not self.registry.heartbeat_event(event_id):
                    logger.warning("Worker=%s lost processing lease for event=%s", self.worker_name, event_id)
                    return
            except Exception:
                logger.exception("Worker=%s failed to refresh processing lease for event=%s", self.worker_name, event_id)

    # BUSINESS LOGIC ----------------------------------------------------------------------------------------------------------------------------------------------------------     
    @abstractmethod
    def handle_event(self, event: Event) -> None:
        raise NotImplementedError

    # EVENT TRANSITION -------------------------------------------------------------------------
    def transition_incident(
        self,
        incident_id: int,
        status: str,
        payload: Optional[dict] = None,
        correlation_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> str:

        logger.info("Worker=%s transition incident_id=%s -> status=%s", self.worker_name, incident_id, status)
        return self.registry.transition(
            incident_id=incident_id,
            status=status,
            producer=self.worker_name,
            payload=payload or {},
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )
