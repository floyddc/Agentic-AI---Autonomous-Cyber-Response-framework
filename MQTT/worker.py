import json
import logging
import signal
import threading
import uuid
from abc import ABC, abstractmethod
from typing import Optional
from queue import Queue, Empty
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
        registry: Optional[IncidentRegistry] = None
    ):
        self.worker_name = worker_name
        self.input_topic = input_topic
        self.group = group
        self.qos = qos
        self.worker_id = (client_id or f"{worker_name}-{uuid.uuid4().hex[:8]}")
        self.mqtt = MQTTClient(client_id=self.worker_id)
        self.registry = registry or IncidentRegistry()
        self._stop_event = threading.Event()
        self._event_queue: Queue[Event] = Queue()
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
                return
            self._event_queue.put(event)

        except Exception:
            logger.exception("Failed to persist event event_id=%s", event.event_id)

    def _process_events(self) -> None:
        while not self._stop_event.is_set():
            try:
                event = self._event_queue.get(timeout=1)
            except Empty:
                continue

            try:
                self.registry.mark_event_processing(event.event_id)
                self.handle_event(event)
                self.registry.mark_event_processed(event.event_id)

            except Exception as exc:
                logger.exception("Worker=%s failed processing event=%s", self.worker_name, event.event_id,)
                self.registry.mark_event_failed(event.event_id, str(exc))

            finally:
                self._event_queue.task_done()

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
    ) -> str:

        logger.info("Worker=%s transition incident_id=%s -> status=%s", self.worker_name, incident_id, status)
        return self.registry.transition(
            incident_id=incident_id,
            status=status,
            producer=self.worker_name,
            payload=payload or {},
            correlation_id=correlation_id,
        )
