import json
import logging
import signal
import threading
import time
import uuid
from typing import Any, Dict, List, Optional
from MQTT.client import MQTTClient
from postgres.db import transaction
from RAG import config

logger = logging.getLogger(__name__)

class OutboxPublisher:

    def __init__(
        self,
        *,
        publisher_name: str = "outbox-publisher",
        batch_size: int = 50,
        poll_interval: float = 1.0,
        qos: int = 1,
        client_id: Optional[str] = None,
    ):
        self.publisher_name = publisher_name
        self.batch_size = batch_size
        self.poll_interval = poll_interval
        self.qos = qos
        self.publisher_id = (client_id or f"{publisher_name}-{uuid.uuid4().hex[:8]}")
        self.mqtt = MQTTClient(client_id=self.publisher_id)
        self._stop_event = threading.Event()

    # LIFECYCLE ----------------------------------------------------------------------------------------------------------------------------------------------------------     
    def start(self) -> None:
        logger.info("Starting outbox publisher name=%s id=%s", self.publisher_name, self.publisher_id)
        self.mqtt.connect()

    def run(self) -> None:
        self.start()
        logger.info("Outbox publisher %s waiting for events...", self.publisher_name)
        try:
            while not self._stop_event.is_set():
                processed = self.publish_batch()
                if processed == 0:
                    self._stop_event.wait(self.poll_interval)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
        finally:
            self.stop()

    def stop(self) -> None:
        if self._stop_event.is_set():
            return
        logger.info("Stopping outbox publisher name=%s id=%s", self.publisher_name, self.publisher_id)
        self._stop_event.set()
        self.mqtt.disconnect()

    # OUTBOX ----------------------------------------------------------------------------------------------------------------------------------------------------------     
    def publish_batch(self) -> int:
        with transaction(config.POSTGRES_OPERATIONAL_DB) as conn:
            
            with conn.cursor() as cur:

                cur.execute(
                    """
                    SELECT event_id, incident_id, event_type, correlation_id, producer, topic, payload
                    FROM event_outbox
                    WHERE published_at IS NULL AND attempts < 5
                    ORDER BY created_at ASC
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                    """,
                    (self.batch_size,)
                )
                rows = cur.fetchall()
                if not rows:
                    return 0

                for event_id, incident_id, event_type, correlation_id, producer, topic, payload in rows:
                    try:
                        self._publish(topic=topic, payload=payload)

                        cur.execute(
                            """
                            UPDATE event_outbox
                            SET published_at = now(), last_error = NULL
                            WHERE event_id = %s
                            """,
                            (event_id,),
                        )
                    except Exception as exc:
                        logger.error("Failed to publish outbox event_id=%s: %s", event_id, exc)
                        cur.execute(
                            """
                            UPDATE event_outbox
                            SET attempts = attempts + 1,
                                last_attempt_at = now(),
                                last_error = %s
                            WHERE event_id = %s
                            """,
                            (str(exc), event_id),
                        )
                return len(rows)

    # MQTT ----------------------------------------------------------------------------------------------------------------------------------------------------------     
    def _publish(
        self,
        *,
        topic: str,
        payload: Dict[str, Any],
    ) -> None:
        info = self.mqtt.publish(topic, payload, qos=self.qos)
        if info is not None and hasattr(info, "wait_for_publish"):
            info.wait_for_publish(timeout=10)
        logger.debug("MQTT publish completed topic=%s", topic)