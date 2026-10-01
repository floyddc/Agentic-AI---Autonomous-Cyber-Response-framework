import logging
import threading
import time
import json
from MQTT.client import MQTTClient
from MQTT.events import Event
from MQTT.topics import (INCIDENT_CREATED, INCIDENT_RETRIEVED)
from MQTT.outbox_publisher import OutboxPublisher
from postgres.db import transaction
from RAG import config
from .test_retrieve_worker import TestRetrieveWorker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)

def main():
    received_event = threading.Event()
    received_data = {}

    subscriber = MQTTClient(client_id="mqtt-test-worker-subscriber")

    def on_retrieved(message):
        logger.info("OUTPUT RECEIVED topic=%s payload=%s", message.topic, message.payload.decode("utf-8", errors="replace"))
        received_data["payload"] = message.payload.decode("utf-8", errors="replace")
        received_event.set()

    logger.info("Connecting output subscriber...")
    subscriber.connect()
    subscriber.subscribe(INCIDENT_RETRIEVED, qos=1, callback=on_retrieved)
    time.sleep(0.5)

    outbox = OutboxPublisher(publisher_name="test-worker-outbox", poll_interval=0.2)
    outbox_thread = threading.Thread(target=outbox.run, daemon=True)
    outbox_thread.start()

    worker = TestRetrieveWorker()
    worker_thread = threading.Thread(target=worker.run, name="test-retrieve-worker", daemon=True)

    logger.info("Starting retrieve worker...")
    worker_thread.start()
    time.sleep(1)

    with transaction(config.POSTGRES_OPERATIONAL_DB) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO incidents (source, summary, description, severity)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                ("test", "Worker end-to-end test", "Test incident", "low"),
            )
            incident_id = cur.fetchone()[0]

    input_event = Event.create(
        event_type=INCIDENT_CREATED,
        incident_id=incident_id,
        producer="test-worker",
        payload={
            "source": "test",
            "message": "Worker end-to-end test",
        },
    )

    logger.info("Publishing input event event_id=%s incident_id=%s", input_event.event_id, input_event.incident_id)
    publisher = MQTTClient(client_id="mqtt-test-worker-publisher")
    publisher.connect()
    publisher.publish(INCIDENT_CREATED, input_event.to_dict(), qos=1)

    logger.info("Waiting for worker output...")

    if not received_event.wait(timeout=10):
        raise AssertionError("Worker did not publish INCIDENT_RETRIEVED within 10 seconds")

    logger.info("Worker output received successfully")

    output_event = Event.from_dict(json.loads(received_data["payload"]))

    assert output_event.event_type == INCIDENT_RETRIEVED
    assert output_event.incident_id == input_event.incident_id
    assert output_event.correlation_id == input_event.correlation_id
    assert output_event.producer == worker.worker_name
    assert output_event.payload["status"] == "retrieved"
    assert output_event.payload["original_event_id"] == input_event.event_id

    print()
    print("=" * 60)
    print("TEST PASSED")
    print("=" * 60)
    print(f"Input event:  {input_event.event_id}")
    print(f"Output event: {output_event.event_id}")
    print(f"Incident ID:  {output_event.incident_id}")
    print(f"Correlation:  {output_event.correlation_id}")
    print(f"Producer:     {output_event.producer}")
    print("=" * 60)

    publisher.disconnect()
    subscriber.disconnect()

    worker.stop()
    worker_thread.join(timeout=5)
    outbox.stop()
    outbox_thread.join(timeout=5)


if __name__ == "__main__":
    main()