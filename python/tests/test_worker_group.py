import json
import logging
import threading
import time
from knowledge.registry import IncidentRegistry
from MQTT.client import MQTTClient
from MQTT.events import Event
from MQTT.topics import INCIDENT_CREATED, INCIDENT_RETRIEVED
from MQTT.outbox_publisher import OutboxPublisher
from .test_retrieve_worker import TestRetrieveWorker
from postgres.db import transaction
import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)

NUM_EVENTS = 10


def main():
    received_event = threading.Event()
    received_events = []
    received_lock = threading.Lock()

    subscriber = MQTTClient(client_id="mqtt-test-group-subscriber")

    def on_retrieved(message):
        try:
            data = json.loads(message.payload.decode("utf-8"))
            event = Event.from_dict(data)

            with received_lock:
                received_events.append(event)
                count = len(received_events)

            logger.info("OUTPUT %d/%d: event=%s incident=%s producer=%s", count, NUM_EVENTS, event.event_id, event.incident_id, event.producer)

            if count >= NUM_EVENTS:
                received_event.set()

        except Exception:
            logger.exception("Failed to process output event")

    def create_test_incident(i: int) -> int:
        with transaction(config.POSTGRES_OPERATIONAL_DB) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO incidents (
                        source,
                        summary,
                        description,
                        severity
                    )
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        "test",
                        f"Group test event {i}",
                        f"Test incident {i}",
                        "low",
                    ),
                )

                return cur.fetchone()[0]

    logger.info("Connecting output subscriber...")
    subscriber.connect()
    subscriber.subscribe(INCIDENT_RETRIEVED, qos=1, callback=on_retrieved)
    time.sleep(0.5)

    outbox = OutboxPublisher(publisher_name="test-group-outbox", poll_interval=0.2)
    outbox_thread = threading.Thread(target=outbox.run, daemon=True)
    outbox_thread.start()

    worker1 = TestRetrieveWorker(worker_name="retrieve-worker-1")
    worker2 = TestRetrieveWorker(worker_name="retrieve-worker-2")

    logger.info("Starting worker 1...")
    worker1.start()
    logger.info("Starting worker 2...")
    worker2.start()

    time.sleep(2)

    publisher = MQTTClient(client_id="mqtt-test-group-publisher")
    publisher.connect()

    logger.info("Creating %d test incidents...", NUM_EVENTS)

    incident_ids = [
        create_test_incident(i)
        for i in range(NUM_EVENTS)
    ]
    logger.info("Created incidents: %s", incident_ids)

    logger.info("Publishing %d INCIDENT_CREATED events...", NUM_EVENTS)
    input_events = []

    for i, incident_id in enumerate(incident_ids):
        event = Event.create(
            event_type=INCIDENT_CREATED,
            incident_id=incident_id,
            producer="test-worker-group",
            payload={
                "source": "test",
                "message": f"Group test event {i}",
            },
        )
        input_events.append(event)
        publisher.publish(INCIDENT_CREATED, event.to_dict(), qos=1)
    
    logger.info("Waiting for %d output events...", NUM_EVENTS)

    if not received_event.wait(timeout=15):
        with received_lock:
            received_count = len(received_events)
        raise AssertionError(f"Expected {NUM_EVENTS} output events, received {received_count}")

    logger.info("All output events received")

    with received_lock:
        outputs = list(received_events)

    assert len(outputs) == NUM_EVENTS

    input_ids = {event.event_id for event in input_events}
    output_original_ids = {event.payload["original_event_id"] for event in outputs}

    assert output_original_ids == input_ids

    producers = {event.producer for event in outputs}
    logger.info("Workers that processed events: %s", producers)

    assert len(producers) >= 1
    assert producers <= {worker1.worker_name, worker2.worker_name}

    print()
    print("=" * 70)
    print("TWO-WORKER GROUP TEST PASSED")
    print("=" * 70)
    print(f"Input events:   {NUM_EVENTS}")
    print(f"Output events:  {len(outputs)}")
    print(f"Workers used:   {', '.join(sorted(producers))}")
    print("=" * 70)

    publisher.disconnect()
    subscriber.disconnect()

    worker1.stop()
    worker2.stop()

    outbox.stop()
    outbox_thread.join(timeout=5)


if __name__ == "__main__":
    main()