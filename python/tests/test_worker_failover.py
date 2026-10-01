import logging
import threading
import time
import json
from MQTT.client import MQTTClient
from MQTT.events import Event
from MQTT.topics import INCIDENT_CREATED, INCIDENT_RETRIEVED
from MQTT.outbox_publisher import OutboxPublisher
from postgres.db import transaction
from RAG import config
from .test_retrieve_worker import TestRetrieveWorker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)

FIRST_BATCH = 10
SECOND_BATCH = 10
TIMEOUT = 15

def main():
    received_event = threading.Event()
    received_events = []

    subscriber = MQTTClient(client_id="mqtt-test-failover-subscriber")

    def on_retrieved(message):
        payload = message.payload.decode("utf-8", errors="replace")
        logger.info("OUTPUT RECEIVED topic=%s payload=%s", message.topic, payload)

        try:
            event = Event.from_dict(json.loads(payload))
            received_events.append(event)
            logger.info("OUTPUT %d: incident=%s producer=%s", len(received_events), event.incident_id, event.producer)
            received_event.set()

        except Exception:
            logger.exception("Failed to parse output event")

    logger.info("Connecting output subscriber...")
    subscriber.connect()
    subscriber.subscribe(INCIDENT_RETRIEVED, qos=1, callback=on_retrieved)
    time.sleep(0.5)

    outbox = OutboxPublisher(publisher_name="test-failover-outbox", poll_interval=0.2)
    outbox_thread = threading.Thread(target=outbox.run, daemon=True)
    outbox_thread.start()

    def create_test_incident(summary: str) -> int:
        with transaction(config.POSTGRES_OPERATIONAL_DB) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO incidents (source, summary, description, severity)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                    """,
                    ("failover-test", summary, "", "low"),
                )
                return cur.fetchone()[0]

    worker1 = TestRetrieveWorker(worker_name="retrieve-worker-1")
    worker2 = TestRetrieveWorker(worker_name="retrieve-worker-2")
    
    worker1_thread = threading.Thread(target=worker1.run, name="retrieve-worker-1-thread", daemon=True)
    worker2_thread = threading.Thread(target=worker2.run, name="retrieve-worker-2-thread", daemon=True)

    logger.info("Starting worker 1...")
    worker1_thread.start()
    logger.info("Starting worker 2...")
    worker2_thread.start()

    time.sleep(2)

    publisher = MQTTClient(client_id="mqtt-test-failover-publisher")
    publisher.connect()

    first_batch_ids = set()
    first_events = []
    logger.info("Publishing first batch: %d incidents...", FIRST_BATCH)

    for i in range(FIRST_BATCH):
        inc_id = create_test_incident(f"First batch {i}")
        first_batch_ids.add(inc_id)
        event = Event.create(
            event_type=INCIDENT_CREATED,
            incident_id=inc_id,
            producer="test-worker-failover",
            payload={
                "source": "failover-test",
                "message": f"First batch event {i}",
                "batch": 1,
            },
        )
        first_events.append(event)
        publisher.publish(INCIDENT_CREATED, event.to_dict(), qos=1)

    logger.info("First batch published. Waiting briefly while workers process...")
    time.sleep(1.0)

    logger.info("Stopping worker 1 while worker group is active...")
    worker1.stop()
    worker1_thread.join(timeout=5)
    logger.info("Worker 1 stopped alive=%s", worker1_thread.is_alive())

    if worker1_thread.is_alive():
        raise AssertionError("Worker 1 did not stop correctly")

    second_batch_ids = set()
    second_events = []
    logger.info("Publishing second batch: %d incidents...", SECOND_BATCH)

    for i in range(SECOND_BATCH):
        inc_id = create_test_incident(f"Second batch {i}")
        second_batch_ids.add(inc_id)
        event = Event.create(
            event_type=INCIDENT_CREATED,
            incident_id=inc_id,
            producer="test-worker-failover",
            payload={
                "source": "failover-test",
                "message": f"Second batch event {i}",
                "batch": 2,
            },
        )
        second_events.append(event)
        publisher.publish(INCIDENT_CREATED, event.to_dict(), qos=1)

    logger.info("Waiting for second batch to be processed by worker 2...")
    deadline = time.time() + TIMEOUT

    while time.time() < deadline:
        second_batch_outputs = [
            event for event in received_events
            if event.incident_id in second_batch_ids
        ]

        if len(second_batch_outputs) >= SECOND_BATCH:
            break

        time.sleep(0.1)

    logger.info("Total outputs received: %d", len(received_events))

    first_output_ids = {
        event.incident_id for event in received_events
        if event.incident_id in first_batch_ids
    }

    second_output_ids = {
        event.incident_id for event in received_events
        if event.incident_id in second_batch_ids
    }

    if len(second_output_ids) != SECOND_BATCH:
        raise AssertionError(f"Worker 2 did not process all second-batch events: expected={SECOND_BATCH}, received={len(second_output_ids)}")

    all_incident_ids = [event.incident_id for event in received_events]
    unique_incident_ids = set(all_incident_ids)

    if len(all_incident_ids) != len(unique_incident_ids):
        raise AssertionError("Duplicate output events detected")

    second_batch_workers = {
        event.producer for event in received_events
        if event.incident_id in second_batch_ids
    }

    if second_batch_workers != {"retrieve-worker-2"}:
        raise AssertionError(f"Second batch was not exclusively processed by worker 2: {second_batch_workers}")

    if second_output_ids != second_batch_ids:
        missing = second_batch_ids - second_output_ids
        unexpected = second_output_ids - second_batch_ids
        raise AssertionError(f"Second batch mismatch. missing={missing}, unexpected={unexpected}")

    for event in received_events:
        assert event.event_type == INCIDENT_RETRIEVED
        assert event.payload["status"] == "retrieved"

    print()
    print("=" * 70)
    print("WORKER FAILOVER TEST PASSED")
    print("=" * 70)
    print(f"First batch:             {FIRST_BATCH}")
    print(f"First batch outputs:     {len(first_output_ids)}")
    print(f"Second batch:            {SECOND_BATCH}")
    print(f"Second batch outputs:    {len(second_output_ids)}")
    print(f"Total unique outputs:    {len(unique_incident_ids)}")
    print("Worker 1:                STOPPED")
    print("Worker 2:                CONTINUED PROCESSING")
    print("Duplicates:              0")
    print("=" * 70)

    publisher.disconnect()
    subscriber.disconnect()

    worker2.stop()
    worker2_thread.join(timeout=5)
    outbox.stop()
    outbox_thread.join(timeout=5)

    logger.info("Failover test cleanup completed")


if __name__ == "__main__":
    main()