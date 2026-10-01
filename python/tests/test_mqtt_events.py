import logging
import threading
import time
from MQTT.client import MQTTClient
from MQTT.events import Event
from MQTT.topics import INCIDENT_CREATED

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

received = threading.Event()

def on_message(message):
    print("\n=== MESSAGE RECEIVED ===")
    print("topic:", message.topic)
    print("payload:", message.payload.decode())
    print("========================\n")
    received.set()


def main():
    subscriber = MQTTClient(client_id="mqtt-test-subscriber")
    publisher = MQTTClient(client_id="mqtt-test-publisher")

    try:
        print("Connecting subscriber...")
        subscriber.connect()
        print("Subscriber connected to:", subscriber.connected_broker)
        subscriber.subscribe(INCIDENT_CREATED, qos=1, callback=on_message)

        time.sleep(0.5)

        print("Connecting publisher...")
        publisher.connect()
        print("Publisher connected to:", publisher.connected_broker)

        event = Event.create(
            event_type=INCIDENT_CREATED,
            incident_id=123,
            producer="mqtt-test",
            payload={
                "source": "test",
                "message": "MQTT test event",
            },
        )

        print("\nPublishing event...")
        publisher.publish(INCIDENT_CREATED, event.to_dict(), qos=1)

        if not received.wait(timeout=10):
            raise RuntimeError("Subscriber did not receive the message")

        print("\nTEST PASSED")

    finally:
        publisher.disconnect()
        subscriber.disconnect()


if __name__ == "__main__":
    main()