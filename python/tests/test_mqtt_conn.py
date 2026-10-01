import logging
import time
from MQTT.client import MQTTClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)
TOPIC = "cyberresponse/test"


def on_message(message):
    logger.info("TEST RECEIVED: topic=%s payload=%s", message.topic, message.payload.decode())


def main():
    client = MQTTClient()
    client.connect()

    client.subscribe(TOPIC, qos=1, callback=on_message)
    time.sleep(1)

    payload = {
        "event_id": "mqtt-test-001",
        "message": "hello from cyber-response",
        "source": "python",
    }

    logger.info("Publishing test message")

    client.publish(TOPIC, payload, qos=1)
    time.sleep(2)
    
    client.disconnect()
    logger.info("MQTT test completed successfully")


if __name__ == "__main__":
    main()
