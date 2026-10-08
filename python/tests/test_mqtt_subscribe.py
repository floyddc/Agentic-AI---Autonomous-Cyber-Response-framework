import threading
import unittest
from unittest.mock import patch

import paho.mqtt.client as mqtt

from MQTT.client import MQTTClient


class MqttSubscribeTests(unittest.TestCase):
    def test_subscribe_waits_for_successful_suback(self):
        with patch("MQTT.client.mqtt.Client") as client_factory:
            client = MQTTClient(connect_timeout=1)
            client._connected.set()
            subscribe_sent = threading.Event()
            client.client.subscribe.side_effect = lambda topic, qos: (
                subscribe_sent.set() or mqtt.MQTT_ERR_SUCCESS,
                42,
            )
            result = []
            failure = []

            def subscribe():
                try:
                    client.subscribe("test/topic")
                    result.append("ready")
                except Exception as exc:
                    failure.append(exc)

            thread = threading.Thread(target=subscribe)
            thread.start()
            self.assertTrue(subscribe_sent.wait(timeout=1))
            self.assertTrue(thread.is_alive())

            client._on_subscribe(None, None, 42, [0], None)
            thread.join(timeout=1)

            self.assertFalse(thread.is_alive())
            self.assertEqual(result, ["ready"])
            self.assertEqual(failure, [])
            client_factory.assert_called_once()

    def test_subscribe_raises_when_broker_rejects_subscription(self):
        with patch("MQTT.client.mqtt.Client"):
            client = MQTTClient(connect_timeout=1)
            client._connected.set()
            subscribe_sent = threading.Event()
            client.client.subscribe.side_effect = lambda topic, qos: (
                subscribe_sent.set() or mqtt.MQTT_ERR_SUCCESS,
                43,
            )

            failures = []

            def subscribe():
                try:
                    client.subscribe("test/topic")
                except Exception as exc:
                    failures.append(exc)

            thread = threading.Thread(target=subscribe)
            thread.start()
            self.assertTrue(subscribe_sent.wait(timeout=1))
            client._on_subscribe(None, None, 43, [128], None)
            thread.join(timeout=1)

            self.assertFalse(thread.is_alive())
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], RuntimeError)


if __name__ == "__main__":
    unittest.main()
