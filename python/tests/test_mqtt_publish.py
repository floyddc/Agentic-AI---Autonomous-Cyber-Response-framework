import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from MQTT.client import MQTTClient
from MQTT.outbox_publisher import OutboxPublisher


class MqttPublishTests(unittest.TestCase):
    def make_client(self, reason_code):
        client = MQTTClient(brokers="localhost:1883", client_id="publish-test")
        client._connected.set()
        message_info = MagicMock()
        message_info.mid = 17
        message_info.rc = 0
        message_info.wait_for_publish.return_value = None
        client.client.publish = MagicMock(return_value=message_info)

        def publish(*args, **kwargs):
            client._on_publish(
                client.client,
                None,
                17,
                reason_code,
                None,
            )
            return message_info

        client.client.publish.side_effect = publish
        return client, message_info

    def test_publish_succeeds_when_puback_is_success(self):
        client, message_info = self.make_client(0)

        client.publish("test/topic", {"event": "test"}, qos=1)

        message_info.wait_for_publish.assert_called_once()
        self.assertNotIn(17, client._publish_reasons)

    def test_publish_raises_when_broker_reports_no_matching_subscribers(self):
        client, message_info = self.make_client(16)

        with self.assertRaisesRegex(
            RuntimeError,
            "MQTT publish rejected: topic=test/topic, reason=16",
        ):
            client.publish("test/topic", {"event": "test"}, qos=1)

        message_info.wait_for_publish.assert_called_once()

    def test_outbox_keeps_rejected_message_pending_for_retry(self):
        cursor = MagicMock()
        cursor.fetchall.return_value = [
            (
                "event-1",
                1,
                "event-type",
                "correlation-1",
                "producer",
                "test/topic",
                {"event": "test"},
            )
        ]
        connection = MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor
        publisher = OutboxPublisher.__new__(OutboxPublisher)
        publisher.batch_size = 10
        publisher._publish = MagicMock(
            side_effect=RuntimeError("No matching subscribers")
        )

        with patch("MQTT.outbox_publisher.transaction") as transaction:
            transaction.return_value.__enter__.return_value = connection
            processed = publisher.publish_batch()

        select_query = cursor.execute.call_args_list[0].args[0]
        self.assertNotIn("attempts < 5", select_query)
        self.assertIn("last_attempt_at", select_query)
        self.assertEqual(processed, 1)
        update_queries = [
            call.args[0] for call in cursor.execute.call_args_list[1:]
        ]
        self.assertTrue(any("attempts = attempts + 1" in query for query in update_queries))
        self.assertFalse(any("published_at = now()" in query for query in update_queries))


if __name__ == "__main__":
    unittest.main()
