import json
import unittest
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from MAPE.workers.retrieve_worker import RetrieveWorker
from MAPE.workers.triage_worker import TriageWorker
from MQTT.client import MQTTClient
from MQTT.events import Event
from MQTT.worker import Worker
from knowledge.registry import IncidentRegistry, STATUS_RETRIEVED, STATUS_TRIAGED


class RecordingWorker(Worker):
    def handle_event(self, event):
        self.handled_event = event
        self._stop_event.set()


class WorkerInboxTests(unittest.TestCase):
    def setUp(self):
        self.mqtt_patcher = patch("MQTT.worker.MQTTClient")
        self.mqtt_patcher.start()

    def tearDown(self):
        self.mqtt_patcher.stop()

    def test_worker_persists_mqtt_event_for_durable_processing(self):
        registry = MagicMock()
        registry.receive_event.return_value = True
        worker = RecordingWorker(
            worker_name="retrieve-worker",
            input_topic="cyberresponse/incident/created",
            registry=registry,
        )
        event = Event.create(
            event_type="cyberresponse/incident/created",
            incident_id=12,
            payload={"raw_payload": {"host": "endpoint-1"}},
            producer="api",
        )
        message = MagicMock()
        message.topic = event.event_type
        message.payload = json.dumps(event.to_dict()).encode("utf-8")

        worker._on_message(message)

        registry.receive_event.assert_called_once()
        self.assertFalse(hasattr(worker, "_event_queue"))

    def test_processing_thread_claims_persisted_events_and_marks_them_done(self):
        event = Event.create(
            event_type="cyberresponse/incident/created",
            incident_id=12,
            payload={},
            producer="api",
        )
        registry = MagicMock()
        registry.claim_pending_event.side_effect = [event]
        worker = RecordingWorker(
            worker_name="retrieve-worker",
            input_topic=event.event_type,
            registry=registry,
        )

        worker._process_events()

        self.assertEqual(worker.handled_event, event)
        registry.claim_pending_event.assert_called_once_with(event_type=event.event_type)
        registry.mark_event_processed.assert_called_once_with(event.event_id)


class InboxClaimTests(unittest.TestCase):
    def test_claim_uses_skip_locked_and_returns_durable_event(self):
        cursor = MagicMock()
        cursor.fetchone.return_value = (
            "e294520e-6ec6-4e11-a461-854c1f5e021d",
            24,
            "cyberresponse/incident/created",
            "a9734b20-5d85-4430-94e9-cc0d595feabb",
            "api",
            datetime(2026, 10, 6, tzinfo=timezone.utc),
            {"source": "edr"},
        )
        connection = MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor

        with patch("knowledge.registry.transaction") as transaction:
            transaction.return_value.__enter__.return_value = connection
            event = IncidentRegistry(history_store=MagicMock()).claim_pending_event(
                "cyberresponse/incident/created"
            )

        sql = cursor.execute.call_args.args[0]
        self.assertIn("FOR UPDATE SKIP LOCKED", sql)
        self.assertIn("status = 'received'", sql)
        self.assertIn("attempts = attempts + 1", sql)
        self.assertEqual(event.event_id, "e294520e-6ec6-4e11-a461-854c1f5e021d")
        self.assertEqual(event.incident_id, 24)
        self.assertEqual(event.payload, {"source": "edr"})
        self.assertEqual(
            cursor.execute.call_args.args[1],
            ("cyberresponse/incident/created",),
        )

    def test_claim_returns_none_when_no_received_event_exists(self):
        cursor = MagicMock()
        cursor.fetchone.return_value = None
        connection = MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor

        with patch("knowledge.registry.transaction") as transaction:
            transaction.return_value.__enter__.return_value = connection
            event = IncidentRegistry(history_store=MagicMock()).claim_pending_event(
                "cyberresponse/incident/created"
            )

        self.assertIsNone(event)

    def test_idempotent_transition_does_not_create_a_second_outbox_event(self):
        cursor = MagicMock()
        cursor.fetchone.side_effect = [("new",), None, ("retrieved",), (1,)]
        connection = MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor
        registry = IncidentRegistry(history_store=MagicMock())
        key = "retrieve-worker:input-event:retrieved"

        with (
            patch("knowledge.registry.transaction") as transaction,
            patch("knowledge.registry.logging_agent.track", return_value=nullcontext()),
        ):
            transaction.return_value.__enter__.return_value = connection
            registry.transition(
                incident_id=24,
                status=STATUS_RETRIEVED,
                producer="retrieve-worker",
                payload={"context": "retrieved"},
                correlation_id="a9734b20-5d85-4430-94e9-cc0d595feabb",
                idempotency_key=key,
            )
            registry.transition(
                incident_id=24,
                status=STATUS_RETRIEVED,
                producer="retrieve-worker",
                payload={"context": "retrieved"},
                correlation_id="a9734b20-5d85-4430-94e9-cc0d595feabb",
                idempotency_key=key,
            )

        insert_calls = [
            call for call in cursor.execute.call_args_list
            if "INSERT INTO event_outbox" in call.args[0]
        ]
        self.assertEqual(len(insert_calls), 1)
        self.assertEqual(
            insert_calls[0].args[1][0],
            str(uuid.uuid5(uuid.NAMESPACE_URL, key)),
        )


class RetrieveWorkerTests(unittest.TestCase):
    def setUp(self):
        self.mqtt_patcher = patch("MQTT.worker.MQTTClient")
        self.mqtt_patcher.start()

    def tearDown(self):
        self.mqtt_patcher.stop()

    def test_retrieve_worker_emits_retrieved_transition_with_context(self):
        registry = MagicMock()
        registry.get_incident.return_value = {
            "id": 24,
            "source": "edr",
            "raw_payload": {"host": "endpoint-1"},
        }
        retrieve_agent = MagicMock()
        retrieve_agent.retrieve.return_value = {
            "query": "source: edr",
            "context": "Relevant security context",
        }
        worker = RetrieveWorker(registry=registry, retrieve_agent=retrieve_agent)
        worker.transition_incident = MagicMock()
        event = Event.create(
            event_type="cyberresponse/incident/created",
            incident_id=24,
            payload={},
            producer="api",
        )

        worker.handle_event(event)

        retrieve_agent.retrieve.assert_called_once_with(
            registry.get_incident.return_value,
            incident_id=24,
        )
        transition = worker.transition_incident.call_args.kwargs
        self.assertEqual(transition["status"], "retrieved")
        self.assertEqual(transition["payload"]["context"], "Relevant security context")
        self.assertEqual(transition["payload"]["original_event_id"], event.event_id)
        self.assertEqual(transition["correlation_id"], event.correlation_id)
        self.assertTrue(transition["idempotency_key"])

    def test_retrieve_worker_does_not_advance_when_retrieval_fails(self):
        registry = MagicMock()
        registry.get_incident.return_value = {"id": 24}
        retrieve_agent = MagicMock()
        retrieve_agent.retrieve.return_value = {"error": "index unavailable"}
        worker = RetrieveWorker(registry=registry, retrieve_agent=retrieve_agent)
        worker.transition_incident = MagicMock()
        event = Event.create(
            event_type="cyberresponse/incident/created",
            incident_id=24,
            payload={},
            producer="api",
        )

        with self.assertRaisesRegex(RuntimeError, "index unavailable"):
            worker.handle_event(event)

        worker.transition_incident.assert_not_called()


class TriageWorkerTests(unittest.TestCase):
    def setUp(self):
        self.mqtt_patcher = patch("MQTT.worker.MQTTClient")
        self.mqtt_patcher.start()

    def tearDown(self):
        self.mqtt_patcher.stop()

    def test_triage_worker_consumes_retrieved_context_and_emits_result(self):
        registry = MagicMock()
        incident = {
            "id": 24,
            "source": "edr",
            "raw_payload": {"host": "endpoint-1"},
        }
        registry.get_incident.return_value = incident
        triage_agent = MagicMock()
        triage_result = {
            "summary": "Suspicious process",
            "description": "Process execution requires investigation",
            "category": "execution",
            "severity": "high",
        }
        triage_agent.triage.return_value = triage_result
        worker = TriageWorker(registry=registry, triage_agent=triage_agent)
        worker.transition_incident = MagicMock()
        event = Event.create(
            event_type="cyberresponse/incident/retrieved",
            incident_id=24,
            payload={"context": "Relevant retrieved knowledge"},
            producer="retrieve-worker",
        )

        worker.handle_event(event)

        triage_agent.triage.assert_called_once_with(
            24,
            incident["raw_payload"],
            "edr",
            "Relevant retrieved knowledge",
        )
        transition = worker.transition_incident.call_args.kwargs
        self.assertEqual(transition["status"], STATUS_TRIAGED)
        self.assertEqual(transition["payload"]["triage"], triage_result)
        self.assertEqual(
            transition["payload"]["context"],
            "Relevant retrieved knowledge",
        )
        self.assertEqual(
            transition["payload"]["original_event_id"],
            event.event_id,
        )
        self.assertEqual(transition["correlation_id"], event.correlation_id)
        self.assertTrue(transition["idempotency_key"])

    def test_triage_worker_rejects_invalid_severity_without_advancing(self):
        registry = MagicMock()
        registry.get_incident.return_value = {
            "id": 24,
            "source": "edr",
            "raw_payload": {"host": "endpoint-1"},
        }
        triage_agent = MagicMock()
        triage_agent.triage.return_value = {"severity": "urgent"}
        worker = TriageWorker(registry=registry, triage_agent=triage_agent)
        worker.transition_incident = MagicMock()
        event = Event.create(
            event_type="cyberresponse/incident/retrieved",
            incident_id=24,
            payload={"context": ""},
            producer="retrieve-worker",
        )

        with self.assertRaisesRegex(RuntimeError, "invalid severity"):
            worker.handle_event(event)

        worker.transition_incident.assert_not_called()

    def test_triage_worker_requires_a_valid_raw_payload(self):
        registry = MagicMock()
        registry.get_incident.return_value = {
            "id": 24,
            "source": "edr",
            "raw_payload": None,
        }
        triage_agent = MagicMock()
        worker = TriageWorker(registry=registry, triage_agent=triage_agent)
        event = Event.create(
            event_type="cyberresponse/incident/retrieved",
            incident_id=24,
            payload={"context": ""},
            producer="retrieve-worker",
        )

        with self.assertRaisesRegex(RuntimeError, "raw payload"):
            worker.handle_event(event)

        triage_agent.triage.assert_not_called()


class ManualAcknowledgementTests(unittest.TestCase):
    def test_manual_ack_occurs_only_after_callback_succeeds(self):
        client = MQTTClient(brokers="localhost:1883", manual_ack=True)
        callback = MagicMock()
        client._subscriptions["test/topic"] = (1, callback)
        mqtt_client = MagicMock()
        message = MagicMock()
        message.topic = "test/topic"
        message.mid = 7
        message.qos = 1
        mqtt_client.ack.return_value = 0

        client._on_message(mqtt_client, None, message)
        mqtt_client.ack.assert_called_once_with(7, 1)

        callback.side_effect = RuntimeError("database unavailable")
        mqtt_client.reset_mock()
        with self.assertLogs("MQTT.client", level="ERROR"):
            client._on_message(mqtt_client, None, message)
        mqtt_client.ack.assert_not_called()
        mqtt_client.disconnect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
