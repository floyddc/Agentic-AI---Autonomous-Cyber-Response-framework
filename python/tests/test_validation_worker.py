import unittest
from unittest.mock import MagicMock, patch

from MAPE.workers.validation_worker import ValidationWorker
from MQTT.events import Event
from knowledge.registry import (
    STATUS_AWAITING_HUMAN_APPROVAL,
    STATUS_FAILED,
    STATUS_VALIDATED,
)


class ValidationWorkerTests(unittest.TestCase):
    def setUp(self):
        self.mqtt_patcher = patch("MQTT.worker.MQTTClient")
        self.mqtt_patcher.start()
        self.addCleanup(self.mqtt_patcher.stop)

    def create_worker(self, validation_response, severity="high"):
        registry = MagicMock()
        registry.get_incident.return_value = {"id": 31, "severity": severity}
        validator = MagicMock()
        validator.validate.return_value = validation_response
        worker = ValidationWorker(
            registry=registry,
            validation_agent=validator,
        )
        worker.transition_incident = MagicMock()
        event = Event.create(
            event_type="cyberresponse/incident/action-proposed",
            incident_id=31,
            payload={
                "action_plan": {
                    "summary": "Contain endpoint",
                    "actions": [{"action": "isolate_host", "target": "endpoint-2"}],
                },
                "severity": severity,
                "context": "Retrieved context",
            },
            producer="action-planner-worker",
        )
        return worker, validator, event

    def test_valid_plan_emits_action_validated_with_triage_severity(self):
        result = {
            "valid": True,
            "approved_actions": [{"action": "isolate_host", "target": "endpoint-2"}],
            "reasons": [],
            "requires_human_approval": False,
        }
        worker, validator, event = self.create_worker((True, result))

        worker.handle_event(event)

        validator.validate.assert_called_once_with(
            event.incident_id,
            event.payload["action_plan"],
            "high",
        )
        transition = worker.transition_incident.call_args.kwargs
        self.assertEqual(transition["status"], STATUS_VALIDATED)
        self.assertEqual(transition["payload"]["approved_actions"], result["approved_actions"])
        self.assertEqual(transition["payload"]["severity"], "high")
        self.assertEqual(transition["payload"]["original_event_id"], event.event_id)
        self.assertEqual(transition["correlation_id"], event.correlation_id)
        self.assertEqual(
            transition["idempotency_key"],
            f"validation:{event.event_id}:{STATUS_VALIDATED}",
        )

    def test_valid_plan_requiring_approval_emits_approval_required(self):
        result = {
            "valid": True,
            "approved_actions": [
                {
                    "action": "isolate_host",
                    "target": "endpoint-2",
                    "requires_human_approval": True,
                }
            ],
            "reasons": [],
            "requires_human_approval": False,
        }
        worker, _, event = self.create_worker((True, result))

        worker.handle_event(event)

        transition = worker.transition_incident.call_args.kwargs
        self.assertEqual(transition["status"], STATUS_AWAITING_HUMAN_APPROVAL)
        self.assertTrue(transition["payload"]["requires_human_approval"])
        self.assertEqual(transition["payload"]["approved_actions"], result["approved_actions"])

    def test_rejected_plan_emits_failed_status(self):
        result = {
            "valid": False,
            "approved_actions": [],
            "reasons": ["action is blocked by policy"],
            "requires_human_approval": False,
        }
        worker, _, event = self.create_worker((False, result))

        worker.handle_event(event)

        transition = worker.transition_incident.call_args.kwargs
        self.assertEqual(transition["status"], STATUS_FAILED)
        self.assertEqual(transition["payload"]["validation"], result)

    def test_missing_or_invalid_severity_fails_before_validation(self):
        result = {
            "valid": True,
            "approved_actions": [{"action": "isolate_host"}],
            "reasons": [],
            "requires_human_approval": False,
        }
        worker, validator, event = self.create_worker((True, result))
        event.payload["severity"] = "urgent"

        with self.assertRaisesRegex(RuntimeError, "invalid severity"):
            worker.handle_event(event)

        validator.validate.assert_not_called()
        worker.transition_incident.assert_not_called()

    def test_invalid_validation_agent_result_does_not_advance(self):
        worker, _, event = self.create_worker({"valid": True})

        with self.assertRaisesRegex(RuntimeError, "invalid result"):
            worker.handle_event(event)

        worker.transition_incident.assert_not_called()


if __name__ == "__main__":
    unittest.main()
