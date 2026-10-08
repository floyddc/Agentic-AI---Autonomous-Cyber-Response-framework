import unittest
from unittest.mock import MagicMock, patch

from MAPE.workers.action_planner_worker import ActionPlannerWorker
from MQTT.events import Event
from knowledge.registry import STATUS_ACTION_PROPOSED


class ActionPlannerWorkerTests(unittest.TestCase):
    def setUp(self):
        self.mqtt_patcher = patch("MQTT.worker.MQTTClient")
        self.mqtt_patcher.start()
        self.addCleanup(self.mqtt_patcher.stop)

    def create_worker(self, plan):
        registry = MagicMock()
        incident = {
            "id": 31,
            "source": "edr",
            "severity": "high",
            "raw_payload": {"host": "endpoint-2"},
        }
        registry.get_incident.return_value = incident
        planner = MagicMock()
        planner.propose_action_plan.return_value = plan
        worker = ActionPlannerWorker(
            registry=registry,
            action_planner_agent=planner,
        )
        worker.transition_incident = MagicMock()
        event = Event.create(
            event_type="cyberresponse/incident/triaged",
            incident_id=31,
            payload={
                "context": "Relevant retrieved context",
                "triage": {"severity": "high"},
            },
            producer="triage-worker",
        )
        return worker, registry, planner, event

    def test_proposes_action_plan_and_emits_action_proposed(self):
        plan = {
            "summary": "Contain suspicious endpoint",
            "actions": [
                {
                    "action": "isolate_host",
                    "target": "endpoint-2",
                    "justification": "Contain the suspected compromise",
                }
            ],
        }
        worker, registry, planner, event = self.create_worker(plan)

        worker.handle_event(event)

        planner.propose_action_plan.assert_called_once_with(
            registry.get_incident.return_value,
            "Relevant retrieved context",
            incident_id=event.incident_id,
        )
        transition = worker.transition_incident.call_args.kwargs
        self.assertEqual(transition["status"], STATUS_ACTION_PROPOSED)
        self.assertEqual(transition["payload"]["action_plan"], plan)
        self.assertEqual(
            transition["payload"]["context"],
            "Relevant retrieved context",
        )
        self.assertEqual(transition["payload"]["severity"], "high")
        self.assertEqual(
            transition["payload"]["original_event_id"],
            event.event_id,
        )
        self.assertEqual(transition["correlation_id"], event.correlation_id)
        self.assertEqual(
            transition["idempotency_key"],
            f"action-plan:{event.event_id}:{STATUS_ACTION_PROPOSED}",
        )

    def test_rejects_invalid_plan_without_emitting_transition(self):
        worker, _, _, event = self.create_worker({"summary": "Missing actions"})

        with self.assertRaisesRegex(RuntimeError, "actions list"):
            worker.handle_event(event)

        worker.transition_incident.assert_not_called()

    def test_rejects_non_object_plan_without_emitting_transition(self):
        worker, _, _, event = self.create_worker([])

        with self.assertRaisesRegex(RuntimeError, "invalid action plan"):
            worker.handle_event(event)

        worker.transition_incident.assert_not_called()

    def test_rejects_invalid_context_before_calling_planner(self):
        worker, _, planner, event = self.create_worker(
            {"actions": []}
        )
        event.payload["context"] = None

        with self.assertRaisesRegex(RuntimeError, "invalid context"):
            worker.handle_event(event)

        planner.propose_action_plan.assert_not_called()

    def test_rejects_invalid_triage_severity_before_planning(self):
        worker, _, planner, event = self.create_worker({"actions": []})
        event.payload["triage"]["severity"] = "urgent"

        with self.assertRaisesRegex(RuntimeError, "invalid severity"):
            worker.handle_event(event)

        planner.propose_action_plan.assert_not_called()
        worker.transition_incident.assert_not_called()


if __name__ == "__main__":
    unittest.main()
