import unittest
from unittest.mock import MagicMock, patch

from MAPE.action_planner_agent import ActionPlannerAgent


class ActionPlannerAgentTests(unittest.TestCase):
    @patch("MAPE.action_planner_agent.logging_agent")
    def test_missing_actions_logs_safe_response_diagnostics(self, logging_agent):
        agent = object.__new__(ActionPlannerAgent)
        agent.model = "test-model"
        agent.client = MagicMock()
        agent.client.chat.return_value = {
            "message": {"content": '{"summary": "sensitive response text"}'}
        }
        agent.registry = MagicMock()
        agent.actions_catalog = {"actions": [{"action": "notify_analyst"}]}
        agent.allowed_actions = {"notify_analyst"}
        response_content = agent.client.chat.return_value["message"]["content"]

        with self.assertLogs("MAPE.action_planner_agent", level="ERROR") as captured:
            plan = agent.propose_action_plan(
                {"source": "test", "raw_payload": {}},
                "context",
                incident_id=42,
            )

        self.assertEqual(plan["actions"][0]["action"], "notify_analyst")
        log_output = "\n".join(captured.output)
        self.assertIn("incident_id=42", log_output)
        self.assertIn("model=test-model", log_output)
        self.assertIn("stage=plan_validation", log_output)
        self.assertIn("reason=invalid_action_plan", log_output)
        self.assertIn("received keys=['summary']", log_output)
        self.assertNotIn("sensitive response text", log_output)
        logging_agent.record.assert_called_once()
        metrics = logging_agent.record.call_args.kwargs
        self.assertEqual(metrics["status"], "fallback")
        self.assertEqual(metrics["details"]["fallback_reason"], "invalid_action_plan")
        self.assertEqual(metrics["details"]["response_chars"], len(response_content))


if __name__ == "__main__":
    unittest.main()
