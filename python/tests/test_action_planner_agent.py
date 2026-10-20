import unittest
from unittest.mock import MagicMock, patch

import config
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
        agent.actions_catalog = {
            "actions": [
                {"action": "notify_analyst", "required_fields": []}
            ]
        }
        agent.actions_by_name = {
            "notify_analyst": agent.actions_catalog["actions"][0]
        }
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

    def test_action_plan_requires_catalog_fields(self):
        agent = object.__new__(ActionPlannerAgent)
        agent.actions_by_name = {
            "isolate_host": {
                "action": "isolate_host",
                "required_fields": ["target"],
            }
        }
        agent.allowed_actions = set(agent.actions_by_name)

        with self.assertRaisesRegex(ValueError, "missing required fields"):
            agent._parse_action_plan(
                '{"summary":"Contain","actions":[{"action":"isolate_host",'
                '"justification":"Contain suspected activity."}]}'
            )

    def test_action_plan_rejects_fields_not_allowed_by_catalog_entry(self):
        agent = object.__new__(ActionPlannerAgent)
        agent.actions_by_name = {
            "block_ip": {
                "action": "block_ip",
                "required_fields": ["target"],
                "target_type": "ip_address",
            }
        }
        agent.allowed_actions = set(agent.actions_by_name)

        with self.assertRaisesRegex(ValueError, "unsupported fields: \\['endpoint'\\]"):
            agent._parse_action_plan(
                '{"summary":"Block indicator","actions":[{"action":"block_ip",'
                '"target":"209.97.189.32","endpoint":"srvprobe",'
                '"justification":"Block the IP from the alert."}]}',
                incident={"raw_payload": {"ip": "209.97.189.32"}},
            )

    def test_action_plan_rejects_invalid_typed_targets_and_targetless_action_fields(self):
        agent = object.__new__(ActionPlannerAgent)
        agent.actions_by_name = {
            "block_ip": {
                "action": "block_ip",
                "required_fields": ["target"],
                "target_type": "ip_address",
            },
            "notify_analyst": {
                "action": "notify_analyst",
                "required_fields": [],
            },
        }
        agent.allowed_actions = set(agent.actions_by_name)

        with self.assertRaisesRegex(ValueError, "invalid target for target type 'ip_address'"):
            agent._parse_action_plan(
                '{"summary":"Block indicator","actions":[{"action":"block_ip",'
                '"target":"ip","justification":"Block the IP."}]}',
                incident={"raw_payload": {"ip": "209.97.189.32"}},
            )

        with self.assertRaisesRegex(ValueError, "unsupported fields: \\['target'\\]"):
            agent._parse_action_plan(
                '{"summary":"Escalate","actions":[{"action":"notify_analyst",'
                '"target":"analyst","justification":"Review the incident."}]}',
                incident={"raw_payload": {}},
            )

    @patch("MAPE.action_planner_agent.logging_agent")
    def test_invalid_action_fields_are_retried_with_catalog_feedback(self, logging_agent):
        agent = object.__new__(ActionPlannerAgent)
        agent.model = "test-model"
        agent.client = MagicMock()
        agent.client.chat.side_effect = [
            {
                "message": {
                    "content": (
                        '{"summary":"Block indicator","actions":[{"action":"block_ip",'
                        '"target":"209.97.189.32","endpoint":"srvprobe",'
                        '"justification":"Block the IP from the alert."}]}'
                    )
                }
            },
            {
                "message": {
                    "content": (
                        '{"summary":"Block indicator","actions":[{"action":"block_ip",'
                        '"target":"209.97.189.32",'
                        '"justification":"Block the IP from the alert."}]}'
                    )
                }
            },
        ]
        agent.registry = MagicMock()
        agent.actions_catalog = {
            "actions": [
                {
                    "action": "block_ip",
                    "description": "Block an IP",
                    "required_fields": ["target"],
                    "target_type": "ip_address",
                    "planning_guidance": "Use the IP in the alert.",
                }
            ]
        }
        agent.actions_by_name = {
            "block_ip": agent.actions_catalog["actions"][0]
        }
        agent.allowed_actions = set(agent.actions_by_name)

        plan = agent.propose_action_plan(
            {"source": "edr", "raw_payload": {"ip": "209.97.189.32"}},
            "",
            incident_id=9,
        )

        self.assertEqual(plan["actions"][0]["target"], "209.97.189.32")
        self.assertEqual(agent.client.chat.call_count, 2)
        retry_prompt = agent.client.chat.call_args.kwargs["messages"][-1]["content"]
        self.assertIn("unsupported fields", retry_prompt)
        self.assertIn("allowed_fields", retry_prompt)
        logging_agent.record.assert_called_once()
        self.assertEqual(logging_agent.record.call_args.kwargs["status"], "success")

    def test_isolate_host_rejects_file_path_as_target(self):
        agent = object.__new__(ActionPlannerAgent)
        agent.actions_by_name = {
            "isolate_host": {
                "action": "isolate_host",
                "required_fields": ["target"],
            }
        }
        agent.allowed_actions = set(agent.actions_by_name)

        with self.assertRaisesRegex(ValueError, "file-path-like target"):
            agent._parse_action_plan(
                '{"summary":"Contain","actions":[{"action":"isolate_host",'
                '"target":"C:\\\\Users\\\\analyst\\\\Downloads\\\\malware.exe",'
                '"justification":"Contain suspected activity."}]}'
            )

    @patch("MAPE.action_planner_agent.logging_agent")
    def test_prompt_contains_context_once_and_requests_deterministic_json(self, logging_agent):
        agent = object.__new__(ActionPlannerAgent)
        agent.model = "test-model"
        agent.client = MagicMock()
        agent.client.chat.return_value = {
            "message": {
                "content": (
                    '{"summary":"Review endpoint","actions":['
                    '{"action":"isolate_host","target":"host-1",'
                    '"justification":"Contain the endpoint."}]}'
                )
            }
        }
        agent.registry = MagicMock()
        agent.actions_catalog = {
            "actions": [
                {
                    "action": "isolate_host",
                    "description": "Isolate an endpoint",
                    "required_fields": ["target"],
                }
            ]
        }
        agent.actions_by_name = {
            "isolate_host": agent.actions_catalog["actions"][0]
        }
        agent.allowed_actions = set(agent.actions_by_name)

        plan = agent.propose_action_plan(
            {"source": "edr", "raw_payload": {"host": "host-1"}},
            "unique-context-marker",
            incident_id=7,
        )

        self.assertEqual(plan["actions"][0]["target"], "host-1")
        call = agent.client.chat.call_args.kwargs
        self.assertEqual(call["options"], {"temperature": 0, "num_predict": config.ACTION_PLAN_MAX_TOKENS})
        self.assertIs(call["think"], False)
        self.assertEqual(call["format"]["required"], ["summary", "actions"])
        prompt = "\n".join(message["content"] for message in call["messages"])
        self.assertEqual(prompt.count("unique-context-marker"), 1)
        logging_agent.record.assert_called_once()

    @patch("MAPE.action_planner_agent.logging_agent")
    def test_output_cut_at_token_limit_is_reported_as_truncated_fallback(self, logging_agent):
        agent = object.__new__(ActionPlannerAgent)
        agent.model = "test-model"
        agent.client = MagicMock()
        agent.client.chat.return_value = {"message": {"content": ""}, "done_reason": "length"}
        agent.registry = MagicMock()
        agent.actions_catalog = {"actions": [{"action": "notify_analyst", "required_fields": []}]}
        agent.actions_by_name = {"notify_analyst": agent.actions_catalog["actions"][0]}
        agent.allowed_actions = set(agent.actions_by_name)

        with self.assertLogs("MAPE.action_planner_agent", level="ERROR"):
            plan = agent.propose_action_plan({"source": "edr"}, "", incident_id=8)

        self.assertEqual(plan["actions"][0]["action"], "notify_analyst")
        details = logging_agent.record.call_args.kwargs["details"]
        self.assertEqual(details["fallback_reason"], "llm_output_truncated")


if __name__ == "__main__":
    unittest.main()
