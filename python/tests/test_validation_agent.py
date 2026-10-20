import unittest
from contextlib import nullcontext
from unittest.mock import MagicMock, patch

from MAPE.validation_agent import ValidationAgent


class ValidationAgentTests(unittest.TestCase):
    def setUp(self):
        self.logging_patcher = patch("MAPE.validation_agent.logging_agent")
        self.logging_agent = self.logging_patcher.start()
        self.addCleanup(self.logging_patcher.stop)
        self.logging_agent.track.return_value = nullcontext()

        self.catalog = {
            "block_ip": {
                "action": "block_ip",
                "required_fields": ["target"],
                "target_type": "ip_address",
                "field_types": {},
                "max_auto_severity": "high",
            },
            "collect_endpoint_artifacts": {
                "action": "collect_endpoint_artifacts",
                "required_fields": ["target"],
                "target_type": "endpoint_id",
                "field_types": {},
                "max_auto_severity": "high",
            },
            "quarantine_file": {
                "action": "quarantine_file",
                "required_fields": ["target", "endpoint"],
                "target_type": "file_reference",
                "field_types": {"endpoint": "endpoint_id"},
                "max_auto_severity": "critical",
            },
            "notify_analyst": {
                "action": "notify_analyst",
                "required_fields": [],
                "field_types": {},
                "max_auto_severity": "critical",
            },
            "no_action": {
                "action": "no_action",
                "required_fields": [],
                "field_types": {},
                "max_auto_severity": "critical",
            },
        }
        self.policies = {
            "severity_order": ["low", "medium", "high", "critical"],
            "require_human_approval_above_severity": "high",
            "blocked_actions": [],
            "max_actions_per_plan": 2,
        }
        self.agent = ValidationAgent(registry=MagicMock())
        self.agent.registry.get_incident.return_value = {
            "raw_payload": {
                "ip": "209.97.189.32",
                "observed_ips": ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
                "endpoint": "srvprobe",
                "hash": "013dcf46786cbf27de49b22a4abd0435904b0a94",
            }
        }
        self.agent._load_action_catalog = MagicMock(return_value=self.catalog)
        self.agent._load_policies = MagicMock(return_value=self.policies)

    def test_repository_catalog_has_valid_target_contracts(self):
        catalog = ValidationAgent(registry=MagicMock())._load_action_catalog()

        self.assertEqual(catalog["isolate_host"]["target_type"], "endpoint_id")
        self.assertEqual(
            catalog["quarantine_file"]["field_types"]["endpoint"],
            "endpoint_id",
        )
        self.assertEqual(catalog["notify_analyst"]["required_fields"], [])

    def validate(self, actions, severity="high", summary="Review alert"):
        return self.agent.validate(
            42,
            {"summary": summary, "actions": actions},
            severity,
        )

    def test_valid_plan_requires_human_approval_at_high_severity(self):
        action = {
            "action": "block_ip",
            "target": "209.97.189.32",
            "justification": "The alert associates this IP with the detected file.",
        }

        valid, result = self.validate([action])

        self.assertTrue(valid)
        self.assertTrue(result["requires_human_approval"])
        self.assertTrue(result["approved_actions"][0]["requires_human_approval"])
        self.assertNotIn("requires_human_approval", action)

    def test_invalid_action_rejects_the_entire_plan(self):
        valid, result = self.validate(
            [
                {
                    "action": "block_ip",
                    "target": "209.97.189.32",
                    "justification": "Alert evidence.",
                },
                {
                    "action": "block_ip",
                    "target": "not-an-ip",
                    "justification": "Malformed indicator.",
                },
            ]
        )

        self.assertFalse(valid)
        self.assertEqual(result["approved_actions"], [])
        self.assertTrue(any("invalid target" in reason for reason in result["reasons"]))

    def test_plan_over_limit_is_rejected_without_truncation(self):
        actions = [
            {
                "action": "block_ip",
                "target": ip,
                "justification": "Alert evidence.",
            }
            for ip in ("192.0.2.1", "192.0.2.2", "192.0.2.3")
        ]

        valid, result = self.validate(actions)

        self.assertFalse(valid)
        self.assertEqual(result["approved_actions"], [])
        self.assertIn(
            "plan exceeds max_actions_per_plan (2)",
            result["reasons"],
        )

    def test_endpoint_path_is_not_accepted_as_endpoint_id(self):
        valid, result = self.validate(
            [
                {
                    "action": "collect_endpoint_artifacts",
                    "target": r"C:\Users\analyst\Downloads",
                    "justification": "Collect endpoint evidence.",
                }
            ]
        )

        self.assertFalse(valid)
        self.assertTrue(any("invalid target" in reason for reason in result["reasons"]))

    def test_action_target_must_be_present_in_raw_alert(self):
        valid, result = self.validate(
            [
                {
                    "action": "block_ip",
                    "target": "203.0.113.10",
                    "justification": "Block the suspected command server.",
                }
            ]
        )

        self.assertFalse(valid)
        self.assertEqual(result["approved_actions"], [])
        self.assertTrue(any("not present in the raw alert" in reason for reason in result["reasons"]))

    def test_hash_file_quarantine_requires_an_endpoint(self):
        valid, result = self.validate(
            [
                {
                    "action": "quarantine_file",
                    "target": "013dcf46786cbf27de49b22a4abd0435904b0a94",
                    "justification": "The alert identifies this malicious file hash.",
                }
            ]
        )

        self.assertFalse(valid)
        self.assertTrue(any("endpoint" in reason for reason in result["reasons"]))

    def test_empty_target_is_removed_from_notification_action(self):
        valid, result = self.validate(
            [
                {
                    "action": "notify_analyst",
                    "target": "",
                    "justification": "Request analyst review.",
                }
            ]
        )

        self.assertTrue(valid)
        self.assertNotIn("target", result["approved_actions"][0])

    def test_no_action_cannot_be_combined_with_remediation(self):
        valid, result = self.validate(
            [
                {
                    "action": "no_action",
                    "justification": "The alert is benign.",
                },
                {
                    "action": "block_ip",
                    "target": "209.97.189.32",
                    "justification": "Block suspicious traffic.",
                },
            ]
        )

        self.assertFalse(valid)
        self.assertEqual(result["approved_actions"], [])
        self.assertIn("'no_action' cannot be combined with other actions", result["reasons"])

    def test_rejects_duplicate_action_and_target(self):
        action = {
            "action": "block_ip",
            "target": "209.97.189.32",
            "justification": "Alert evidence.",
        }

        valid, result = self.validate([action, dict(action)])

        self.assertFalse(valid)
        self.assertEqual(result["approved_actions"], [])
        self.assertIn("duplicate action and target: block_ip", result["reasons"])

    def test_requires_non_empty_plan_summary(self):
        valid, result = self.validate(
            [
                {
                    "action": "notify_analyst",
                    "justification": "Request analyst review.",
                }
            ],
            summary=" ",
        )

        self.assertFalse(valid)
        self.assertIn("action plan must contain a non-empty summary", result["reasons"])


if __name__ == "__main__":
    unittest.main()
