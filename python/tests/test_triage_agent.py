import json
import unittest
from unittest.mock import MagicMock

from MAPE.triage_agent import TRIAGE_RESPONSE_SCHEMA, TriageAgent


class TriageAgentTests(unittest.TestCase):
    def setUp(self):
        self.agent = object.__new__(TriageAgent)
        self.agent.model = "test-model"
        self.agent.client = MagicMock()

    def test_requests_schema_constrained_triage_and_returns_valid_result(self):
        expected = {
            "summary": "Phishing email with malicious attachment",
            "description": "A suspicious email delivered a macro-enabled document.",
            "category": "Initial Access",
            "severity": "high",
        }
        self.agent.client.chat.return_value = {
            "message": {"content": json.dumps(expected)}
        }

        result = self.agent._llm_triage(
            {"alert_title": "Suspicious email with malicious attachment"},
            "mail-security",
            "Unrelated context mentioning Reconnaissance.",
        )

        self.assertEqual(result, expected)
        call = self.agent.client.chat.call_args.kwargs
        self.assertEqual(call["format"], TRIAGE_RESPONSE_SCHEMA)
        self.assertEqual(call["options"], {"temperature": 0})
        self.assertEqual(call["think"], False)

    def test_rejects_incomplete_triage_output(self):
        self.agent.client.chat.return_value = {
            "message": {"content": '{"summary":"Incomplete","severity":"high"}'}
        }

        with self.assertLogs("MAPE.triage_agent", level="ERROR"):
            result = self.agent._llm_triage({"alert_title": "Malware"}, "edr")

        self.assertIsNone(result)

    def test_malicious_phishing_delivery_is_categorized_as_initial_access(self):
        self.agent.client.chat.return_value = {
            "message": {
                "content": json.dumps(
                    {
                        "summary": "Suspicious email",
                        "description": "Email contains a macro-enabled malicious attachment.",
                        "category": "Reconnaissance",
                        "severity": "high",
                    }
                )
            }
        }

        result = self.agent._llm_triage(
            {
                "alert_title": "Suspicious email with malicious attachment",
                "alert_description": "Phishing email with macro-based malware",
            },
            "mail-security",
        )

        self.assertEqual(result["category"], "Initial Access")


if __name__ == "__main__":
    unittest.main()
