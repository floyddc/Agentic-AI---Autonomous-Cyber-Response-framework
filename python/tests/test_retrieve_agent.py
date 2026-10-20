import unittest
from unittest.mock import MagicMock, patch

from MAPE.retrieve_agent import RetrieveAgent


class RetrieveAgentTests(unittest.TestCase):
    @patch("MAPE.retrieve_agent.logging_agent")
    @patch("MAPE.retrieve_agent.build_context", return_value="relevant context")
    def test_successful_retrieval_records_success(self, build_context, logging_agent):
        registry = MagicMock()
        agent = RetrieveAgent(registry=registry)

        result = agent.retrieve(
            {"customer_id": 1, "raw_payload": {"alert_title": "Suspicious file"}},
            incident_id=17,
        )

        self.assertEqual(result["context"], "relevant context")
        self.assertNotIn("error", result)
        self.assertEqual(logging_agent.record.call_args.kwargs["status"], "success")
        registry.log_action.assert_called_once()
        build_context.assert_called_once()

    @patch("MAPE.retrieve_agent.logging_agent")
    @patch("MAPE.retrieve_agent.build_context", side_effect=RuntimeError("search failed"))
    def test_failed_retrieval_records_error(self, build_context, logging_agent):
        agent = RetrieveAgent(registry=MagicMock())

        with self.assertLogs("MAPE.retrieve_agent", level="ERROR"):
            result = agent.retrieve(
                {"customer_id": 1, "raw_payload": {"alert_title": "Suspicious file"}},
                incident_id=18,
            )

        self.assertEqual(result["error"], "search failed")
        self.assertEqual(logging_agent.record.call_args.kwargs["status"], "error")
        self.assertEqual(
            logging_agent.record.call_args.kwargs["details"]["error"],
            "search failed",
        )
        build_context.assert_called_once()


if __name__ == "__main__":
    unittest.main()
