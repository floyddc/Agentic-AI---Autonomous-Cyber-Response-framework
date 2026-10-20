import unittest
from unittest.mock import MagicMock, patch

from MAPE.retrieve_agent import RetrieveAgent


class RetrieveAgentTests(unittest.TestCase):
    def test_incident_query_prioritizes_alert_signals_and_indicators(self):
        agent = RetrieveAgent(registry=MagicMock())

        query = agent._incident_to_query({
            "source": "manual",
            "summary": "Suspicious executable",
            "customer_id": 1,
            "raw_payload": {
                "alert_title": "Threat detected",
                "alert_source": "SentinelOne",
                "alert_context": {
                    "agent": "srvprobe",
                    "tactic": "Initial Access",
                    "technique": "T1566",
                    "description": "Suspicious attachment detected",
                },
                "alert_iocs": [{
                    "ioc_value": "invoice.docm",
                    "ioc_type_id": 37,
                    "ioc_description": "Malicious attachment",
                    "ioc_tags": "phishing,macro",
                }],
                "generic_full_log": (
                    "Threat detected. File: invoice.docm. "
                    "SHA1: 013dcf46786cbf27de49b22a4abd0435904b0a94. "
                    "IP: 209.97.189.32. Unrelated verbose log text"
                ),
                "irrelevant_blob": "should not enter the search query",
            },
        })

        self.assertIn("alert_title: Threat detected", query)
        self.assertIn("alert_source: SentinelOne", query)
        self.assertIn("tactic: Initial Access", query)
        self.assertIn("ioc: invoice.docm", query)
        self.assertIn("file: invoice.docm", query)
        self.assertIn("hash: 013dcf46786cbf27de49b22a4abd0435904b0a94", query)
        self.assertIn("ip: 209.97.189.32", query)
        self.assertNotIn("Unrelated verbose log text", query)
        self.assertNotIn("should not enter the search query", query)

    def test_semantic_query_excludes_identifiers_but_keeps_meaning(self):
        agent = RetrieveAgent(registry=MagicMock())

        query = agent._incident_to_query({
            "source": "manual",
            "raw_payload": {
                "alert_title": "Suspicious email with malicious attachment",
                "alert_context": {
                    "agent": "srvprobe",
                    "generic_full_log": (
                        "Threat detected. File: invoice.docm. "
                        "SHA1: 013dcf46786cbf27de49b22a4abd0435904b0a94. IP: 209.97.189.32. "
                        "Site: AZIENDA X"
                    ),
                },
                "alert_iocs": [{
                    "ioc_value": "mail-update@secure-invoice-support.com",
                    "ioc_description": "Malicious macro-enabled document",
                    "ioc_tags": "phishing,macro",
                }],
            },
        }, semantic=True)

        self.assertIn("alert_title: Suspicious email with malicious attachment", query)
        self.assertIn("file: macro-enabled Office document", query)
        self.assertIn("ioc_description: Malicious macro-enabled document", query)
        self.assertIn("ioc_tags: phishing,macro", query)
        for noise in ("srvprobe", "013dcf46", "209.97.189.32", "secure-invoice-support.com", "manual"):
            self.assertNotIn(noise, query)

    def test_semantic_query_describes_downloaded_executable_without_random_file_name(self):
        agent = RetrieveAgent(registry=MagicMock())

        query = agent._incident_to_query({
            "customer_id": 1,
            "raw_payload": {
                "alert_title": "Cst00 Detection",
                "alert_description": "High CYLOS detection",
                "alert_source": "SentinelOne",
                "alert_context": {
                    "description": "Sentinel One event: Threat with confidence level suspicious detected: 4k-video-downloader_R-jPBn1.exe",
                    "generic_full_log": (
                        "Threat with confidence level malicious detected. File: 4k-video-downloader_R-jPBn1.exe. "
                        "Path: C:\\Users\\luxval\\Downloads\\4k-video-downloader_R-jPBn1.exe. "
                        "SHA1: 013dcf46786cbf27de49b22a4abd0435904b0a94. IP: 209.97.189.32."
                    ),
                },
            },
        }, semantic=True)

        self.assertIn("log_message: Threat with confidence level malicious detected", query)
        self.assertIn("file: executable", query)
        self.assertIn("origin: downloaded by the user", query)
        for noise in (
            "Cst00 Detection", "CYLOS", "SentinelOne", "4k-video-downloader",
            "jPBn1", "luxval", "013dcf46", "209.97.189.32",
        ):
            self.assertNotIn(noise, query)

    def test_incident_query_caps_length(self):
        agent = RetrieveAgent(registry=MagicMock())

        query = agent._incident_to_query({
            "raw_payload": {"alert_description": "A" * 5000},
        })

        self.assertLessEqual(len(query), 1600)

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
