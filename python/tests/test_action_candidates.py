import unittest

from MAPE.action_candidates import build_action_candidates, normalize_alert


class ActionCandidateTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            "actions": [
                {
                    "action": "block_ip",
                    "description": "Block an IP",
                    "required_fields": ["target"],
                    "target_type": "ip_address",
                },
                {
                    "action": "block_url",
                    "description": "Block a URL",
                    "required_fields": ["target"],
                    "target_type": "url",
                },
                {
                    "action": "block_hash",
                    "description": "Block a file hash",
                    "required_fields": ["target"],
                    "target_type": "file_hash",
                },
                {
                    "action": "quarantine_file",
                    "description": "Quarantine a file",
                    "required_fields": ["target", "endpoint"],
                    "target_type": "file_reference",
                    "field_types": {"endpoint": "endpoint_id"},
                },
                {
                    "action": "notify_analyst",
                    "description": "Escalate to an analyst",
                    "required_fields": [],
                },
            ]
        }

    def test_sentinelone_log_builds_only_complete_supported_candidates(self):
        raw_payload = {
            "alert_source": "SentinelOne",
            "alert_context": {
                "agent": "srvprobe",
                "generic_full_log": (
                    "Threat with confidence level malicious detected. "
                    "File: sample.exe. Path: C:\\Users\\alice\\Downloads\\sample.exe. "
                    "SHA1: 013dcf46786cbf27de49b22a4abd0435904b0a94. "
                    "IP: 209.97.189.32."
                ),
            },
        }

        normalized = normalize_alert(raw_payload)
        candidates = build_action_candidates(raw_payload, self.catalog)
        candidate_actions = [candidate.action for candidate in candidates]

        self.assertEqual(normalized.source_family, "endpoint_edr")
        agent_evidence = [
            item for item in normalized.evidence if item.source.endswith(".agent")
        ]
        self.assertEqual(len(agent_evidence), 1)
        self.assertFalse(agent_evidence[0].verified)
        self.assertEqual(
            {action["action"] for action in candidate_actions},
            {"block_ip", "block_hash", "notify_analyst"},
        )
        self.assertTrue(
            all(
                action["action"] != "quarantine_file"
                or {"target", "endpoint"} <= action.keys()
                for action in candidate_actions
            )
        )
        self.assertEqual(
            next(action["target"] for action in candidate_actions if action["action"] == "block_ip"),
            "209.97.189.32",
        )
        self.assertEqual(
            next(action["target"] for action in candidate_actions if action["action"] == "block_hash"),
            "013dcf46786cbf27de49b22a4abd0435904b0a94",
        )

    def test_defender_office_iocs_create_url_candidate_not_endpoint_quarantine(self):
        raw_payload = {
            "alert_source": "Microsoft Defender for Office365",
            "alert_iocs": [
                {
                    "ioc_value": "Invoice_2026-02-18.docm",
                    "ioc_description": "Malicious macro-enabled document",
                    "ioc_tags": "phishing,macro,document",
                },
                {
                    "ioc_value": "mail-update@secure-invoice-support.com",
                    "ioc_description": "Suspicious sender email address",
                    "ioc_tags": "phishing,email",
                },
                {
                    "ioc_value": "https://secure-invoice-support.com/update",
                    "ioc_description": "Phishing landing page",
                    "ioc_tags": "phishing,url,c2",
                },
            ],
        }

        normalized = normalize_alert(raw_payload)
        candidates = build_action_candidates(raw_payload, self.catalog)
        candidate_actions = [candidate.action for candidate in candidates]

        self.assertEqual(normalized.source_family, "email_defender")
        self.assertEqual(
            {action["action"] for action in candidate_actions},
            {"block_url", "notify_analyst"},
        )
        self.assertEqual(
            next(action["target"] for action in candidate_actions if action["action"] == "block_url"),
            "https://secure-invoice-support.com/update",
        )

    def test_unclassified_url_is_not_promoted_to_a_block_action(self):
        raw_payload = {
            "alert_source": "unknown",
            "alert_iocs": [
                {
                    "ioc_value": "https://example.com/download",
                    "ioc_tags": "url",
                }
            ],
        }

        candidates = build_action_candidates(raw_payload, self.catalog)

        self.assertEqual([candidate.action["action"] for candidate in candidates], ["notify_analyst"])

    def test_verified_endpoint_allows_complete_file_quarantine_candidate(self):
        raw_payload = {
            "alert_source": "Microsoft Defender for Endpoint",
            "alert_description": "Microsoft Defender detected a malicious file.",
            "endpoint_id": "device-42",
            "file_path": "C:\\Users\\alice\\Downloads\\sample.exe",
        }

        candidates = build_action_candidates(raw_payload, self.catalog)
        quarantine = next(
            candidate.action
            for candidate in candidates
            if candidate.action["action"] == "quarantine_file"
        )

        self.assertEqual(quarantine["target"], "C:\\Users\\alice\\Downloads\\sample.exe")
        self.assertEqual(quarantine["endpoint"], "device-42")

    def test_negated_malware_text_does_not_generate_hash_block_candidate(self):
        raw_payload = {
            "alert_source": "SentinelOne",
            "alert_description": "The file is not malicious.",
            "alert_iocs": [
                {
                    "ioc_value": "013dcf46786cbf27de49b22a4abd0435904b0a94",
                    "ioc_tags": "file,hash",
                }
            ],
        }

        candidates = build_action_candidates(raw_payload, self.catalog)

        self.assertEqual(
            [candidate.action["action"] for candidate in candidates],
            ["notify_analyst"],
        )


if __name__ == "__main__":
    unittest.main()
