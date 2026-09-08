import json
import logging
from typing import Any, Dict, Optional
from ollama import Client
from . import config
from .incident_registry import IncidentRegistry
from .logging_agent import logging_agent

logger = logging.getLogger(__name__)

VALID_SEVERITIES = ("low", "medium", "high", "critical")

SYSTEM_PROMPT = (
    "You are the AI Triage agent in a cyber-response system. Given a raw security alert "
    "(from EDR/XDR/SIEM), normalize it and respond with ONLY a compact JSON object with "
    "these keys: \"summary\" (short one-line title), \"description\" (normalized details), "
    "\"category\" (best-guess MITRE ATT&CK tactic or attack type), "
    "\"severity\" (one of: low, medium, high, critical). No prose, no markdown, JSON only."
)


class TriageAgent:

    def __init__(self, model: str = config.CHAT_MODEL, host: str = config.OLLAMA_HOST, registry: Optional[IncidentRegistry] = None):
        self.model = model
        self.client = Client(host=host)
        self.registry = registry or IncidentRegistry()

    def _heuristic_severity(self, raw_payload: Dict[str, Any]) -> str:
        text = json.dumps(raw_payload).lower()
        if any(k in text for k in ("ransomware", "critical", "root_shell", "lateral_movement")):
            return "critical"
        if any(k in text for k in ("privilege_escalation", "exfiltration", "c2", "malware")):
            return "high"
        if any(k in text for k in ("suspicious", "anomaly", "failed_login")):
            return "medium"
        return "low"

    def _llm_triage(self, raw_payload: Dict[str, Any], source: str) -> Optional[Dict[str, Any]]:
        try:
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"source: {source}\nalert: {json.dumps(raw_payload, ensure_ascii=False)}"},
            ]
            response = self.client.chat(model=self.model, messages=messages, format="json")
            content = response["message"]["content"]
            data = json.loads(content)
            if data.get("severity") not in VALID_SEVERITIES:
                data["severity"] = self._heuristic_severity(raw_payload)
            return data
        except Exception:
            logger.exception("LLM triage failed, falling back to heuristic classification")
            return None

    def triage(self, incident_id: int, raw_payload: Dict[str, Any], source: str) -> Dict[str, Any]:
        with logging_agent.track("triage_agent", "triage", incident_id=incident_id):
            result = self._llm_triage(raw_payload, source)
            if result is None:
                result = {
                    "summary": f"{source} alert",
                    "description": json.dumps(raw_payload, ensure_ascii=False),
                    "category": "unknown",
                    "severity": self._heuristic_severity(raw_payload),
                }

            self.registry.update_fields(
                incident_id,
                summary=result.get("summary"),
                description=result.get("description"),
                severity=result.get("severity"),
            )
            self.registry.log_action(
                incident_id,
                agent="triage_agent",
                action="triaged",
                details=result,
            )
            return result
