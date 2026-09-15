import json
import logging
import sys
import time
from typing import Any, Dict
from RAG import config
from RAG.context_builder import build_context
from knowledge.registry import IncidentRegistry
from .logging_agent import logging_agent

logger = logging.getLogger(__name__)

class RetrieveAgent:

    def __init__(self, top_k: int = config.TOP_K, registry: IncidentRegistry = None):
        self.top_k = top_k
        self.logger = logger
        self.registry = registry or IncidentRegistry()

    def _incident_to_query(self, incident: Any) -> str:

        if isinstance(incident, str):
            return incident

        if not isinstance(incident, dict):
            return str(incident)

        raw_payload = incident.get("raw_payload")

        if isinstance(raw_payload, dict):

            parts = []

            source = incident.get("source") or raw_payload.get("_source")
            if source: parts.append(f"source: {source}")

            fields = [
                "alert",
                "message",
                "command_line",
                "indicators",
                "host",
                "user",
                "signature",
                "event_type",
                "event_name",
                "process",
                "service",
            ]

            for field in fields: 
                value = raw_payload.get(field)

                if value is not None and value != "":
                    parts.append(f"{field}: {value}")

            if parts:
                return "\n".join(parts)

            return json.dumps(raw_payload, ensure_ascii=False, default=str)

        # Fallback
        fields = [
            "summary",
            "title",
            "description",
            "alert",
            "message",
            "command_line",
            "indicators",
            "host",
            "user",
            "signature",
        ]

        parts = []

        for field in fields:
            value = incident.get(field)

            if value is not None and value != "":
                parts.append(f"{field}: {value}")

        if parts:
            return "\n".join(parts)

        return json.dumps(incident, ensure_ascii=False, default=str)


    def retrieve(self, incident_or_query: Any, incident_id: int = None) -> Dict[str, Any]:

        q = self._incident_to_query(incident_or_query)
        start = time.perf_counter()
        try:
            context = build_context(q, top_k=self.top_k)
            try:
                self.registry.log_action(
                    incident_id,
                    agent="retrieve_agent",
                    action="retrieved_context",
                    details={"query": q, "context_length": len(context) if context else 0},
                )
            except Exception:
                self.logger.exception("Failed to log retrieve_agent action to the incident registry")
            logging_agent.record(
                "retrieve_agent", "retrieve", status="success",
                duration_ms=(time.perf_counter() - start) * 1000, incident_id=incident_id,
            )
            return {"query": q, "context": context}
        except Exception as exc:
            self.logger.exception("Retrieve failed")
            logging_agent.record(
                "retrieve_agent", "retrieve", status="error",
                duration_ms=(time.perf_counter() - start) * 1000, incident_id=incident_id,
                details={"error": str(exc)},
            )
            return {"query": q, "error": str(exc)}


if __name__ == "__main__":
    import logging as _logging

    _logging.basicConfig(level=_logging.INFO)
    for lib in ("httpx", "sentence_transformers", "transformers", "urllib3", "chromadb"):
        _logging.getLogger(lib).setLevel(_logging.WARNING)

    agent = RetrieveAgent()
    if len(sys.argv) > 1:
        q = " ".join(sys.argv[1:])
    else:
        q = input("Incident or query: ")
    out = agent.retrieve(q)
    print(json.dumps(out, indent=2, ensure_ascii=False))
