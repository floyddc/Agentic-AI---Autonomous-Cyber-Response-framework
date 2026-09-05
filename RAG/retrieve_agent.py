import json
import logging
import sys
from typing import Any, Dict
from . import config
from .context_builder import build_context
from .incident_registry import IncidentRegistry

logger = logging.getLogger(__name__)

class RetrieveAgent:

    def __init__(self, top_k: int = config.TOP_K, registry: IncidentRegistry = None):
        self.top_k = top_k
        self.logger = logger
        self.registry = registry or IncidentRegistry()

    def _incident_to_query(self, incident: Any) -> str:

        if isinstance(incident, str):
            return incident
        
        if isinstance(incident, dict):

            fields = ["summary", "title", "description", "alert", "message", "signature"]
            parts = []
            for f in fields:
                v = incident.get(f)
                if v:
                    parts.append(f"{f}: {v}")

            if incident.get("indicators"):
                parts.append(f"indicators: {incident['indicators']}")

            if parts:
                return " \n".join(parts)

            try:
                return json.dumps(incident)
            except Exception:
                return str(incident)

        return str(incident)

    def retrieve(self, incident_or_query: Any, incident_id: int = None) -> Dict[str, Any]:

        q = self._incident_to_query(incident_or_query)
        try:
            context = build_context(q, top_k=self.top_k)
            try:
                self.registry.log_action(
                    incident_id,
                    agent="retrieve_agent",
                    action="retrieved_context",
                    details={"query": q, "context": context},
                )
            except Exception:
                self.logger.exception("Failed to log retrieve_agent action to the incident registry")
            return {"query": q, "context": context}
        except Exception as exc:
            self.logger.exception("Retrieve failed")
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
