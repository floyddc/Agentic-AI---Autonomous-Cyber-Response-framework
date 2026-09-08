import json
import logging
import sys
from typing import Any, Dict, Optional
from .incident_registry import IncidentRegistry
from .logging_agent import logging_agent
from .response_agent import ResponseAgent
from .response_layer import ResponseLayer
from .retrieve_agent import RetrieveAgent
from .triage_agent import TriageAgent
from .validation_agent import ValidationAgent

logger = logging.getLogger(__name__)


class OrchestratorAgent:
    """MULTI-AGENT ORCHESTRATION: drives a security alert through the full incident lifecycle (MAPE-K loop), one step at a time:
        new -> triage -> triaged -> retrieve -> validation -> validated -> response -> responded
    """

    def __init__(
        self,
        registry: Optional[IncidentRegistry] = None,
        triage_agent: Optional[TriageAgent] = None,
        retrieve_agent: Optional[RetrieveAgent] = None,
        response_agent: Optional[ResponseAgent] = None,
        validation_agent: Optional[ValidationAgent] = None,
        response_layer: Optional[ResponseLayer] = None,
    ):
        self.registry = registry or IncidentRegistry()
        self.triage_agent = triage_agent or TriageAgent(registry=self.registry)
        self.retrieve_agent = retrieve_agent or RetrieveAgent(registry=self.registry)
        self.response_agent = response_agent or ResponseAgent(registry=self.registry)
        self.validation_agent = validation_agent or ValidationAgent(registry=self.registry)
        self.response_layer = response_layer or ResponseLayer(registry=self.registry)

    def _fail(self, incident_id: int, phase: str, error: Exception) -> Dict[str, Any]:
        logger.exception("Orchestration failed for incident %s during phase '%s'", incident_id, phase)
        self.registry.update_status(incident_id, "failed")
        self.registry.log_action(
            incident_id,
            agent="orchestrator_agent",
            action="failed",
            details={"phase": phase, "error": str(error)},
        )
        return {"incident_id": incident_id, "status": "failed", "phase": phase, "error": str(error)}

    def handle_alert(self, source: str, raw_payload: Dict[str, Any], external_id: Optional[str] = None) -> Dict[str, Any]:
        
        with logging_agent.track("orchestrator_agent", "handle_alert"):

            # new
            incident_id = self.registry.create_incident(source=source, external_id=external_id, raw_payload=raw_payload)
            self.registry.log_action(incident_id, agent="orchestrator_agent", action="created", details={"source": source})

            # triage -> triaged
            self.registry.update_status(incident_id, "triage")
            try:
                triage_result = self.triage_agent.triage(incident_id, raw_payload, source)
            except Exception as exc:
                return self._fail(incident_id, "triage", exc)
            self.registry.update_status(incident_id, "triaged")

            severity = triage_result.get("severity")
            incident = self.registry.get_incident(incident_id)

            # retrieve
            self.registry.update_status(incident_id, "retrieve")
            try:
                retrieval = self.retrieve_agent.retrieve(incident, incident_id=incident_id)
            except Exception as exc:
                return self._fail(incident_id, "retrieve", exc)
            if retrieval.get("error"):
                return self._fail(incident_id, "retrieve", RuntimeError(retrieval["error"]))
            context = retrieval.get("context", "")

            # validation -> validated (response agent proposes the plan, validation layer checks it)
            self.registry.update_status(incident_id, "validation")
            try:
                action_plan = self.response_agent.propose_action_plan(incident, context, incident_id=incident_id)
                is_valid, validation_result = self.validation_agent.validate(incident_id, action_plan, severity)
            except Exception as exc:
                return self._fail(incident_id, "validation", exc)
            if not is_valid:
                self.registry.update_status(incident_id, "failed")
                self.registry.log_action(
                    incident_id, agent="orchestrator_agent", action="validation_rejected", details=validation_result
                )
                return {
                    "incident_id": incident_id,
                    "status": "failed",
                    "phase": "validation",
                    "action_plan": action_plan,
                    "validation": validation_result,
                }
            self.registry.update_status(incident_id, "validated")

            # response -> responded (response layer executes the validated actions)
            self.registry.update_status(incident_id, "response")
            try:
                execution = self.response_layer.execute(incident_id, validation_result["approved_actions"])
            except Exception as exc:
                return self._fail(incident_id, "response", exc)
            self.registry.update_status(incident_id, "responded")

            self.registry.log_action(incident_id, agent="orchestrator_agent", action="completed", details={"execution": execution})

            return {
                "incident_id": incident_id,
                "status": "responded",
                "triage": triage_result,
                "context": context,
                "action_plan": action_plan,
                "validation": validation_result,
                "execution": execution,
            }


def handle_alert(source: str, raw_payload: Dict[str, Any], external_id: Optional[str] = None) -> Dict[str, Any]:
    return OrchestratorAgent().handle_alert(source, raw_payload, external_id=external_id)


if __name__ == "__main__":
    import logging as _logging

    _logging.basicConfig(level=_logging.INFO)
    for lib in ("httpx", "sentence_transformers", "transformers", "urllib3", "chromadb"):
        _logging.getLogger(lib).setLevel(_logging.WARNING)

    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8-sig") as f:
            payload = json.load(f)
    else:
        payload = json.loads(input("Raw alert JSON: "))

    source = payload.pop("_source", "manual")
    report = handle_alert(source=source, raw_payload=payload)
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
