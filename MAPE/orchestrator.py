import json
import logging
import sys
from typing import Any, Dict, Optional, Tuple
from knowledge.registry import IncidentRegistry
from .action_planner_agent import ActionPlannerAgent
from .logging_agent import logging_agent
from .response_layer import ResponseLayer
from .retrieve_agent import RetrieveAgent
from .triage_agent import TriageAgent
from .validation_agent import ValidationAgent

logger = logging.getLogger(__name__)

NEW = "new"
TRIAGE = "triage"
TRIAGED = "triaged"
RETRIEVE = "retrieve"
VALIDATION = "validation"
VALIDATED = "validated"
AWAITING_HUMAN_APPROVAL = "awaiting_human_approval"
RESPONSE = "response"
RESPONDED = "responded"
FAILED = "failed"
CLOSED = "closed"
ACTION_TRIAGE = "TRIAGE"
ACTION_RETRIEVE = "RETRIEVE"
ACTION_PLAN = "PLAN"
ACTION_VALIDATE = "VALIDATE"
ACTION_EXECUTE = "EXECUTE"
ACTION_WAIT_FOR_HUMAN = "WAIT_FOR_HUMAN_APPROVAL"
ACTION_END = "END"


# RULE-BASED ROUTER ----------------------------------------------------------------------------------------------------------------------------------------------------------
class Router:                   

    def decide(self, state: Dict[str, Any]) -> str:

        phase = state.get("phase")
        if phase == NEW: return ACTION_TRIAGE
        if phase == TRIAGED: return ACTION_RETRIEVE
        if phase == "retrieved": return ACTION_PLAN
        if phase == "response_proposed": return ACTION_VALIDATE
        if phase == VALIDATED: return ACTION_EXECUTE
        if phase == AWAITING_HUMAN_APPROVAL: return ACTION_WAIT_FOR_HUMAN
        if phase == RESPONDED: return ACTION_END
        if phase == FAILED: return ACTION_END
        raise RuntimeError(f"Unknown orchestration phase: {phase}")

# ORCHESTRATOR  ----------------------------------------------------------------------------------------------------------------------------------------------------------
class Orchestrator:

    MAX_STEPS = 10

    def __init__(
        self,
        registry: Optional[IncidentRegistry] = None,
        triage_agent: Optional[TriageAgent] = None,
        retrieve_agent: Optional[RetrieveAgent] = None,
        action_planner_agent: Optional[ActionPlannerAgent] = None,
        validation_agent: Optional[ValidationAgent] = None,
        response_layer: Optional[ResponseLayer] = None,
        router: Optional[Router] = None,
    ):
        self.registry = registry or IncidentRegistry()
        self.triage_agent = triage_agent or TriageAgent(registry=self.registry)
        self.retrieve_agent = retrieve_agent or RetrieveAgent(registry=self.registry)
        self.action_planner_agent = (action_planner_agent or ActionPlannerAgent(registry=self.registry))
        self.validation_agent = (validation_agent or ValidationAgent(registry=self.registry))
        self.response_layer = response_layer or ResponseLayer(registry=self.registry)
        self.router = router or Router()


    def _set_phase(self, incident_id: int, state: Dict[str, Any], phase: str, *, persist: bool = True, details: Optional[Dict[str, Any]] = None) -> None:

        previous_phase = state.get("phase")
        state["phase"] = phase

        if persist: 
            self.registry.update_status(incident_id, phase)

        self.registry.log_action(
            incident_id,
            agent="orchestrator",
            action="phase_transition",
            details={
                "from": previous_phase,
                "to": phase,
                "persisted": persist,
                **(details or {}),
            },
        )

        logger.info("Incident %s: phase %s -> %s", incident_id, previous_phase, phase)



    def _fail(self, incident_id: int, state: Dict[str, Any], phase: str, error: Exception) -> Dict[str, Any]:

        logger.exception("Incident %s failed during phase '%s'", incident_id, phase)
        state["phase"] = FAILED

        try:
            self.registry.update_status(incident_id, FAILED)
            self.registry.log_action(
                incident_id,
                agent="orchestrator",
                action="failed",
                details={
                    "phase": phase,
                    "error": str(error),
                    "error_type": type(error).__name__,
                },
            )

        except Exception:
            logger.exception("Unable to persist failure for incident %s", incident_id)

        return {
            "incident_id": incident_id,
            "status": FAILED,
            "phase": phase,
            "error": str(error),
        }


    # TRIAGE ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def _run_triage(self, incident_id: int, raw_payload: Dict[str, Any], source: str, state: Dict[str, Any]) -> Dict[str, Any]:
        
        self._set_phase(incident_id, state, TRIAGE)
        result = self.triage_agent.triage(incident_id, raw_payload, source)

        if not isinstance(result, dict):
            raise RuntimeError("TriageAgent returned an invalid result")

        self.registry.update_fields(
            incident_id,
            summary=result.get("summary"),
            description=result.get("description"),
            severity=result.get("severity"),
        )

        self._set_phase(incident_id, state, TRIAGED)

        return result


    # RETRIEVE ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def _run_retrieve(self, incident_id: int, state: Dict[str, Any]) -> Dict[str, Any]:

        self._set_phase(incident_id, state, RETRIEVE)
        incident = self.registry.get_incident(incident_id)

        if incident is None:
            raise RuntimeError(f"Incident {incident_id} not found")

        result = self.retrieve_agent.retrieve(incident, incident_id=incident_id)

        if not isinstance(result, dict):
            raise RuntimeError("RetrieveAgent returned an invalid result")

        if result.get("error"):
            raise RuntimeError(str(result["error"]))

        self._set_phase(incident_id, state, "retrieved", persist=False)

        return result


    # PLAN ACTION ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def _run_planning(self, incident_id: int, context: str, state: Dict[str, Any]) -> Dict[str, Any]:
        
        incident = self.registry.get_incident(incident_id)

        if incident is None:
            raise RuntimeError(f"Incident {incident_id} not found")

        action_plan = self.action_planner_agent.propose_action_plan(incident, context, incident_id=incident_id)

        if not isinstance(action_plan, dict):
            raise RuntimeError("ActionPlannerAgent returned an invalid action plan")

        self._set_phase(incident_id, state, "response_proposed", persist=False)

        return action_plan


    # VALIDATION ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def _run_validation(self, incident_id: int, action_plan: Dict[str, Any], severity: Optional[str], state: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:

        self._set_phase(incident_id, state, VALIDATION)

        is_valid, validation_result = self.validation_agent.validate(
            incident_id,
            action_plan,
            severity,
        )

        if not isinstance(validation_result, dict):
            raise RuntimeError(
                "ValidationAgent returned an invalid result"
            )

        if not is_valid:
            self._set_phase(
                incident_id,
                state,
                FAILED,
                details={
                    "reason": "validation_rejected",
                },
            )

            return False, validation_result

        self._set_phase(incident_id, state, VALIDATED)

        return True, validation_result


    # RESPONSE ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def _run_response(self, incident_id: int, validation_result: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:

        approved_actions = validation_result.get("approved_actions")

        if approved_actions is None:
            raise RuntimeError("Validation result does not contain 'approved_actions'")

        if not isinstance(approved_actions, list):
            raise RuntimeError("Validation result contains an invalid 'approved_actions' value")

        requires_human_approval = (
            bool(validation_result.get("requires_human_approval", False))
            or
            any(isinstance(action, dict) and bool(action.get("requires_human_approval", False)) for action in approved_actions)
        )

        if requires_human_approval:

            self._set_phase(incident_id, state, AWAITING_HUMAN_APPROVAL)

            self.registry.log_action(
                incident_id,
                agent="orchestrator",
                action="human_approval_required",
                details={
                    "validation": validation_result,
                    "approved_actions": approved_actions,
                },
            )

            return {
                "status": AWAITING_HUMAN_APPROVAL,
                "approved_actions": approved_actions,
            }

        self._set_phase(incident_id, state, RESPONSE)

        response = self.response_layer.execute(incident_id, approved_actions)

        if not isinstance(response, dict):
            raise RuntimeError("ResponseLayer returned an invalid result")

        self._set_phase(incident_id, state, RESPONDED)

        return response


    # POST-APPROVAL ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def resume_after_human_approval(self, incident_id: int, approved_actions: list) -> Dict[str, Any]:

        incident = self.registry.get_incident(incident_id)

        if incident is None:
            raise RuntimeError(f"Incident {incident_id} not found")

        current_status = incident.get("status")

        if current_status != AWAITING_HUMAN_APPROVAL:
            raise RuntimeError(f"Incident {incident_id} is not "f"awaiting human approval. "f"Current status: {current_status}")

        state: Dict[str, Any] = {"phase": AWAITING_HUMAN_APPROVAL}

        self.registry.log_action(
            incident_id,
            agent="orchestrator",
            action="human_approval_received",
            details={
                "approved_actions": approved_actions,
            },
        )

        validation_result = {"requires_human_approval": False, "approved_actions": approved_actions}

        try:
            response = self._run_response(incident_id, validation_result, state)

            self.registry.log_action(
                incident_id,
                agent="orchestrator",
                action="completed",
                details={
                    "response": response,
                },
            )

            return {"incident_id": incident_id, "status": RESPONDED, "response": response}

        except Exception as exc:
            return self._fail(incident_id, state, RESPONSE, exc)


    # MAIN LOOP ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def handle_alert(self, source: str, raw_payload: Dict[str, Any], external_id: Optional[str] = None) -> Dict[str, Any]:
        
        with logging_agent.track("orchestrator","handle_alert"):

            incident_id = self.registry.create_incident(source=source, external_id=external_id, raw_payload=raw_payload)

            self.registry.log_action(
                incident_id,
                agent="orchestrator",
                action="created",
                details={
                    "source": source,
                    "external_id": external_id,
                },
            )

            state: Dict[str, Any] = {"phase": NEW}
            context = ""
            triage_result: Optional[Dict[str, Any]] = None
            action_plan: Optional[Dict[str, Any]] = None
            validation_result: Optional[Dict[str, Any]] = None
            response: Optional[Dict[str, Any]] = None

            for step in range(self.MAX_STEPS):

                action = None

                try:
                    action = self.router.decide(state)

                    logger.info("Incident %s - router decision=%s step=%s phase=%s", incident_id, action, step, state.get("phase"))

                    self.registry.log_action(
                        incident_id,
                        agent="router_agent",
                        action="decision",
                        details={
                            "decision": action,
                            "step": step,
                            "phase": state.get("phase"),
                        },
                    )

                    if action == ACTION_END:
                        status = state.get("phase", "unknown")

                        return {
                            "incident_id": incident_id,
                            "status": status,
                            "triage": triage_result,
                            "context": context,
                            "action_plan": action_plan,
                            "validation": validation_result,
                            "response": response,
                        }

                    if action == ACTION_TRIAGE:
                        triage_result = self._run_triage(incident_id, raw_payload, source, state)
                        continue

                    if action == ACTION_RETRIEVE:
                        retrieval = self._run_retrieve(incident_id, state)
                        context = retrieval.get("context", "")
                        continue

                    if action == ACTION_PLAN:
                        action_plan = self._run_planning(incident_id, context, state)
                        continue

                    if action == ACTION_VALIDATE:
                        if action_plan is None:
                            raise RuntimeError("VALIDATION requested but no action plan exists")

                        if triage_result is None:
                            raise RuntimeError("VALIDATION requested but no triage result exists")

                        severity = triage_result.get("severity")

                        is_valid, validation_result = self._run_validation(incident_id, action_plan, severity, state)

                        if not is_valid:
                            return {
                                "incident_id": incident_id,
                                "status": FAILED,
                                "phase": VALIDATION,
                                "triage": triage_result,
                                "context": context,
                                "action_plan": action_plan,
                                "validation": validation_result,
                                "response": None,
                            }

                        continue

                    if action == ACTION_EXECUTE:
                        if validation_result is None:
                            raise RuntimeError("EXECUTE requested but no validation result exists")

                        response = self._run_response(incident_id, validation_result, state)

                        if response.get("status") == AWAITING_HUMAN_APPROVAL:
                            return {
                                "incident_id": incident_id,
                                "status": AWAITING_HUMAN_APPROVAL,
                                "triage": triage_result,
                                "context": context,
                                "action_plan": action_plan,
                                "validation": validation_result,
                                "response": response,
                            }

                        continue


                    if action == ACTION_WAIT_FOR_HUMAN:
                        return {
                            "incident_id": incident_id,
                            "status": AWAITING_HUMAN_APPROVAL,
                            "triage": triage_result,
                            "context": context,
                            "action_plan": action_plan,
                            "validation": validation_result,
                            "response": response,
                        }


                    raise RuntimeError("Router returned unsupported "f"action: {action}")

                except Exception as exc:
                    return self._fail(incident_id, state, state.get("phase", "unknown"), exc)

            return self._fail(
                incident_id, 
                state, 
                state.get("phase", "unknown"), 
                RuntimeError("Maximum orchestration steps "f"({self.MAX_STEPS}) exceeded")
            )


# ENTRY POINT ----------------------------------------------------------------------------------------------------------------------------------------------------------    
def handle_alert(source: str, raw_payload: Dict[str, Any], external_id: Optional[str] = None) -> Dict[str, Any]:
    return Orchestrator().handle_alert(source=source, raw_payload=raw_payload, external_id=external_id)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    for lib in (
        "httpx",
        "sentence_transformers",
        "transformers",
        "urllib3",
        "chromadb",
    ):
        logging.getLogger(lib).setLevel(logging.WARNING)

    if len(sys.argv) > 1:
        with open(
            sys.argv[1],
            "r",
            encoding="utf-8-sig",
        ) as f:
            payload = json.load(f)
    else:
        payload = json.loads(input("Raw alert JSON: "))

    source = payload.pop("_source", "manual")

    report = handle_alert(
        source=source,
        raw_payload=payload,
    )

    print(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )
