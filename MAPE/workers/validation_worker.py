import logging
from typing import Optional
import config
from MQTT.events import Event
from MQTT.topics import ACTION_PROPOSED, VALIDATION_GROUP
from MQTT.worker import Worker
from knowledge.registry import (
    IncidentRegistry,
    STATUS_AWAITING_HUMAN_APPROVAL,
    STATUS_FAILED,
    STATUS_VALIDATED,
)
from ..validation_agent import ValidationAgent

logger = logging.getLogger(__name__)


class ValidationWorker(Worker):
    def __init__(
        self,
        *,
        worker_name: str = "validation-worker",
        registry: Optional[IncidentRegistry] = None,
        validation_agent: Optional[ValidationAgent] = None,
    ):
        shared_registry = registry or IncidentRegistry()
        super().__init__(
            worker_name=worker_name,
            input_topic=ACTION_PROPOSED,
            group=VALIDATION_GROUP,
            registry=shared_registry,
        )
        self.validation_agent = validation_agent or ValidationAgent(registry=self.registry)


    # BUSINESS LOGIC ----------------------------------------------------------------------------------------------------------------------------------------------------------
    def handle_event(self, event: Event) -> None:
        incident = self.registry.get_incident(event.incident_id)
        if incident is None: raise RuntimeError(f"Incident {event.incident_id} not found")

        # collect info about incident and event payload
        action_plan = event.payload.get("action_plan")
        if not isinstance(action_plan, dict): raise RuntimeError(f"Action-proposed event {event.event_id} has an invalid action plan")
        if not isinstance(action_plan.get("actions"), list): raise RuntimeError(f"Action-proposed event {event.event_id} has no valid actions list")
        severity = event.payload.get("severity")
        if severity not in config.VALID_SEVERITIES: raise RuntimeError(f"Action-proposed event {event.event_id} has an invalid severity: {severity!r}")

        # validation
        validation_response = self.validation_agent.validate(event.incident_id, action_plan, severity)
        if (not isinstance(validation_response, tuple) or len(validation_response) != 2): raise RuntimeError("ValidationAgent returned an invalid result")
        is_valid, validation_result = validation_response
        if not isinstance(is_valid, bool) or not isinstance(validation_result, dict): raise RuntimeError("ValidationAgent returned an invalid result")
        approved_actions = validation_result.get("approved_actions")
        if not isinstance(approved_actions, list): raise RuntimeError("ValidationAgent result does not contain a valid approved_actions list")
        if is_valid and not approved_actions: raise RuntimeError("ValidationAgent marked the plan valid without approved actions")

        requires_human_approval = (
            bool(validation_result.get("requires_human_approval", False))
            or any(
                isinstance(action, dict)
                and bool(action.get("requires_human_approval", False))
                for action in approved_actions
            )
        )

        if not is_valid: status = STATUS_FAILED
        elif requires_human_approval: status = STATUS_AWAITING_HUMAN_APPROVAL
        else: status = STATUS_VALIDATED

        # send new status and results
        self.transition_incident(
            incident_id=event.incident_id,
            status=status,
            payload={
                "action_plan": action_plan,
                "severity": severity,
                "validation": validation_result,
                "approved_actions": approved_actions,
                "requires_human_approval": requires_human_approval,
                "original_event_id": event.event_id,
            },
            correlation_id=event.correlation_id,
            idempotency_key=f"validation:{event.event_id}:{status}",
        )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    ValidationWorker().run()
