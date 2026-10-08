import logging
from typing import Optional
import config
from MQTT.events import Event
from MQTT.topics import INCIDENT_TRIAGED, PLANNER_GROUP
from MQTT.worker import Worker
from knowledge.registry import IncidentRegistry, STATUS_ACTION_PROPOSED
from ..action_planner_agent import ActionPlannerAgent


class ActionPlannerWorker(Worker):
    def __init__(
        self,
        *,
        worker_name: str = "action-planner-worker",
        registry: Optional[IncidentRegistry] = None,
        action_planner_agent: Optional["ActionPlannerAgent"] = None,
    ):
        shared_registry = registry or IncidentRegistry()
        super().__init__(
            worker_name=worker_name,
            input_topic=INCIDENT_TRIAGED,
            group=PLANNER_GROUP,
            registry=shared_registry,
        )
        self.action_planner_agent = action_planner_agent or ActionPlannerAgent(registry=self.registry)


    # BUSINESS LOGIC ----------------------------------------------------------------------------------------------------------------------------------------------------------
    def handle_event(self, event: Event) -> None:
        incident = self.registry.get_incident(event.incident_id)
        if incident is None: raise RuntimeError(f"Incident {event.incident_id} not found")

        # collect info about event payload
        context = event.payload.get("context", "")
        if not isinstance(context, str): raise RuntimeError(f"Triaged event {event.event_id} has an invalid context")
        triage_result = event.payload.get("triage")
        if not isinstance(triage_result, dict): raise RuntimeError(f"Triaged event {event.event_id} has an invalid triage result")
        severity = triage_result.get("severity")
        if severity not in config.VALID_SEVERITIES: raise RuntimeError(f"Triaged event {event.event_id} has an invalid severity: {severity!r}")

        # planning
        action_plan = self.action_planner_agent.propose_action_plan(incident, context, incident_id=event.incident_id)
        if not isinstance(action_plan, dict): raise RuntimeError("ActionPlannerAgent returned an invalid action plan")
        if not isinstance(action_plan.get("actions"), list): raise RuntimeError("ActionPlannerAgent returned an action plan without an actions list")

        # send new status and results
        self.transition_incident(
            incident_id=event.incident_id,
            status=STATUS_ACTION_PROPOSED,
            payload={
                "action_plan": action_plan,
                "context": context,
                "severity": severity,
                "original_event_id": event.event_id,
            },
            correlation_id=event.correlation_id,
            idempotency_key=f"action-plan:{event.event_id}:{STATUS_ACTION_PROPOSED}",
        )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    ActionPlannerWorker().run()
       