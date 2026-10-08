import logging
from typing import Optional
import config
from MQTT.events import Event
from MQTT.topics import INCIDENT_RETRIEVED, TRIAGE_GROUP
from MQTT.worker import Worker
from knowledge.registry import IncidentRegistry, STATUS_TRIAGED
from ..triage_agent import TriageAgent


class TriageWorker(Worker):
    def __init__(
        self,
        *,
        worker_name: str = "triage-worker",
        registry: Optional[IncidentRegistry] = None,
        triage_agent: Optional[TriageAgent] = None,
    ):
        shared_registry = registry or IncidentRegistry()
        super().__init__(
            worker_name=worker_name,
            input_topic=INCIDENT_RETRIEVED,
            group=TRIAGE_GROUP,
            registry=shared_registry,
        )
        self.triage_agent = triage_agent or TriageAgent(registry=self.registry)


    # BUSINESS LOGIC ----------------------------------------------------------------------------------------------------------------------------------------------------------
    def handle_event(self, event: Event) -> None:
        incident = self.registry.get_incident(event.incident_id)
        if incident is None: raise RuntimeError(f"Incident {event.incident_id} not found")

        # collect info about incident and event payload
        source = incident.get("source")
        if not isinstance(source, str) or not source.strip(): raise RuntimeError(f"Incident {event.incident_id} has no valid source")
        raw_payload = incident.get("raw_payload")
        if not isinstance(raw_payload, dict): raise RuntimeError(f"Incident {event.incident_id} has no valid raw payload")
        context = event.payload.get("context", "")
        if not isinstance(context, str): raise RuntimeError(f"Retrieved event {event.event_id} has an invalid context")

        # triage
        result = self.triage_agent.triage(event.incident_id, raw_payload, source, context)
        if not isinstance(result, dict): raise RuntimeError("TriageAgent returned an invalid result")
        severity = result.get("severity")
        if severity not in config.VALID_SEVERITIES: raise RuntimeError(f"TriageAgent returned an invalid severity: {severity!r}")

        # send new status and results
        self.transition_incident(
            incident_id=event.incident_id,
            status=STATUS_TRIAGED,
            payload={
                "triage": result,
                "context": context,
                "original_event_id": event.event_id,
            },
            correlation_id=event.correlation_id,
            idempotency_key=f"triage:{event.event_id}:{STATUS_TRIAGED}",
        )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    TriageWorker().run()