import logging
from typing import Optional
from MQTT.events import Event
from MQTT.topics import INCIDENT_CREATED, RETRIEVE_GROUP
from knowledge.registry import IncidentRegistry, STATUS_RETRIEVED
from MQTT.worker import Worker
from ..retrieve_agent import RetrieveAgent


class RetrieveWorker(Worker):
    def __init__(
        self,
        *,
        worker_name: str = "retrieve-worker",
        registry: Optional[IncidentRegistry] = None,
        retrieve_agent: Optional[RetrieveAgent] = None,
    ):
        shared_registry = registry or IncidentRegistry()
        super().__init__(
            worker_name=worker_name,
            input_topic=INCIDENT_CREATED,
            group=RETRIEVE_GROUP,
            registry=shared_registry,
        )
        self.retrieve_agent = retrieve_agent or RetrieveAgent(registry=self.registry)


    # BUSINESS LOGIC ----------------------------------------------------------------------------------------------------------------------------------------------------------
    def handle_event(self, event: Event) -> None:
        incident = self.registry.get_incident(event.incident_id)
        if incident is None: raise RuntimeError(f"Incident {event.incident_id} not found")
      
        # retrieve
        result = self.retrieve_agent.retrieve(incident, incident_id=event.incident_id)
        if not isinstance(result, dict): raise RuntimeError("RetrieveAgent returned an invalid result")
        if result.get("error"): raise RuntimeError(f"Context retrieval failed: {result['error']}")
        context = result.get("context")
        if not isinstance(context, str): raise RuntimeError("RetrieveAgent result does not contain a valid context")

        # send new status and results
        self.transition_incident(
            incident_id=event.incident_id,
            status=STATUS_RETRIEVED,
            payload={
                "context": context,
                "original_event_id": event.event_id,
            },
            correlation_id=event.correlation_id,
            idempotency_key=f"retrieve:{event.event_id}:{STATUS_RETRIEVED}",
        )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    RetrieveWorker().run()
