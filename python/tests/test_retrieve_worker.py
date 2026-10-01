from MQTT.worker import Worker
from MQTT.events import Event
from MQTT.topics import INCIDENT_CREATED, RETRIEVE_GROUP
from knowledge.registry import STATUS_RETRIEVED

class TestRetrieveWorker(Worker):

    def __init__(self, worker_name="test-retrieve"):
        super().__init__(
            worker_name=worker_name,
            input_topic=INCIDENT_CREATED,
            group=RETRIEVE_GROUP,
        )

    def handle_event(self, event: Event) -> None:
        print(f"Processing incident {event.incident_id}")

        self.registry.transition(
            incident_id=event.incident_id,
            status=STATUS_RETRIEVED,
            producer=self.worker_name,
            payload={
                "status": "retrieved",
                "original_event_id": event.event_id,
            },
            correlation_id=event.correlation_id,
        )