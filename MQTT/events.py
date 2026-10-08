from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import uuid

@dataclass
class Event:
    event_id: str
    event_type: str
    incident_id: int
    correlation_id: str
    producer: str
    timestamp: str
    schema_version: int
    payload: dict[str, Any]

    @classmethod
    def create(
        cls,
        *,
        event_type: str,
        incident_id: int,
        payload: dict[str, Any],
        producer: str,
        correlation_id: str | None = None,
        event_id: str | None = None,
    ) -> "Event":

        return cls(
            event_id=event_id or str(uuid.uuid4()),
            event_type=event_type,
            incident_id=incident_id,
            correlation_id=correlation_id or str(uuid.uuid4()),
            producer=producer,
            timestamp=datetime.now(timezone.utc).isoformat(),
            schema_version=1,
            payload=payload,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "incident_id": self.incident_id,
            "correlation_id": self.correlation_id,
            "producer": self.producer,
            "timestamp": self.timestamp,
            "schema_version": self.schema_version,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        return cls(
            event_id=data["event_id"],
            event_type=data["event_type"],
            incident_id=data["incident_id"],
            correlation_id=data["correlation_id"],
            producer=data["producer"],
            timestamp=data["timestamp"],
            schema_version=data["schema_version"],
            payload=data["payload"],
        )