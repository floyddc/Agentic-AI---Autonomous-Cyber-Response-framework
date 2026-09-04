import json
from typing import Any, Dict, List, Optional
from . import config
from .db import cursor as _cursor
from .knowledge_store import IncidentHistoryStore


class IncidentRegistry:

    def __init__(self, history_store: Optional[IncidentHistoryStore] = None):
        self.history_store = history_store or IncidentHistoryStore()

    def create_incident(
        self,
        source: str,
        summary: str = "",
        description: str = "",
        severity: Optional[str] = None,
        external_id: Optional[str] = None,
        raw_payload: Optional[Dict[str, Any]] = None,
    ) -> int:
        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute(
                """
                INSERT INTO incidents (source, external_id, summary, description, severity, raw_payload)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (source, external_id, summary, description, severity, json.dumps(raw_payload or {})),
            )
            return cur.fetchone()["id"]

    def update_status(self, incident_id: int, status: str) -> None:
        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute(
                "UPDATE incidents SET status = %s, updated_at = now() WHERE id = %s",
                (status, incident_id),
            )

    def get_incident(self, incident_id: int) -> Optional[Dict[str, Any]]:
        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute("SELECT * FROM incidents WHERE id = %s", (incident_id,))
            return cur.fetchone()

    def list_incidents(self, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            if status:
                cur.execute(
                    "SELECT * FROM incidents WHERE status = %s ORDER BY created_at DESC LIMIT %s",
                    (status, limit),
                )
            else:
                cur.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT %s", (limit,))
            return cur.fetchall()

    def log_action(self, incident_id: Optional[int], agent: str, action: str, details: Optional[Dict[str, Any]] = None) -> None:
        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute(
                """
                INSERT INTO audit_log (incident_id, agent, action, details)
                VALUES (%s, %s, %s, %s)
                """,
                (incident_id, agent, action, json.dumps(details or {})),
            )

    def get_audit_trail(self, incident_id: int) -> List[Dict[str, Any]]:
        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute(
                "SELECT * FROM audit_log WHERE incident_id = %s ORDER BY created_at ASC",
                (incident_id,),
            )
            return cur.fetchall()

    def close_incident(self, incident_id: int, resolution: str = "", lessons_learned: str = "") -> None:

        incident = self.get_incident(incident_id)
        if incident is None:
            return

        self.update_status(incident_id, "closed")
        self.history_store.add(
            incident_id=incident_id,
            source=incident.get("source", ""),
            summary=incident.get("summary", ""),
            description=incident.get("description", ""),
            severity=incident.get("severity"),
            resolution=resolution,
            lessons_learned=lessons_learned,
            raw_payload=incident.get("raw_payload"),
        )
