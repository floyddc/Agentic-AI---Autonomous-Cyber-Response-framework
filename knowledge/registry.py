import json
from typing import Any, Dict, List, Optional
from RAG import config
from postgres.db import cursor as _cursor
from RAG.knowledge_store import IncidentHistoryStore
from MAPE.logging_agent import logging_agent


STATUS_FLOW = [
    "new",
    "triage",
    "triaged",
    "retrieve",
    "validation",
    "validated",
    "awaiting_human_approval",
    "response",
    "responded",
]

STATUS_FAILED = "failed"
STATUS_CLOSED = "closed"

ALLOWED_STATUSES = set(STATUS_FLOW) | {
    STATUS_FAILED,
    STATUS_CLOSED,
}


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
        with logging_agent.track("incident_registry", "create_incident"):
            with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
                cur.execute(
                    """
                    INSERT INTO incidents (
                        source,
                        external_id,
                        summary,
                        description,
                        severity,
                        raw_payload
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    RETURNING id
                    """,
                    (
                        source,
                        external_id,
                        summary,
                        description,
                        severity,
                        json.dumps(raw_payload or {}),
                    ),
                )

                row = cur.fetchone()

                if not row:
                    raise RuntimeError("Failed to create incident")

                return row["id"]


    def update_status(self, incident_id: int, status: str) -> None:

        if status not in ALLOWED_STATUSES:
            raise ValueError(f"Invalid incident status: {status}")

        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute(
                """
                UPDATE incidents
                SET
                    status = %s,
                    updated_at = now()
                WHERE id = %s
                """,
                (status, incident_id),
            )

            if cur.rowcount == 0:
                raise RuntimeError(f"Incident {incident_id} not found")

    def get_status(self, incident_id: int) -> Optional[str]:
        incident = self.get_incident(incident_id)

        if incident is None:
            return None

        return incident.get("status")

    def update_fields(self, incident_id: int, **fields: Any) -> None:
        """
        Update a controlled subset of incident fields.
        """
        allowed = {
            "summary",
            "description",
            "severity",
            "external_id",
        }

        updates = {
            key: value
            for key, value in fields.items()
            if key in allowed and value is not None
        }

        if not updates:
            return

        set_clause = ", ".join(f"{column} = %s" for column in updates)

        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute(
                f"""
                UPDATE incidents
                SET
                    {set_clause},
                    updated_at = now()
                WHERE id = %s
                """,
                (*updates.values(), incident_id),
            )

            if cur.rowcount == 0:
                raise RuntimeError(f"Incident {incident_id} not found")


    def get_incident(
        self,
        incident_id: int,
    ) -> Optional[Dict[str, Any]]:
        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute(
                """
                SELECT *
                FROM incidents
                WHERE id = %s
                """,
                (incident_id,),
            )

            return cur.fetchone()

    def list_incidents(
        self,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        if status is not None and status not in ALLOWED_STATUSES:
            raise ValueError(f"Invalid incident status: {status}")

        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            if status:
                cur.execute(
                    """
                    SELECT *
                    FROM incidents
                    WHERE status = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (status, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT *
                    FROM incidents
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )

            return cur.fetchall()


    def log_action(
        self,
        incident_id: Optional[int],
        agent: str,
        action: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        with logging_agent.track(
            "incident_registry",
            "log_action",
            incident_id=incident_id,
        ):
            with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
                cur.execute(
                    """
                    INSERT INTO audit_log (
                        incident_id,
                        agent,
                        action,
                        details
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        incident_id,
                        agent,
                        action,
                        json.dumps(details or {}),
                    ),
                )

    def get_audit_trail(
        self,
        incident_id: int,
    ) -> List[Dict[str, Any]]:
        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute(
                """
                SELECT *
                FROM audit_log
                WHERE incident_id = %s
                ORDER BY created_at ASC
                """,
                (incident_id,),
            )

            return cur.fetchall()


    def close_incident(
        self,
        incident_id: int,
        resolution: str = "",
        lessons_learned: str = "",
    ) -> None:
        with logging_agent.track(
            "incident_registry",
            "close_incident",
            incident_id=incident_id,
        ):
            incident = self.get_incident(incident_id)

            if incident is None:
                raise RuntimeError(f"Incident {incident_id} not found")

            self.update_status(incident_id, STATUS_CLOSED)

            self.log_action(
                incident_id,
                agent="incident_registry",
                action="closed",
                details={
                    "resolution": resolution,
                    "lessons_learned": lessons_learned,
                },
            )

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
