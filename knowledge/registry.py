import json
import uuid
from typing import Any, Dict, List, Optional
from RAG import config
from postgres.db import cursor as _cursor
from postgres.db import transaction
from RAG.knowledge_store import IncidentHistoryStore
from MAPE.logging_agent import logging_agent
from MQTT import topics
from MQTT.events import Event

STATUS_NEW = "new"
STATUS_RETRIEVE = "retrieve"
STATUS_RETRIEVED = "retrieved"
STATUS_TRIAGE = "triage"
STATUS_TRIAGED = "triaged"
STATUS_PLANNING = "planning"
STATUS_ACTION_PROPOSED = "action_proposed"
STATUS_VALIDATION = "validation"
STATUS_VALIDATED = "validated"
STATUS_AWAITING_HUMAN_APPROVAL = "awaiting_human_approval"
STATUS_RESPONSE = "response"
STATUS_RESPONDED = "responded"
STATUS_FAILED = "failed"
STATUS_CLOSED = "closed"

ALLOWED_STATUSES = {
    STATUS_NEW,
    STATUS_RETRIEVE,
    STATUS_RETRIEVED,
    STATUS_TRIAGE,
    STATUS_TRIAGED,
    STATUS_PLANNING,
    STATUS_ACTION_PROPOSED,
    STATUS_VALIDATION,
    STATUS_VALIDATED,
    STATUS_AWAITING_HUMAN_APPROVAL,
    STATUS_RESPONSE,
    STATUS_RESPONDED,
    STATUS_FAILED,
    STATUS_CLOSED,
}

STATUS_EVENT_MAP = {
    STATUS_RETRIEVE: topics.INCIDENT_CREATED,
    STATUS_RETRIEVED: topics.INCIDENT_RETRIEVED,
    STATUS_TRIAGED: topics.INCIDENT_TRIAGED,
    STATUS_ACTION_PROPOSED: topics.ACTION_PROPOSED,
    STATUS_VALIDATED: topics.ACTION_VALIDATED,
    STATUS_AWAITING_HUMAN_APPROVAL: topics.HUMAN_APPROVAL_REQUIRED,
    STATUS_RESPONDED: topics.ACTION_EXECUTED,
    STATUS_CLOSED: topics.INCIDENT_COMPLETED,
    STATUS_FAILED: topics.INCIDENT_FAILED,
}


class IncidentRegistry:
    def __init__(self, history_store: Optional[IncidentHistoryStore] = None):
        self.history_store = history_store or IncidentHistoryStore()


    # 1. Insert the specified incident as a new one
    # 2. Insert event (INCIDENT_CREATED) into Outbox
    # 3. Write on Audit Log 
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
            with transaction(config.POSTGRES_OPERATIONAL_DB) as conn:
                with conn.cursor() as cur:

                    cur.execute(
                        """
                        INSERT INTO incidents (source, external_id, summary, description, severity, raw_payload)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id
                        """,
                        (source, external_id, summary, description, severity, json.dumps(raw_payload or {}))
                    )

                    row = cur.fetchone()
                    if not row:
                        raise RuntimeError("Failed to create incident")

                    incident_id = row[0]
                    correlation_id = str(uuid.uuid4())

                    self._insert_outbox_event(
                        cur,
                        incident_id=incident_id,
                        event_type=topics.INCIDENT_CREATED,
                        correlation_id=correlation_id,
                        producer="incident_registry",
                        topic=topics.INCIDENT_CREATED,
                        payload={
                            "source": source,
                            "external_id": external_id,
                            "summary": summary,
                            "description": description,
                            "severity": severity,
                            "raw_payload": raw_payload or {},
                        },
                    )

                    cur.execute(
                        """
                        INSERT INTO audit_log (incident_id, agent, action, details)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (incident_id, "incident_registry", "created", json.dumps({"source": source, "external_id": external_id}))
                    )

                    return incident_id

    # 1. Try to find the specified incident
    # 2. Update incident status
    # 3. Write on Audit Log 
    # 4. Insert event into event_outbox
        # 4.1 Outbox Publisher will publish it
    def transition(
        self,
        incident_id: int,
        *,
        status: str,
        producer: str,
        payload: Optional[Dict[str, Any]] = None,
        event_type: Optional[str] = None,
        topic: Optional[str] = None,
        correlation_id: Optional[str] = None,
        audit_details: Optional[Dict[str, Any]] = None,
    ) -> str:

        if status not in ALLOWED_STATUSES:
            raise ValueError(f"Invalid incident status: {status}")

        correlation_id = correlation_id or str(uuid.uuid4())
        payload = payload or {}

        with logging_agent.track("incident_registry", "transition", incident_id=incident_id):
            with transaction(config.POSTGRES_OPERATIONAL_DB) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT status
                        FROM incidents
                        WHERE id = %s
                        FOR UPDATE
                        """,
                        (incident_id,),
                    )

                    row = cur.fetchone()
                    if row is None:
                        raise RuntimeError(f"Incident {incident_id} not found")

                    previous_status = row[0]
                    cur.execute(
                        """
                        UPDATE incidents
                        SET status = %s, updated_at = now()
                        WHERE id = %s
                        """,
                        (status, incident_id)
                    )

                    details = {"from": previous_status, "to": status, **(audit_details or {})}
                    cur.execute(
                        """
                        INSERT INTO audit_log (incident_id, agent, action, details)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (incident_id, producer, "phase_transition", json.dumps(details))
                    )

                    if event_type is None:
                        event_type = STATUS_EVENT_MAP.get(status)

                    if topic is None and event_type is not None:
                        topic = event_type

                    if event_type is None or topic is None:
                        return correlation_id

                    self._insert_outbox_event(
                        cur,
                        incident_id=incident_id,
                        event_type=event_type,
                        correlation_id=correlation_id,
                        producer=producer,
                        topic=topic,
                        payload={
                            "incident_id": incident_id,
                            "previous_status": previous_status,
                            "status": status,
                            **payload,
                        },
                    )

            return correlation_id

    def _insert_outbox_event(
        self,
        cur,
        *,
        incident_id: int,
        event_type: str,
        correlation_id: str,
        producer: str,
        topic: str,
        payload: Dict[str, Any],
    ) -> str:

        event = Event.create(
            event_type=event_type,
            incident_id=incident_id,
            payload=payload,
            producer=producer,
            correlation_id=correlation_id,
        )

        cur.execute(
            """
            INSERT INTO event_outbox (event_id, incident_id, event_type, correlation_id, producer, topic, payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (event.event_id, incident_id, event.event_type, event.correlation_id, event.producer, topic, json.dumps(event.to_dict()))
        )

        return event.event_id

    # Call transition() with an allowed status
    def update_status(self, incident_id: int, status: str) -> None:

        if status not in ALLOWED_STATUSES:
            raise ValueError(f"Invalid incident status: {status}")

        self.transition(
            incident_id,
            status=status,
            producer="incident_registry"
        )

    def update_fields(self, incident_id: int, **fields: Any) -> None:

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
                (incident_id,)
            )

            return cur.fetchone()

    def get_status(self, incident_id: int) -> Optional[str]:
        incident = self.get_incident(incident_id)

        if incident is None:
            return None

        return incident.get("status")

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
        with logging_agent.track("incident_registry", "log_action", incident_id=incident_id):
            with transaction(config.POSTGRES_OPERATIONAL_DB) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO audit_log (incident_id, agent, action, details)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (incident_id, agent, action, json.dumps(details or {}))
                    )

    def receive_event(self, event: Event) -> bool:
        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute(
                """
                INSERT INTO event_inbox (event_id, incident_id, event_type, correlation_id, producer, payload)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                RETURNING id
                """,
                (event.event_id, event.incident_id, event.event_type, event.correlation_id, event.producer, json.dumps(event.payload))
            )
            row = cur.fetchone()
            return row is not None

    def get_pending_events(
        self,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute(
                """
                SELECT
                    id,
                    event_id,
                    incident_id,
                    event_type,
                    correlation_id,
                    producer,
                    payload,
                    status,
                    attempts,
                    received_at,
                    processing_started_at,
                    processed_at,
                    last_error
                FROM event_inbox
                WHERE status = 'received'
                ORDER BY received_at ASC
                LIMIT %s
                """,
                (limit,),
            )
            return cur.fetchall()

    def mark_event_processing(self, event_id: str) -> None:
        with transaction(config.POSTGRES_OPERATIONAL_DB) as conn:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    UPDATE event_inbox
                    SET
                        status = 'processing',
                        attempts = attempts + 1,
                        processing_started_at = now(),
                        last_error = NULL
                    WHERE event_id = %s
                    AND status = 'received'
                    """,
                    (event_id,),
                )
                if cur.rowcount == 0:
                    raise RuntimeError(f"Event {event_id} not found or not in 'received' state")

    def mark_event_processed(self, event_id: str) -> None:
        with transaction(config.POSTGRES_OPERATIONAL_DB) as conn:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    UPDATE event_inbox
                    SET
                        status = 'processed',
                        processed_at = now()
                    WHERE event_id = %s
                    AND status = 'processing'
                    """,
                    (event_id,),
                )

                if cur.rowcount == 0:
                    raise RuntimeError(f"Event {event_id} not found or not in 'processing' state")

    def mark_event_failed(
        self,
        event_id: str,
        error: str,
    ) -> None:
        with transaction(config.POSTGRES_OPERATIONAL_DB) as conn:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    UPDATE event_inbox
                    SET
                        status = 'failed',
                        last_error = %s
                    WHERE event_id = %s
                    AND status = 'processing'
                    """,
                    (error, event_id),
                )

                if cur.rowcount == 0:
                    raise RuntimeError(f"Event {event_id} not found or not in 'processing' state")

    def recover_stale_events(
        self,
        timeout_seconds: int = 300,
    ) -> int:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute(
                """
                UPDATE event_inbox
                SET
                    status = 'received',
                    processing_started_at = NULL,
                    last_error = 'Recovered stale processing event'
                WHERE status = 'processing'
                AND processing_started_at IS NOT NULL
                AND processing_started_at < (
                    now() - (%s * INTERVAL '1 second')
                )
                """,
                (timeout_seconds,),
            )
            return cur.rowcount

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
                (incident_id,)
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
