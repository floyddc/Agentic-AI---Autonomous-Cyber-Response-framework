import json
from typing import Any, Dict, List, Optional
import config
from postgres.db import cursor


class KnowledgeBaseStore:

    def upsert_document(
        self,
        source_path: str,
        category: str,
        content: str,
        title: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        with cursor(config.POSTGRES_KNOWLEDGE_DB) as cur:
            cur.execute(
                """
                INSERT INTO kb_documents (source_path, category, title, content, metadata)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (source_path) DO UPDATE
                    SET category = EXCLUDED.category,
                        title = EXCLUDED.title,
                        content = EXCLUDED.content,
                        metadata = EXCLUDED.metadata,
                        updated_at = now()
                RETURNING id
                """,
                (source_path, category, title, content, json.dumps(metadata or {})),
            )
            return cur.fetchone()["id"]

    def list_documents(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        with cursor(config.POSTGRES_KNOWLEDGE_DB) as cur:
            if category:
                cur.execute("SELECT * FROM kb_documents WHERE category = %s ORDER BY source_path", (category,))
            else:
                cur.execute("SELECT * FROM kb_documents ORDER BY category, source_path")
            return cur.fetchall()


class IncidentHistoryStore:

    def add(
        self,
        incident_id: Optional[int],
        source: str = "",
        summary: str = "",
        description: str = "",
        severity: Optional[str] = None,
        resolution: str = "",
        lessons_learned: str = "",
        raw_payload: Optional[Dict[str, Any]] = None,
    ) -> int:
        with cursor(config.POSTGRES_KNOWLEDGE_DB) as cur:
            cur.execute(
                """
                INSERT INTO incident_history
                    (incident_id, source, summary, description, severity, resolution, lessons_learned, raw_payload)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    incident_id,
                    source,
                    summary,
                    description,
                    severity,
                    resolution,
                    lessons_learned,
                    json.dumps(raw_payload or {}),
                ),
            )
            return cur.fetchone()["id"]

    def list_history(self, limit: int = 500) -> List[Dict[str, Any]]:
        with cursor(config.POSTGRES_KNOWLEDGE_DB) as cur:
            cur.execute("SELECT * FROM incident_history ORDER BY created_at DESC LIMIT %s", (limit,))
            return cur.fetchall()


class IndexStateStore:
    
    def get_cursor(self, source: str) -> int:
        with cursor(config.POSTGRES_KNOWLEDGE_DB) as cur:
            cur.execute(
                """
                INSERT INTO index_cursors (source, last_id)
                VALUES (%s, 0)
                ON CONFLICT (source) DO NOTHING
                """,
                (source,),
            )
            cur.execute(
                "SELECT last_id FROM index_cursors WHERE source = %s",
                (source,),
            )
            row = cur.fetchone()
            if row is None:
                raise RuntimeError(f"Unable to load RAG index cursor for {source}")
            return row["last_id"]

    def advance_cursor(self, source: str, last_id: int) -> None:
        with cursor(config.POSTGRES_KNOWLEDGE_DB) as cur:
            cur.execute(
                """
                INSERT INTO index_cursors (source, last_id)
                VALUES (%s, %s)
                ON CONFLICT (source) DO UPDATE
                SET last_id = GREATEST(index_cursors.last_id, EXCLUDED.last_id),
                    updated_at = now()
                """,
                (source, last_id),
            )