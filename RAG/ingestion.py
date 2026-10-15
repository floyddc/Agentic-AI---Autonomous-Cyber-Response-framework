from dataclasses import dataclass
from typing import Any, Dict, List
import config
from .knowledge_store import IncidentHistoryStore, KnowledgeBaseStore
from .text_cleaner import clean_retrieval_text


@dataclass
class SourceDocument:
    path: str
    category: str
    content: str
    metadata: Dict[str, Any]


def _knowledge_documents(rows: List[Dict[str, Any]]) -> List[SourceDocument]:
    documents = []
    for row in rows:
        metadata = row.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise ValueError(f"Knowledge document {row['source_path']} has invalid metadata")
        documents.append(
            SourceDocument(
                path=row["source_path"],
                category=row["category"],
                content=row["content"],
                metadata={**metadata, "scope": "global"},
            )
        )
    return documents


def _history_documents(rows: List[Dict[str, Any]]) -> List[SourceDocument]:
    documents: List[SourceDocument] = []
    for row in rows:
        metadata = row.get("metadata") or {}
        customer = metadata.get("customer") if isinstance(metadata, dict) else None
        if isinstance(customer, bool) or not isinstance(customer, int) or customer <= 0:
            continue

        parts = [f"summary: {row['summary']}", f"description: {row['description']}"]
        if row.get("resolution"):
            parts.append(f"resolution: {row['resolution']}")
        if row.get("lessons_learned"):
            parts.append(f"lessons_learned: {row['lessons_learned']}")
        content = "\n".join(p for p in parts if p.strip())
        if content:
            documents.append(
                SourceDocument(
                    path=f"incident_history::{row['id']}",
                    category="incident_history",
                    content=content,
                    metadata={**metadata, "customer": customer, "scope": "customer"},
                )
            )
    return documents


def load_new_database_documents(
    knowledge_after_id: int,
    history_after_id: int,
) -> tuple[List[SourceDocument], List[Dict[str, Any]], List[Dict[str, Any]]]:
    knowledge_rows = KnowledgeBaseStore().list_documents_after(knowledge_after_id)
    history_rows = IncidentHistoryStore().list_history_after(history_after_id)
    documents = _knowledge_documents(knowledge_rows) + _history_documents(history_rows)
    return documents, knowledge_rows, history_rows


def chunk_text(text: str, chunk_size: int = config.CHUNK_SIZE, overlap: int = config.CHUNK_OVERLAP) -> List[str]:

    words = clean_retrieval_text(text).split()
    if not words:
        return []

    step = max(chunk_size - overlap, 1)
    chunks = []
    for start in range(0, len(words), step):
        chunks.append(" ".join(words[start:start + chunk_size]))
        if start + chunk_size >= len(words):
            break
    return chunks


def build_chunks(documents: List[SourceDocument]) -> List[dict]:

    records = []
    
    for doc in documents:
        for i, chunk in enumerate(chunk_text(doc.content)):
            metadata = {
                **doc.metadata,
                "source": doc.path,
                "category": doc.category,
                "chunk_index": i,
            }
            records.append({"id": f"{doc.path}::{i}", "text": chunk, "metadata": metadata})
            
    return records
