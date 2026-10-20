import re
from dataclasses import dataclass
from typing import Any, Dict, List
import config
from .knowledge_store import IncidentHistoryStore, KnowledgeBaseStore
from .text_cleaner import clean_retrieval_text, split_sentences


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


def _word_windows(text: str, chunk_size: int, overlap: int) -> List[str]:
    words = text.split()
    step = max(chunk_size - overlap, 1)
    windows = []
    for start in range(0, len(words), step):
        windows.append(" ".join(words[start:start + chunk_size]))
        if start + chunk_size >= len(words):
            break
    return windows


def chunk_text(text: str, chunk_size: int = config.CHUNK_SIZE, overlap: int = config.CHUNK_OVERLAP) -> List[str]:
    """Split on sentence boundaries so chunks never end mid-sentence; consecutive
    chunks share trailing sentences (up to `overlap` words). A sentence longer than
    chunk_size falls back to plain word windows."""

    chunks: List[str] = []
    current: List[str] = []
    count = 0

    def flush() -> None:
        if current:
            chunks.append(" ".join(current))

    for sentence in split_sentences(clean_retrieval_text(text)):
        size = len(sentence.split())
        if size > chunk_size:
            flush()
            current, count = [], 0
            chunks.extend(_word_windows(sentence, chunk_size, overlap))
            continue
        if current and count + size > chunk_size:
            flush()
            carried: List[str] = []
            carried_words = 0
            for previous in reversed(current):
                previous_size = len(previous.split())
                if carried_words + previous_size > overlap or carried_words + previous_size + size > chunk_size:
                    break
                carried.insert(0, previous)
                carried_words += previous_size
            current, count = carried, carried_words
        current.append(sentence)
        count += size

    flush()
    return chunks


_TITLE_PATTERN = re.compile(r"^#\s*(?P<title>.+?)(?:\s+##\s|\s*\?(?:\s|$)|$)")


def _document_title(text: str) -> str:
    first_line = next((line.strip() for line in clean_retrieval_text(text).splitlines() if line.strip()), "")
    match = _TITLE_PATTERN.match(first_line)
    return match.group("title").strip()[:160] if match else ""


def build_chunks(documents: List[SourceDocument]) -> List[dict]:

    records = []
    
    for doc in documents:
        title = _document_title(doc.content)
        for i, chunk in enumerate(chunk_text(doc.content)):
            # the first chunk already starts with the title; later ones would lose the technique they belong to
            if i > 0 and title:
                chunk = f"{title}: {chunk}"
            metadata = {
                **doc.metadata,
                "source": doc.path,
                "category": doc.category,
                "chunk_index": i,
                **({"title": title} if title else {}),
            }
            records.append({"id": f"{doc.path}::{i}", "text": chunk, "metadata": metadata})
            
    return records
