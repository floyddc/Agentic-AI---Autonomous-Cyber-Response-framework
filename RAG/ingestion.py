import glob
import os
from dataclasses import dataclass
from typing import Iterator, List
from . import config
from .knowledge_store import IncidentHistoryStore, KnowledgeBaseStore

SUPPORTED_EXTENSIONS = (".md", ".txt", ".json")


@dataclass
class SourceDocument:
    path: str
    category: str
    content: str


def _iter_files(root: str) -> Iterator[str]:
    if not os.path.isdir(root):
        return
    for path in glob.glob(os.path.join(root, "**", "*"), recursive=True):
        if os.path.isfile(path) and path.lower().endswith(SUPPORTED_EXTENSIONS):
            yield path


def _load_file_documents() -> List[SourceDocument]:

    sources = {
        "policies": config.POLICIES_DIR,
        "actions_catalog": config.ACTIONS_CATALOG_DIR,
    }

    documents: List[SourceDocument] = []
    for category, folder in sources.items():
        for path in _iter_files(folder):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content:
                documents.append(SourceDocument(path=path, category=category, content=content))
    return documents


def _load_knowledge_base_documents() -> List[SourceDocument]:

    documents: List[SourceDocument] = []

    for row in KnowledgeBaseStore().list_documents():
        documents.append(SourceDocument(path=row["source_path"], category=row["category"], content=row["content"]))

    for row in IncidentHistoryStore().list_history():
        parts = [f"summary: {row['summary']}", f"description: {row['description']}"]
        if row.get("resolution"):
            parts.append(f"resolution: {row['resolution']}")
        if row.get("lessons_learned"):
            parts.append(f"lessons_learned: {row['lessons_learned']}")
        content = "\n".join(p for p in parts if p.strip())
        if content:
            documents.append(SourceDocument(path=f"incident_history::{row['id']}", category="incident_history", content=content))

    return documents


def load_documents() -> List[SourceDocument]:

    return _load_knowledge_base_documents() + _load_file_documents()


def chunk_text(text: str, chunk_size: int = config.CHUNK_SIZE, overlap: int = config.CHUNK_OVERLAP) -> List[str]:

    words = text.split()
    if not words:
        return []

    step = max(chunk_size - overlap, 1)
    chunks = []
    for start in range(0, len(words), step):
        chunks.append(" ".join(words[start:start + chunk_size]))
        if start + chunk_size >= len(words):
            break
    return chunks


def build_chunks() -> List[dict]:

    records = []
    
    for doc in load_documents():
        for i, chunk in enumerate(chunk_text(doc.content)):
            records.append({
                "id": f"{doc.path}::{i}",
                "text": chunk,
                "metadata": {"source": doc.path, "category": doc.category, "chunk_index": i},
            })
    return records
