from typing import List
from . import config
from .embeddings import embed_query
from .vectorstore import get_collection

def retrieve(query: str, top_k: int = config.TOP_K) -> List[dict]:

    collection = get_collection()
    if collection.count() == 0:
        return []

    query_embedding = embed_query(query)
    results = collection.query(query_embeddings=[query_embedding], n_results=min(top_k, collection.count()))

    hits = []
    for doc, meta, dist in zip(results["documents"][0], results["metadatas"][0], results["distances"][0]):
        hits.append({"text": doc, "metadata": meta, "distance": dist})
    return hits

def format_context(hits: List[dict]) -> str:
    if not hits:
        return "No relevant context found in the knowledge base."

    parts = []
    for i, hit in enumerate(hits, start=1):
        source = hit["metadata"].get("source", "unknown")
        parts.append(f"[{i}] (source: {source})\n{hit['text']}")
    return "\n\n".join(parts)
