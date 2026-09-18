import time
from typing import Any, Dict, List, Optional
from . import config
from .embeddings import embed_query
from .reranker import rerank
from .vector_store import get_collection

def retrieve(query: str, top_k: int = config.TOP_K, metrics: Optional[Dict[str, Any]] = None) -> List[dict]:

    total_start = time.perf_counter()

    # get ChromaDB collection
    start = time.perf_counter()
    collection = get_collection()
    collection_ms = (time.perf_counter() - start) * 1000

    if collection.count() == 0:
        total_ms = (time.perf_counter() - total_start) * 1000
        if metrics is not None:
            metrics.update({
                "collection_ms": collection_ms,
                "embedding_ms": 0.0,
                "search_ms": 0.0,
                "hits_ms": 0.0,
                "rerank_ms": 0.0,
                "total_ms": total_ms,
                "candidate_k": 0,
                "result_count": 0,
            })
        return []

    candidate_k = min(max(top_k, config.RERANK_CANDIDATES), collection.count())

    # generate query embedding
    start = time.perf_counter()
    query_embedding = embed_query(query)
    embedding_ms = (time.perf_counter() - start) * 1000

    # ChromaDB vector search
    start = time.perf_counter()
    results = collection.query(query_embeddings=[query_embedding], n_results=candidate_k)
    search_ms = (time.perf_counter() - start) * 1000

    # build hits
    start = time.perf_counter()
    hits = []
    for doc, meta, dist in zip(results["documents"][0], results["metadatas"][0], results["distances"][0]):
        hits.append({"text": doc, "metadata": meta, "distance": dist})
    hits_ms = (time.perf_counter() - start) * 1000

    # reranking
    start = time.perf_counter()
    ranked_hits = rerank(query, hits, top_k=top_k)
    rerank_ms = (time.perf_counter() - start) * 1000

    # total retrieval time
    total_ms = (time.perf_counter() - total_start) * 1000

    # store metrics for Retrieve Agent
    if metrics is not None:
        metrics.update({
            "collection_ms": collection_ms,
            "embedding_ms": embedding_ms,
            "search_ms": search_ms,
            "hits_ms": hits_ms,
            "rerank_ms": rerank_ms,
            "total_ms": total_ms,
            "candidate_k": candidate_k,
            "result_count": len(ranked_hits)
        })

    return ranked_hits

def format_context(hits: List[dict]) -> str:
    if not hits:
        return "No relevant context found in the knowledge base."

    parts = []
    for i, hit in enumerate(hits, start=1):
        source = hit["metadata"].get("source", "unknown")
        parts.append(f"[{i}] (source: {source})\n{hit['text']}")
    return "\n\n".join(parts)
