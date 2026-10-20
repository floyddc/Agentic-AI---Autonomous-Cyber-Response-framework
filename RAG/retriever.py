import time
from typing import Any, Dict, List, Optional
import config
from .embeddings import embed_query
from .reranker import rerank
from .text_cleaner import clean_retrieval_text
from .vector_store import get_collection

def retrieve(
    query: str,
    customer_id: int,
    top_k: int = config.TOP_K,
    metrics: Optional[Dict[str, Any]] = None,
) -> List[dict]:
    if isinstance(customer_id, bool) or not isinstance(customer_id, int) or customer_id <= 0:
        raise ValueError("customer_id must be a positive integer for tenant-scoped retrieval")

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
                "candidate_results": [],
                "reranked_results": [],
            })
        return []

    candidate_k = min(max(top_k, config.RERANK_CANDIDATES), collection.count())

    # generate query embedding
    start = time.perf_counter()
    query_embedding = embed_query(query)
    embedding_ms = (time.perf_counter() - start) * 1000

    # ChromaDB vector search
    start = time.perf_counter()
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=candidate_k,
        where={"$or": [{"scope": "global"}, {"customer": customer_id}]},
    )
    search_ms = (time.perf_counter() - start) * 1000

    # build hits
    start = time.perf_counter()
    hits = []
    for doc, meta, dist in zip(results["documents"][0], results["metadatas"][0], results["distances"][0]):
        cleaned_doc = clean_retrieval_text(doc)
        if cleaned_doc:
            hits.append({"text": cleaned_doc, "metadata": meta, "distance": dist})
    hits_ms = (time.perf_counter() - start) * 1000

    candidate_results = [
        {
            "rank": rank,
            "source": hit["metadata"].get("source"),
            "category": hit["metadata"].get("category"),
            "vector_distance": float(hit["distance"]),
        }
        for rank, hit in enumerate(hits, start=1)
    ]

    # reranking
    start = time.perf_counter()
    reranked_hits = rerank(query, hits, top_k=len(hits))
    rerank_ms = (time.perf_counter() - start) * 1000
    reranked_results = [
        {
            "rank": rank,
            "source": hit["metadata"].get("source"),
            "category": hit["metadata"].get("category"),
            "rerank_score": hit.get("rerank_score"),
        }
        for rank, hit in enumerate(reranked_hits, start=1)
    ]
    ranked_hits = reranked_hits[:top_k]

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
            "result_count": len(ranked_hits),
            "candidate_results": candidate_results,
            "reranked_results": reranked_results,
        })

    return ranked_hits

def format_context(hits: List[dict]) -> str:
    if not hits:
        return "No relevant context found in the knowledge base."

    context_parts = []
    seen = set()
    for hit in hits:
        text = clean_retrieval_text(hit["text"])
        if text and text not in seen:
            context_parts.append(text)
            seen.add(text)

    return "\n\n".join(context_parts) or "No relevant context found in the knowledge base."
