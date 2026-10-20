import logging
import re
import time
from typing import Any, Dict, List, Optional
import config
from .embeddings import embed_query
from .reranker import rerank
from .text_cleaner import clean_retrieval_text, split_sentences
from .vector_store import get_collection

logger = logging.getLogger(__name__)

_TECHNIQUE_ID = re.compile(r"(?<![A-Za-z0-9])[Tt](\d{4})(?:[._](\d{3}))?(?!\d)")


def _diversity_key(hit: dict) -> str:
    # the same MITRE technique can come from several sources/chunks: treat it as one result
    metadata = hit["metadata"]
    source = str(metadata.get("source") or "")
    match = _TECHNIQUE_ID.search(source) or _TECHNIQUE_ID.search(hit["text"][:300])
    if not match:
        return source
    return f"T{match.group(1)}" + (f".{match.group(2)}" if match.group(2) else "")


def select_hits(
    reranked_hits: List[dict],
    top_k: int,
    min_score: Optional[float] = None,
    margin: Optional[float] = None,
) -> List[dict]:
    """Keep the best hit per technique/source, drop weak ones, and cap at top_k.

    A hit is weak when its score is below min_score or more than `margin` below the best hit."""
    min_score = config.RERANK_MIN_SCORE if min_score is None else min_score
    margin = config.RERANK_SCORE_MARGIN if margin is None else margin
    selected: List[dict] = []
    seen = set()
    for hit in reranked_hits:
        key = _diversity_key(hit)
        if key in seen:
            continue
        score = hit.get("rerank_score")
        if selected and score is not None:
            best = selected[0].get("rerank_score")
            if score < min_score or (best is not None and score < best - margin):
                break
        seen.add(key)
        selected.append(hit)
        if len(selected) >= top_k:
            break
    return selected


def merge_chunks(current: str, following: str, title: Optional[str] = None) -> str:
    """Append the next chunk to the current one, dropping the title prefix and the sentences shared by the overlap."""
    if title and following.startswith(f"{title}: "):
        following = following[len(title) + 2:]
    current_sentences = split_sentences(current)
    following_sentences = split_sentences(following)
    for shared in range(min(len(current_sentences), len(following_sentences)), 0, -1):
        if current_sentences[-shared:] == following_sentences[:shared]:
            following_sentences = following_sentences[shared:]
            break
    return " ".join([current, *following_sentences]).strip()


def expand_hits(collection, hits: List[dict], count: int) -> None:
    """Extend the best hits with the following chunk of the same document, in place."""
    for hit in hits[:count]:
        metadata = hit["metadata"]
        index = metadata.get("chunk_index")
        source = metadata.get("source")
        if not isinstance(index, int) or isinstance(index, bool) or not source:
            continue
        try:
            found = collection.get(ids=[f"{source}::{index + 1}"], include=["documents"])
            documents = found.get("documents") or []
        except Exception:
            logger.warning("Could not load the chunk following %s::%s", source, index, exc_info=True)
            continue
        if documents:
            hit["text"] = merge_chunks(hit["text"], clean_retrieval_text(documents[0]), metadata.get("title"))


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
    ranked_hits = select_hits(reranked_hits, top_k)
    selected_results = [
        {
            "rank": rank,
            "source": hit["metadata"].get("source"),
            "category": hit["metadata"].get("category"),
            "rerank_score": hit.get("rerank_score"),
        }
        for rank, hit in enumerate(ranked_hits, start=1)
    ]
    expand_hits(collection, ranked_hits, config.CONTEXT_EXPAND_TOP)

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
            "selected_results": selected_results,
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
