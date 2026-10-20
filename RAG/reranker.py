from typing import List
import config

_model = None

def _get_model():
    global _model
    if _model is None:
        from sentence_transformers import CrossEncoder
        _model = CrossEncoder(config.RERANKER_MODEL, device="cpu", cache_folder=config.CACHE_DIR)
    return _model


def rerank(query: str, hits: List[dict], top_k: int) -> List[dict]:

    if not hits:
        return hits

    pairs = [(query, hit["text"]) for hit in hits]
    scores = _get_model().predict(pairs)

    for hit, score in zip(hits, scores):
        hit["rerank_score"] = float(score)

    ranked = sorted(hits, key=lambda h: h["rerank_score"], reverse=True)
    return ranked[:top_k]
