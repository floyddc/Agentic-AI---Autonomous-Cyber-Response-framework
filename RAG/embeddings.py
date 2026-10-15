import os
from typing import List
import config

_MAX_PROMPT_CHARS = 1600
_model = None

def _get_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer

        _model = SentenceTransformer(
            config.EMBEDDING_MODEL,
            device="cpu",
            model_kwargs={"cache_dir": config.CACHE_DIR},
        )
    return _model

def _prepare_query(text: str) -> str:
    return "query: " + text[:_MAX_PROMPT_CHARS]

def _prepare_document(text: str) -> str:
    return "passage: " + text[:_MAX_PROMPT_CHARS]


def embed_texts(texts: List[str]) -> List[List[float]]:
    if not texts: return []

    prepared = [
        _prepare_document(text)
        for text in texts
    ]
    embeddings = _get_model().encode(
        prepared,
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=False,
    )
    return embeddings.tolist()


def embed_query(text: str) -> List[float]:

    query = _prepare_query(text)
    embedding = _get_model().encode(
        query,
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=False,
    )
    return embedding.tolist()