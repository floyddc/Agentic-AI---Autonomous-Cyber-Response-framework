from typing import List
from ollama import Client
from . import config

_client = Client(host=config.OLLAMA_HOST)

_MAX_PROMPT_CHARS = 1600

def embed_texts(texts: List[str]) -> List[List[float]]:

    if not texts:
        return []

    truncated = [
        text[:_MAX_PROMPT_CHARS]
        for text in texts
    ]

    response = _client.embed(
        model=config.EMBEDDING_MODEL,
        input=truncated,
    )

    return response["embeddings"]


def embed_query(text: str) -> List[float]:

    truncated = text[:_MAX_PROMPT_CHARS]

    return _client.embeddings(
        model=config.EMBEDDING_MODEL,
        prompt=truncated,
    )["embedding"]
