from typing import List
import chromadb
from tqdm import tqdm
from . import config
from .embeddings import embed_texts

_BATCH_SIZE = 64

def _client() -> chromadb.PersistentClient:
    return chromadb.PersistentClient(path=config.INDICES_DIR)

def get_collection():
    return _client().get_or_create_collection(
        name=config.COLLECTION_NAME
    )

def reset_collection():
    client = _client()

    try:
        client.delete_collection(config.COLLECTION_NAME)
    except ValueError:
        pass

    return client.get_or_create_collection(
        name=config.COLLECTION_NAME
    )

def index_records(records: List[dict], reset: bool = False) -> int:

    collection = reset_collection() if reset else get_collection()

    if not records:
        return 0

    total = 0

    with tqdm(
        total=len(records),
        desc="Indexing knowledge base",
        unit="chunk",
    ) as progress:

        for i in range(0, len(records), _BATCH_SIZE):

            batch = records[i:i + _BATCH_SIZE]

            ids = [r["id"] for r in batch]
            texts = [r["text"] for r in batch]
            metadatas = [r["metadata"] for r in batch]

            # Generate embeddings for the entire batch
            embeddings = embed_texts(texts)

            # Store embeddings in ChromaDB
            collection.upsert(
                ids=ids,
                documents=texts,
                metadatas=metadatas,
                embeddings=embeddings,
            )

            total += len(batch)

            # Update global progress
            progress.update(len(batch))

    return total
