import os

RAG_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(RAG_DIR)
KNOWLEDGE_DIR = os.path.join(PROJECT_ROOT, "knowledge")

BASE_DIR = os.path.join(KNOWLEDGE_DIR, "base")
POLICIES_DIR = os.path.join(KNOWLEDGE_DIR, "policies")
ACTIONS_CATALOG_DIR = os.path.join(KNOWLEDGE_DIR, "actions_catalog")
PROCESSED_DIR = os.path.join(KNOWLEDGE_DIR, "processed_data")
ENRICHED_INCIDENTS_DIR = os.path.join(PROCESSED_DIR, "enriched_incidents")
NORMALIZED_ALERTS_DIR = os.path.join(PROCESSED_DIR, "normalized_alerts")
INDICES_DIR = os.path.join(KNOWLEDGE_DIR, "indices")

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "qllama/multilingual-e5-small")
CHAT_MODEL = os.environ.get("CHAT_MODEL", "qwen3:4b-instruct")

POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "postgres")
POSTGRES_PORT = os.environ.get("POSTGRES_PORT", "5432")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "cyberresponse")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "cyberresponse")

# Operational DB: Incident Registry (active incidents) + Audit Store (agent action log).
POSTGRES_DB = os.environ.get("POSTGRES_DB", "incident_registry")
POSTGRES_OPERATIONAL_DB = POSTGRES_DB

# Knowledge DB: Incident History (closed/enriched incidents) + Knowledge Base (Docs store),
# both read by the RAG engine and embedded into the chromaDB vector index.
POSTGRES_KNOWLEDGE_DB = os.environ.get("POSTGRES_KNOWLEDGE_DB", "knowledge")

COLLECTION_NAME = "cyber_response_kb"

CHUNK_SIZE = 300
CHUNK_OVERLAP = 50
TOP_K = 5

# Cross-encoder reranker applied to the top RERANK_CANDIDATES results retrieved from Chroma.
RERANKER_MODEL = os.environ.get("RERANKER_MODEL", "cross-encoder/ms-marco-MiniLM-L2-v2")
RERANK_CANDIDATES = int(os.environ.get("RERANK_CANDIDATES", "10"))
