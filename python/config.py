import os

RAG_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(RAG_DIR)
_knowledge_candidates = [
    os.environ.get("KNOWLEDGE_DIR", ""),
    os.path.join(RAG_DIR, "knowledge"),  
    os.path.join(PROJECT_ROOT, "knowledge"),  
]
KNOWLEDGE_DIR = next(
    (p for p in _knowledge_candidates if p and os.path.isdir(p)),
    _knowledge_candidates[-1],
)
BASE_DIR = os.path.join(KNOWLEDGE_DIR, "base")
POLICIES_DIR = os.path.join(KNOWLEDGE_DIR, "policies")
ACTIONS_CATALOG_DIR = os.path.join(KNOWLEDGE_DIR, "actions_catalog")
PROCESSED_DIR = os.path.join(KNOWLEDGE_DIR, "processed_data")
ENRICHED_INCIDENTS_DIR = os.path.join(PROCESSED_DIR, "enriched_incidents")
NORMALIZED_ALERTS_DIR = os.path.join(PROCESSED_DIR, "normalized_alerts")
INDICES_DIR = os.path.join(KNOWLEDGE_DIR, "indices")
CACHE_DIR = os.environ.get("CACHE_DIR", "/root/.cache/huggingface")

# PIPELINE & OLLAMA SETUP ----------------------------------------------------------------------------------------------------------------------------------------------------------     
WARMUP_ON = os.environ.get("WARMUP_ON", True)                                       # change it if you don't wanna warmup the pipeline
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://host.docker.internal:11434")
API_HOST = os.environ.get("API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("API_PORT", "8000"))

# RERANKER & EMBEDDER (CPU MODELS) ----------------------------------------------------------------------------------------------------------------------------------------------------------     
CHUNK_SIZE = 300
CHUNK_OVERLAP = 50
TOP_K = 5
RERANKER_MODEL = os.environ.get("RERANKER_MODEL", "cross-encoder/ms-marco-MiniLM-L2-v2")
RERANK_CANDIDATES = int(os.environ.get("RERANK_CANDIDATES", "10"))
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "intfloat/multilingual-e5-small")

# TRIAGER (GPU MODEL) ----------------------------------------------------------------------------------------------------------------------------------------------------------     
VALID_SEVERITIES = ("low", "medium", "high", "critical")
TRIAGE_MODEL = os.environ.get("TRIAGE_MODEL", "qwen3:0.6b")
TRIAGE_SYSTEM_PROMPT = (
    "You are the AI Triage agent in a cyber-response system. "
    "Given a raw security alert (from EDR/XDR/SIEM), together with "
    "relevant context retrieved from a cybersecurity knowledge base, "
    "normalize and triage the incident. "

    "Use the retrieved context as supporting evidence for the triage. "
    "The raw alert is the primary source of truth. "
    "Retrieved documents may describe similar incidents, known attack "
    "patterns, procedures, or historical cases, but they are not "
    "necessarily applicable to the current alert. "

    "Respond with ONLY a compact JSON object with these keys: "
    "\"summary\" (short one-line title), "
    "\"description\" (normalized details), "
    "\"category\" (best-guess MITRE ATT&CK tactic or attack type), "
    "\"severity\" (one of: low, medium, high, critical). "
    "No prose, no markdown, JSON only."
)

# PLANNER (GPU MODEL) ----------------------------------------------------------------------------------------------------------------------------------------------------------     
PLAN_MODEL = os.environ.get("PLAN_MODEL", "qwen3:4b-instruct")
ACTION_PLAN_CONTEXT_CHARS = int(os.environ.get("ACTION_PLAN_CONTEXT_CHARS", "4500"))
MAX_ACTIONS_PER_PLAN = 3
ACTION_PLAN_SYSTEM_PROMPT = (
    "You are a Response Agent."
    "Given an incident, context, and ACTION CATALOG, propose a remediation plan."
    "Rules:"
    "- Use ONLY action names EXACTLY as in the catalog. No inventing, no renaming, no paraphrasing."
    "- Respect required_fields in the catalog."
    f"- Max {MAX_ACTIONS_PER_PLAN} actions. If more are relevant, pick only the most important ones — by containment, severity, risk reduction, and evidentiary value."
    "- Output ONLY a compact JSON: {\"summary\": \"...\", \"actions\": [...]}"
    "- Each action has: \"action\", \"target\" (if needed), \"justification\""
    "- No prose. No markdown. Only valid JSON."
    "- This plan is validated before execution."
)

# DB ----------------------------------------------------------------------------------------------------------------------------------------------------------     
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "postgres")
POSTGRES_PORT = os.environ.get("POSTGRES_PORT", "5432")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "cyberresponse")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "cyberresponse")
POSTGRES_DB = os.environ.get("POSTGRES_DB", "incident_registry")
POSTGRES_OPERATIONAL_DB = POSTGRES_DB
POSTGRES_KNOWLEDGE_DB = os.environ.get("POSTGRES_KNOWLEDGE_DB", "knowledge")
COLLECTION_NAME = "cyber_response_kb"

# OPEN TELEMETRY ----------------------------------------------------------------------------------------------------------------------------------------------------------     
OTEL_SERVICE_NAME = os.environ.get("OTEL_SERVICE_NAME", "cyber-response-agents")
OTEL_EXPORTER_OTLP_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
OTEL_METRIC_EXPORT_INTERVAL_MS = int(os.environ.get("OTEL_METRIC_EXPORT_INTERVAL_MS", "5000"))
