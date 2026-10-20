import json
import logging
import re
import time
from typing import Any, Dict, Optional
import argparse
import config
import logging as _logging
from RAG.context_builder import build_context
from knowledge.registry import IncidentRegistry
from .logging_agent import logging_agent

logger = logging.getLogger(__name__)

_QUERY_FIELDS = {
    "alert_title",
    "title",
    "alert",
    "detection_name",
    "rule_name",
    "alert_source",
    "source",
    "product",
    "vendor",
    "alert_description",
    "description",
    "message",
    "event_type",
    "severity",
    "alert_severity",
    "tactic",
    "technique",
    "host",
    "hostname",
    "endpoint",
    "agent",
    "device",
    "file",
    "file_name",
    "filename",
    "file_path",
    "path",
    "process",
    "process_name",
    "command_line",
    "user",
    "username",
}
_IOC_COLLECTION_FIELDS = {"alert_iocs", "iocs", "indicators"}
_NON_SEMANTIC_LABELS = {
    "agent", "host", "hostname", "endpoint", "device", "user", "username",
    "source", "severity", "alert_severity", "path", "file_path",
    "ioc", "ioc_type", "hash", "ip", "url", "email", "storyline", "site",
}
_LOG_FIELDS = {"generic_full_log", "windows_full_log", "full_log", "raw_log"}
_HASH_PATTERN = re.compile(r"\b(?:[a-f0-9]{128}|[a-f0-9]{64}|[a-f0-9]{40})\b", re.IGNORECASE)
_IP_PATTERN = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_LOG_VALUE_PATTERN = re.compile(
    r"(?:^|[.\s])(?P<label>file|path|process|image)\s*:\s*(?P<value>.*?)"
    r"(?=\s+(?:file|path|process|image|sha1|sha256|sha512|ip|storyline|site)\s*:|$)",
    re.IGNORECASE,
)


class RetrieveAgent:

    def __init__(self, top_k: int = config.TOP_K, registry: IncidentRegistry = None):
        self.top_k = top_k
        self.logger = logger
        self.registry = registry or IncidentRegistry()

    def _incident_to_query(self, incident: Any, semantic: bool = False) -> str:
        """Build the retrieval query. With semantic=True, identifiers that carry no
        technique meaning (hosts, hashes, IPs, URLs, emails, IOC values) are left out,
        since they only add noise to the embedding and the cross-encoder."""

        if isinstance(incident, str): return incident

        if not isinstance(incident, dict): return str(incident)

        parts = []
        seen = set()

        def add(label: str, value: Any, limit: int = 240) -> None:
            if isinstance(value, (dict, list)) or value is None:
                return
            if semantic and label.casefold() in _NON_SEMANTIC_LABELS:
                return
            text = " ".join(str(value).split()).rstrip(".,;")
            if not text:
                return
            text = text[:limit]
            entry = f"{label.casefold()}: {text}"
            if entry.casefold() not in seen:
                parts.append(entry)
                seen.add(entry.casefold())

        def visit(data: Any) -> None:
            if isinstance(data, dict):
                for key, value in data.items():
                    normalized_key = str(key).casefold()
                    if normalized_key in _QUERY_FIELDS:
                        add(str(key), value)
                    elif normalized_key in _IOC_COLLECTION_FIELDS and isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                add("ioc", item.get("ioc_value", item.get("value")))
                                add("ioc_type", item.get("ioc_type", item.get("type")))
                                add("ioc_description", item.get("ioc_description", item.get("description")))
                                add("ioc_tags", item.get("ioc_tags", item.get("tags")))
                            else:
                                add("ioc", item)
                    elif normalized_key in _LOG_FIELDS and isinstance(value, str):
                        for match in _LOG_VALUE_PATTERN.finditer(value):
                            add(match.group("label"), match.group("value"))
                        for pattern, label in (
                            (_HASH_PATTERN, "hash"),
                            (_IP_PATTERN, "ip"),
                            (_URL_PATTERN, "url"),
                            (_EMAIL_PATTERN, "email"),
                        ):
                            for match in pattern.findall(value):
                                add(label, match)
                    elif isinstance(value, (dict, list)):
                        visit(value)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, (dict, list)):
                        visit(item)

        visit(incident)
        query = "\n".join(parts)
        return query[:1600] if query else json.dumps(incident, ensure_ascii=False, default=str)


    def retrieve(
        self,
        incident_or_query: Any,
        incident_id: int = None,
        customer_id: Optional[int] = None,
    ) -> Dict[str, Any]:

        q = self._incident_to_query(incident_or_query, semantic=True)
        if isinstance(incident_or_query, dict):
            incident_customer_id = incident_or_query.get("customer_id")
            if customer_id is not None and customer_id != incident_customer_id:
                raise ValueError("customer_id does not match the incident tenant")
            customer_id = incident_customer_id

        start = time.perf_counter()
        retrieval_metrics = {}
        context = ""

        try:
            if isinstance(customer_id, bool) or not isinstance(customer_id, int) or customer_id <= 0:
                raise ValueError("customer_id must be a positive integer for tenant-scoped retrieval")
            context = build_context(q, customer_id=customer_id, top_k=self.top_k, retrieval_metrics=retrieval_metrics,)
            total_duration_ms = (time.perf_counter() - start) * 1000

            try:
                self.registry.log_action(
                    incident_id,
                    agent="retrieve_agent",
                    action="retrieved_context",
                    details={"query": q, "context_length": len(context) if context else 0},
                )
            except Exception:
                self.logger.exception("Failed to log retrieve_agent action to the incident registry")

            logging_agent.record(
                "retrieve_agent", "retrieve", status="success", duration_ms=total_duration_ms, incident_id=incident_id,
                details={
                    "collection_ms": retrieval_metrics.get("collection_ms", 0.0),
                    "embedding_ms": retrieval_metrics.get("embedding_ms", 0.0),
                    "search_ms": retrieval_metrics.get("search_ms", 0.0),
                    "hits_ms": retrieval_metrics.get("hits_ms", 0.0),
                    "rerank_ms": retrieval_metrics.get("rerank_ms", 0.0),
                    "retrieval_total_ms": retrieval_metrics.get("total_ms", 0.0),
                    "candidate_k": retrieval_metrics.get("candidate_k", 0),
                    "result_count": retrieval_metrics.get("result_count", 0),
                    "context_length": (len(context) if context else 0),
                    "candidate_results": retrieval_metrics.get("candidate_results", []),
                    "reranked_results": retrieval_metrics.get("reranked_results", []),
                    "selected_results": retrieval_metrics.get("selected_results", []),
                },
            )
            return {"query": q, "context": context}
        
        except Exception as exc:
            total_duration_ms = (time.perf_counter() - start) * 1000
            self.logger.exception("Retrieve failed")
            
            logging_agent.record(
                            "retrieve_agent", "retrieve", status="error", duration_ms=total_duration_ms, incident_id=incident_id,
                            details={
                                "error": str(exc),
                                "collection_ms": retrieval_metrics.get("collection_ms", 0.0),
                                "embedding_ms": retrieval_metrics.get("embedding_ms", 0.0),
                                "search_ms": retrieval_metrics.get("search_ms", 0.0),
                                "hits_ms": retrieval_metrics.get("hits_ms", 0.0),
                                "rerank_ms": retrieval_metrics.get("rerank_ms", 0.0),
                                "retrieval_total_ms": retrieval_metrics.get("total_ms", 0.0),
                                "candidate_k": retrieval_metrics.get("candidate_k", 0),
                                "result_count": retrieval_metrics.get("result_count", 0),
                                "context_length": (len(context) if context else 0),
                                "candidate_results": retrieval_metrics.get("candidate_results", []),
                                "reranked_results": retrieval_metrics.get("reranked_results", []),
                            },
                        )
            return {"query": q, "error": str(exc)}


if __name__ == "__main__":

    _logging.basicConfig(level=_logging.INFO)
    for lib in ("httpx", "sentence_transformers", "transformers", "urllib3", "chromadb"):
        _logging.getLogger(lib).setLevel(_logging.WARNING)

    agent = RetrieveAgent()
    parser = argparse.ArgumentParser()
    parser.add_argument("--customer-id", required=True, type=int)
    parser.add_argument("query", nargs="*")
    args = parser.parse_args()
    q = " ".join(args.query) or input("Incident or query: ")
    out = agent.retrieve(q, customer_id=args.customer_id)
    print(json.dumps(out, indent=2, ensure_ascii=False))
