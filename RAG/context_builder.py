from . import config
from .retriever import retrieve, format_context
from typing import Dict, Optional, Any

class ContextBuilder:

    def __init__(self, retriever_func=retrieve, top_k: int = config.TOP_K, retrieval_metrics: Optional[Dict[str, Any]] = None):
        self.retriever_func = retriever_func
        self.top_k = top_k
        self.retrieval_metrics = retrieval_metrics

    def build(self, query: str) -> str:
        hits = self.retriever_func(query, top_k=self.top_k, metrics=self.retrieval_metrics)
        return format_context(hits)

def build_context(query: str, top_k: int = config.TOP_K, retrieval_metrics: Optional[Dict[str, Any]] = None) -> str:
    return ContextBuilder(top_k=top_k, retrieval_metrics=retrieval_metrics).build(query)
