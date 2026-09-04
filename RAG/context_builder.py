from . import config
from .retriever import retrieve, format_context

class ContextBuilder:

    def __init__(self, retriever_func=retrieve, top_k: int = config.TOP_K):
        self.retriever_func = retriever_func
        self.top_k = top_k

    def build(self, query: str) -> str:
        hits = self.retriever_func(query, top_k=self.top_k)
        return format_context(hits)

def build_context(query: str, top_k: int = config.TOP_K) -> str:
    return ContextBuilder(top_k=top_k).build(query)
