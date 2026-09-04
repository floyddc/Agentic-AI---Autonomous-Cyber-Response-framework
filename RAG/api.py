from typing import Any, Dict
from . import config
from .context_builder import build_context
from .response_agent import ResponseAgent

class RAGService:

    def __init__(self, model: str = config.CHAT_MODEL, host: str = config.OLLAMA_HOST):
        self.model = model
        self.host = host
        self.response_agent = ResponseAgent(model=model, host=host)

    def query(self, question: str, warmup: bool = True, incident_id: int = None) -> Dict[str, Any]:
        context = build_context(question)
        answer = self.response_agent.ask(question, incident_id=incident_id)

        return {
            "question": question,
            "context": context,
            "answer": answer,
            "model": self.model,
        }


def query_rag(question: str, model: str = config.CHAT_MODEL, host: str = config.OLLAMA_HOST, warmup: bool = True, incident_id: int = None) -> Dict[str, Any]:
    return RAGService(model=model, host=host).query(question, warmup=warmup, incident_id=incident_id)
