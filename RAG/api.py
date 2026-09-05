from typing import Any, Dict
from . import config
from .retrieve_agent import RetrieveAgent
from .response_agent import ResponseAgent

class RAGService:

    def __init__(self, model: str = config.CHAT_MODEL, host: str = config.OLLAMA_HOST):
        self.model = model
        self.host = host
        self.retrieve_agent = RetrieveAgent()
        self.response_agent = ResponseAgent(model=model, host=host)

    def query(self, question: str, warmup: bool = True, incident_id: int = None) -> Dict[str, Any]:
        context = self.retrieve_agent.retrieve(question, incident_id=incident_id).get("context")
        answer = self.response_agent.ask(question, context=context, incident_id=incident_id)

        return {
            "question": question,
            "context": context,
            "answer": answer,
            "model": self.model,
        }


def query_rag(question: str, model: str = config.CHAT_MODEL, host: str = config.OLLAMA_HOST, warmup: bool = True, incident_id: int = None) -> Dict[str, Any]:
    return RAGService(model=model, host=host).query(question, warmup=warmup, incident_id=incident_id)
