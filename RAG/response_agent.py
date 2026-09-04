import logging
from ollama import Client
from . import config
from .context_builder import build_context
from .incident_registry import IncidentRegistry

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are the Response Agent in a multi-agent cyber-response system. "
    "Use the retrieved context to reason on the incident and provide a grounded answer. "
    "If the context is insufficient or missing, say so explicitly."
)


class ResponseAgent:

    def __init__(self, model: str = config.CHAT_MODEL, host: str = config.OLLAMA_HOST, registry: IncidentRegistry = None):
        self.model = model
        self.client = Client(host=host)
        self.registry = registry or IncidentRegistry()

    def ask(self, question: str, context: str = None, incident_id: int = None) -> str:
        if context is None:
            context = build_context(question)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"},
        ]
        response = self.client.chat(model=self.model, messages=messages)
        answer = response["message"]["content"]

        try:
            self.registry.log_action(
                incident_id,
                agent="response_agent",
                action="generated_response",
                details={"question": question, "answer": answer},
            )
        except Exception:
            logger.exception("Failed to log response_agent action to the incident registry")

        return answer


def ask_response(question: str, model: str = config.CHAT_MODEL, incident_id: int = None) -> str:
    return ResponseAgent(model=model).ask(question, incident_id=incident_id)
