import json
import logging
from ollama import Client
from RAG import config
from RAG.context_builder import build_context
from knowledge.registry import IncidentRegistry
from .logging_agent import logging_agent

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are the Response Agent in a multi-agent cyber-response system. "
    "Use the retrieved context to reason on the incident and provide a grounded answer. "
    "If the context is insufficient or missing, say so explicitly."
)

ACTION_PLAN_SYSTEM_PROMPT = (
    "You are the Response Agent in a multi-agent cyber-response system. Given an incident "
    "and retrieved context (MITRE ATT&CK knowledge, past incidents, policies, action catalog), "
    "propose a remediation action plan. Respond with ONLY a compact JSON object with keys: "
    "\"summary\" (short rationale) and \"actions\" (a list of objects, each with "
    "\"action\" = one of the known action-catalog action names, \"target\" = the host/ip/account "
    "affected, and \"justification\"). No prose, no markdown, JSON only. "
    "This plan will be checked by a policy/validation layer before response."
)


class ActionPlannerAgent:

    def __init__(self, model: str = config.CHAT_MODEL, host: str = config.OLLAMA_HOST, registry: IncidentRegistry = None):
        self.model = model
        self.client = Client(host=host)
        self.registry = registry or IncidentRegistry()

    def ask(self, question: str, context: str = None, incident_id: int = None) -> str:
        with logging_agent.track("response_agent", "ask", incident_id=incident_id):
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

    def propose_action_plan(self, incident: dict, context: str, incident_id: int = None) -> dict:
        with logging_agent.track("response_agent", "propose_action_plan", incident_id=incident_id):
            
            prompt_incident = {
                field: incident.get(field)
                for field in ("source", "external_id", "summary", "description", "severity", "raw_payload")
                if incident.get(field) is not None
            }

            question = json.dumps(prompt_incident, ensure_ascii=False, default=str)

            context = (context or "")[:config.ACTION_PLAN_CONTEXT_CHARS]

            messages = [
                {"role": "system", "content": ACTION_PLAN_SYSTEM_PROMPT},
                {"role": "user", "content": f"Context:\n{context}\n\nIncident: {question}"},
            ]

            try:
                response = self.client.chat(model=self.model, messages=messages, format="json")
                plan = json.loads(response["message"]["content"])
                if not isinstance(plan, dict) or not isinstance(plan.get("actions"), list):
                    raise ValueError("LLM action plan is not a JSON object with an actions list")
            except Exception:
                logger.exception("Failed to obtain/parse action plan from LLM")
                plan = {
                    "summary": "LLM plan unavailable; escalate the alert for analyst review.",
                    "actions": [{"action": "notify_analyst", "justification": "Automatic planning failed."}],
                }

            try:
                self.registry.log_action(
                    incident_id,
                    agent="response_agent",
                    action="proposed_action_plan",
                    details=plan,
                )
            except Exception:
                logger.exception("Failed to log response_agent action to the incident registry")

            return plan
