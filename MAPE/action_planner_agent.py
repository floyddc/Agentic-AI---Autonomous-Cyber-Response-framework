import json
import logging
import time
import glob
import os
from typing import Any, Dict, List
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
    "You are the Response Agent in a multi-agent cyber-response system. "
    "Given an incident, retrieved context, and the provided ACTION CATALOG, "
    "propose a remediation action plan. "
    "You MUST use ONLY action names that appear exactly in the ACTION CATALOG. "
    "NEVER invent, rename, or paraphrase an action. "
    "Respect the required_fields defined by the catalog. "
    "Respond with ONLY a compact JSON object with keys: "
    "\"summary\" and \"actions\". "
    "Each action must contain \"action\", \"target\" when required, "
    "and \"justification\". "
    "No prose, no markdown, JSON only. "
    "This plan will be checked by a policy/validation layer before execution."
)

class ActionPlannerAgent:

    def __init__(self, model: str = config.PLAN_MODEL, host: str = config.OLLAMA_HOST, registry: IncidentRegistry = None):
        self.model = model
        self.client = Client(host=host)
        self.registry = registry or IncidentRegistry()
        self.actions_catalog = self._load_actions_catalog()
        self.allowed_actions = {
            action["action"]
            for action in self.actions_catalog["actions"]
        }

    def _load_actions_catalog(self) -> dict:
        catalog_path = os.path.join(
            config.ACTIONS_CATALOG_DIR,
            "actions_catalog.json"
        )

        with open(catalog_path, "r", encoding="utf-8") as f:
            catalog = json.load(f)

        if not isinstance(catalog, dict):
            raise ValueError("Invalid actions catalog")

        if not isinstance(catalog.get("actions"), list):
            raise ValueError("actions_catalog.json must contain an 'actions' list")

        return catalog


    def _parse_action_plan(self, content: str) -> dict:
        content = content.strip()

        try:
            plan = json.loads(content)

        except json.JSONDecodeError:
            decoder = json.JSONDecoder()
            plan, _ = decoder.raw_decode(content)

        if not isinstance(plan, dict):
            raise ValueError("LLM action plan is not a JSON object")

        if not isinstance(plan.get("actions"), list):
            raise ValueError("LLM action plan does not contain an actions list")

        return plan

    def ask(self, question: str, context: str = None, incident_id: int = None) -> str:
        with logging_agent.track("action_planner_agent", "ask", incident_id=incident_id):
            if context is None:
                context = build_context(question)
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"},
            ]

            response = self.client.chat(
                model=self.model,
                messages=messages,
                format="json",
                keep_alive=-1,  
                options={
                    "temperature": 0.0,      
                    "num_predict": 256
                }
            )            
            answer = response["message"]["content"]

            try:
                self.registry.log_action(
                    incident_id,
                    agent="action_planner_agent",
                    action="generated_response",
                    details={"question": question, "answer": answer},
                )
            except Exception:
                logger.exception("Failed to log action_planner_agent action to the incident registry")

            return answer

    def propose_action_plan(self, incident: dict, context: str, incident_id: int = None) -> dict:

        start = time.perf_counter()
        fallback_used = False
        fallback_reason = None
        llm_ms = 0.0
        parsing_ms = 0.0

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
            ## LLM inference
            llm_start = time.perf_counter()
            response = self.client.chat(model=self.model, messages=messages, format="json", keep_alive=-1)
            llm_ms = (time.perf_counter() - llm_start) * 1000

            # JSON parsing + validation
            parsing_start = time.perf_counter()
            content = response["message"]["content"]
            plan = self._parse_action_plan(content)
            parsing_ms = (time.perf_counter() - parsing_start) * 1000

        except Exception:
            fallback_used = True
            fallback_reason = "json_parse_error"
            logger.exception("Failed to obtain/parse action plan from LLM")
            plan = {
                "summary": "LLM plan unavailable; escalate the alert for analyst review.",
                "actions": [{"action": "notify_analyst", "justification": "Automatic planning failed because the LLM returned invalid JSON."}],
            }

        # total execution time
        total_ms = (time.perf_counter() - start) * 1000

        try:
            self.registry.log_action(
                incident_id,
                agent="action_planner_agent",
                action="proposed_action_plan",
                details=plan,
            )
        except Exception:
            logger.exception("Failed to log action_planner_agent action to the incident registry")

        logging_agent.record("action_planner_agent", "propose_action_plan", status="success", duration_ms=total_ms, incident_id=incident_id,
            details={
                "model": self.model,
                "llm_ms": llm_ms,
                "parsing_ms": parsing_ms,
                "context_length": len(context),
                "incident_length": len(question),
                "actions_count": len(plan.get("actions", [])),
                "fallback_used": fallback_used,
                "fallback_reason": fallback_reason
            },
        )
        
        return plan
