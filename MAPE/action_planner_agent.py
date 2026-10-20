import json
import logging
import time
import os
from pathlib import PurePosixPath, PureWindowsPath
from ollama import Client
import config
from knowledge.registry import IncidentRegistry
from .logging_agent import logging_agent

logger = logging.getLogger(__name__)

class ActionPlannerAgent:

    def __init__(self, model: str = config.PLAN_MODEL, host: str = config.OLLAMA_HOST, registry: IncidentRegistry = None):
        self.model = model
        self.client = Client(host=host, timeout=config.OLLAMA_TIMEOUT_SECONDS)
        self.registry = registry or IncidentRegistry()
        self.actions_catalog = self._load_actions_catalog()
        self.actions_by_name = {
            action["action"]: action for action in self.actions_catalog["actions"]
        }
        self.allowed_actions = set(self.actions_by_name)

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
        if not isinstance(content, str) or not content.strip():
            raise ValueError("LLM returned empty action-plan content")

        content = content.strip()

        try:
            plan = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM returned invalid JSON: {exc}") from exc

        if not isinstance(plan, dict):
            raise ValueError("LLM action plan must be a JSON object")

        actions = plan.get("actions")

        if not isinstance(actions, list):
            raise ValueError(
                f"LLM action plan must contain an 'actions' list; received keys={list(plan.keys())}"
            )
        if not actions or len(actions) > config.MAX_ACTIONS_PER_PLAN:
            raise ValueError(f"LLM action plan must contain between 1 and {config.MAX_ACTIONS_PER_PLAN} actions")
        if not isinstance(plan.get("summary"), str) or not plan["summary"].strip():
            raise ValueError("LLM action plan must contain a non-empty summary")

        for index, item in enumerate(actions):
            if not isinstance(item, dict):
                raise ValueError(f"Action at index {index} must be a JSON object")

            action_name = item.get("action")

            if not isinstance(action_name, str) or not action_name.strip():
                raise ValueError(f"Action at index {index} has no valid action name")

            if action_name not in self.allowed_actions:
                raise ValueError(f"Unsupported action at index {index}: {action_name}")
            if not isinstance(item.get("justification"), str) or not item["justification"].strip():
                raise ValueError(f"Action at index {index} has no valid justification")
            missing_fields = [
                field
                for field in self.actions_by_name[action_name].get("required_fields", [])
                if not isinstance(item.get(field), str) or not item[field].strip()
            ]
            if missing_fields:
                raise ValueError(f"Action at index {index} ({action_name}) is missing required fields: {missing_fields}")
            if action_name == "isolate_host":
                target = item["target"]
                if PureWindowsPath(target).is_absolute() or PurePosixPath(target).is_absolute():
                    raise ValueError(f"Action at index {index} (isolate_host) has a file-path-like target; expected a hostname or endpoint identifier")

        return plan

    def _action_plan_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "actions": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": config.MAX_ACTIONS_PER_PLAN,
                    "items": {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": sorted(self.allowed_actions),
                            },
                            "target": {"type": "string"},
                            **{
                                field: {"type": "string"}
                                for action in self.actions_catalog["actions"]
                                for field in action.get("required_fields", [])
                                if field not in {"action", "target"}
                            },
                            "justification": {"type": "string"},
                            "description": {"type": "string"},
                        },
                        "required": ["action", "justification"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["summary", "actions"],
            "additionalProperties": False,
        }


    def propose_action_plan(self, incident: dict, context: str, incident_id: int = None) -> dict:

        start = time.perf_counter()
        fallback_used = False
        fallback_reason = None
        llm_ms = 0.0
        parsing_ms = 0.0
        response_content_length = None
        failure_stage = "llm_request"

        prompt_incident = {
            field: incident.get(field)
            for field in ("source", "external_id", "summary", "description", "severity", "raw_payload")
            if incident.get(field) is not None
        }

        question = json.dumps(prompt_incident, ensure_ascii=False, default=str)
        context = (context or "")[:config.ACTION_PLAN_CONTEXT_CHARS]

        catalog_for_llm = [
            {
                "action": action["action"],
                "description": action.get("description"),
                "required_fields": action.get("required_fields", []),
                "target_type": action.get("target_type"),
                "field_types": action.get("field_types", {}),
                "planning_guidance": action.get("planning_guidance"),
            }
            for action in self.actions_catalog["actions"]
        ]
        catalog_text = json.dumps(catalog_for_llm, ensure_ascii=False, indent=2)
        response_schema = self._action_plan_schema()

        messages = [
            {"role": "system", "content": config.ACTION_PLAN_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"ACTION CATALOG:\n{catalog_text}\n\n"
                    f"RETRIEVED CONTEXT (use only if directly relevant):\n{context}\n\n"
                    f"AUTHORITATIVE INCIDENT:\n{question}\n\n"
                    f"OUTPUT SCHEMA:\n"
                    f"{json.dumps(response_schema, ensure_ascii=False)}"
                ),
            }
        ]

        try:
            ## LLM inference
            llm_start = time.perf_counter()
            response = self.client.chat(
                model=self.model,
                messages=messages,
                format=response_schema,
                options={"temperature": 0, "num_predict": config.ACTION_PLAN_MAX_TOKENS},
                keep_alive=-1,
            )
            llm_ms = (time.perf_counter() - llm_start) * 1000

            failure_stage = "response_extraction"
            content = response["message"]["content"]
            response_content_length = len(content) if isinstance(content, str) else None

            # JSON parsing + validation
            failure_stage = "plan_validation"
            parsing_start = time.perf_counter()
            plan = self._parse_action_plan(content)
            parsing_ms = (time.perf_counter() - parsing_start) * 1000

        except Exception as exc:
            fallback_used = True
            if failure_stage == "llm_request":
                fallback_reason = "llm_request_error"
            elif failure_stage == "response_extraction":
                fallback_reason = "invalid_llm_response"
            elif isinstance(exc.__cause__, json.JSONDecodeError):
                fallback_reason = "invalid_json"
            else:
                fallback_reason = "invalid_action_plan"
            logger.exception(
                "Action plan fallback used: incident_id=%s model=%s stage=%s "
                "reason=%s error_type=%s response_chars=%s error=%s",
                incident_id,
                self.model,
                failure_stage,
                fallback_reason,
                type(exc).__name__,
                response_content_length,
                exc,
            )
            plan = {
                "summary": "LLM plan unavailable; escalate the alert for analyst review.",
                "actions": [{"action": "notify_analyst", "justification": "Automatic planning returned an invalid or incomplete response."}],
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

        logging_agent.record("action_planner_agent", "propose_action_plan", status="fallback" if fallback_used else "success", duration_ms=total_ms, incident_id=incident_id,
            details={
                "model": self.model,
                "llm_ms": llm_ms,
                "parsing_ms": parsing_ms,
                "context_length": len(context),
                "incident_length": len(question),
                "response_chars": response_content_length,
                "actions_count": len(plan.get("actions", [])),
                "fallback_used": fallback_used,
                "fallback_reason": fallback_reason
            },
        )
        
        return plan
