import json
import logging
import time
import os
from typing import List
from pathlib import PurePosixPath, PureWindowsPath
from ollama import Client
import config
from knowledge.registry import IncidentRegistry
from .logging_agent import logging_agent
from .action_candidates import ActionCandidate, build_action_candidates
from .validation_agent import _raw_evidence_text, _valid_target

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


    def _parse_action_plan(self, content: str, incident: dict = None) -> dict:
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
            catalog_entry = self.actions_by_name[action_name]
            if not isinstance(item.get("justification"), str) or not item["justification"].strip():
                raise ValueError(f"Action at index {index} has no valid justification")
            missing_fields = [
                field
                for field in catalog_entry.get("required_fields", [])
                if not isinstance(item.get(field), str) or not item[field].strip()
            ]
            if missing_fields:
                raise ValueError(f"Action at index {index} ({action_name}) is missing required fields: {missing_fields}")

            allowed_fields = {
                "action",
                "justification",
                "description",
                *catalog_entry.get("required_fields", []),
                *catalog_entry.get("field_types", {}).keys(),
            }
            if catalog_entry.get("target_type"):
                allowed_fields.add("target")
            unsupported_fields = set(item) - allowed_fields
            if unsupported_fields:
                raise ValueError(
                    f"Action at index {index} ({action_name}) has unsupported "
                    f"fields: {sorted(unsupported_fields)}"
                )

            typed_fields = dict(catalog_entry.get("field_types", {}))
            if catalog_entry.get("target_type"):
                typed_fields["target"] = catalog_entry["target_type"]
            evidence_text = _raw_evidence_text(incident).casefold()
            for field, target_type in typed_fields.items():
                value = item.get(field)
                if value is None:
                    continue
                if not _valid_target(target_type, value):
                    raise ValueError(
                        f"Action at index {index} ({action_name}) has an invalid "
                        f"{field} for target type {target_type!r}"
                    )
                if value.strip().casefold() not in evidence_text:
                    raise ValueError(
                        f"Action at index {index} ({action_name}) uses {field} "
                        "that is not present in the raw alert"
                    )

            if action_name == "isolate_host":
                target = item["target"]
                if PureWindowsPath(target).is_absolute() or PurePosixPath(target).is_absolute():
                    raise ValueError(f"Action at index {index} (isolate_host) has a file-path-like target; expected a hostname or endpoint identifier")

        return plan

    def _candidate_selection_schema(self, candidates: List[ActionCandidate]) -> dict:
        candidate_ids = [candidate.candidate_id for candidate in candidates]
        return {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "selected_candidate_ids": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": config.MAX_ACTIONS_PER_PLAN,
                    "items": {"type": "string", "enum": candidate_ids},
                },
            },
            "required": ["summary", "selected_candidate_ids"],
            "additionalProperties": False,
        }

    def _parse_candidate_selection(
        self,
        content: str,
        candidates: List[ActionCandidate],
    ) -> dict:
        if not isinstance(content, str) or not content.strip():
            raise ValueError("LLM returned empty candidate-selection content")
        try:
            selection = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM returned invalid JSON: {exc}") from exc
        if not isinstance(selection, dict):
            raise ValueError("Candidate selection must be a JSON object")
        if set(selection) != {"summary", "selected_candidate_ids"}:
            raise ValueError(
                "Candidate selection must contain only 'summary' and "
                "'selected_candidate_ids'"
            )
        if not isinstance(selection.get("summary"), str) or not selection["summary"].strip():
            raise ValueError("Candidate selection must contain a non-empty summary")

        selected_ids = selection.get("selected_candidate_ids")
        if (
            not isinstance(selected_ids, list)
            or not selected_ids
            or len(selected_ids) > config.MAX_ACTIONS_PER_PLAN
        ):
            raise ValueError(
                f"Select between 1 and {config.MAX_ACTIONS_PER_PLAN} candidates"
            )
        if any(not isinstance(candidate_id, str) for candidate_id in selected_ids):
            raise ValueError("Selected candidate IDs must be strings")
        if len(selected_ids) != len(set(selected_ids)):
            raise ValueError("Selected candidate IDs must not contain duplicates")

        candidates_by_id = {
            candidate.candidate_id: candidate for candidate in candidates
        }
        unknown_ids = set(selected_ids) - set(candidates_by_id)
        if unknown_ids:
            raise ValueError(
                f"Unknown candidate IDs: {sorted(unknown_ids)}"
            )

        selected_actions = [
            candidates_by_id[candidate_id].action["action"]
            for candidate_id in selected_ids
        ]
        if "no_action" in selected_actions and len(selected_actions) != 1:
            raise ValueError("'no_action' cannot be combined with other candidates")
        return selection


    def propose_action_plan(self, incident: dict, context: str, incident_id: int = None) -> dict:

        start = time.perf_counter()
        fallback_used = False
        fallback_reason = None
        llm_ms = 0.0
        parsing_ms = 0.0
        response_content_length = None
        failure_stage = "llm_request"
        truncated = False

        prompt_incident = {
            field: incident.get(field)
            for field in ("source", "external_id", "summary", "description", "severity", "raw_payload")
            if incident.get(field) is not None
        }

        question = json.dumps(prompt_incident, ensure_ascii=False, default=str)
        context = (context or "")[:config.ACTION_PLAN_CONTEXT_CHARS]
        candidates = build_action_candidates(
            incident.get("raw_payload"),
            self.actions_catalog,
        )
        if not candidates:
            raise ValueError("No complete action candidates could be built")
        candidates_by_id = {
            candidate.candidate_id: candidate for candidate in candidates
        }
        candidates_text = json.dumps(
            [candidate.to_prompt_dict() for candidate in candidates],
            ensure_ascii=False,
            indent=2,
        )
        response_schema = self._candidate_selection_schema(candidates)

        messages = [
            {"role": "system", "content": config.ACTION_PLAN_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"COMPLETE ACTION CANDIDATES:\n{candidates_text}\n\n"
                    f"RETRIEVED CONTEXT (use only if directly relevant):\n{context}\n\n"
                    f"AUTHORITATIVE INCIDENT:\n{question}\n\n"
                    "Select candidate IDs only. Do not create actions or edit "
                    "candidate parameters.\n\n"
                    f"OUTPUT SCHEMA:\n"
                    f"{json.dumps(response_schema, ensure_ascii=False)}"
                ),
            }
        ]

        try:
            for attempt in range(2):
                failure_stage = "llm_request"
                llm_start = time.perf_counter()
                # think=False: reasoning tokens would otherwise eat the num_predict budget and leave the content empty
                response = self.client.chat(
                    model=self.model,
                    messages=messages,
                    format=response_schema,
                    think=False,
                    options={"temperature": 0, "num_predict": config.ACTION_PLAN_MAX_TOKENS},
                    keep_alive=-1,
                )
                llm_ms += (time.perf_counter() - llm_start) * 1000

                failure_stage = "response_extraction"
                truncated = response.get("done_reason") == "length"
                content = response["message"]["content"]
                response_content_length = len(content) if isinstance(content, str) else None

                failure_stage = "plan_validation"
                parsing_start = time.perf_counter()
                try:
                    selection = self._parse_candidate_selection(content, candidates)
                except ValueError as exc:
                    parsing_ms += (time.perf_counter() - parsing_start) * 1000
                    if attempt == 1:
                        raise
                    messages.extend([
                        {"role": "assistant", "content": content},
                        {
                            "role": "user",
                            "content": (
                                f"The candidate selection was rejected: {exc}. Return "
                                "a corrected JSON object selecting only IDs from the "
                                "complete action candidates. Do not create or edit "
                                "action parameters."
                            ),
                        },
                    ])
                    continue
                parsing_ms += (time.perf_counter() - parsing_start) * 1000
                break

            plan = {
                "summary": selection["summary"],
                "actions": [
                    dict(candidates_by_id[candidate_id].action)
                    for candidate_id in selection["selected_candidate_ids"]
                ],
            }
            failure_stage = "plan_validation"
            parsing_start = time.perf_counter()
            plan = self._parse_action_plan(
                json.dumps(plan, ensure_ascii=False),
                incident=incident,
            )
            parsing_ms += (time.perf_counter() - parsing_start) * 1000
        except Exception as exc:
            fallback_used = True
            if failure_stage == "llm_request":
                fallback_reason = "llm_request_error"
            elif truncated:
                fallback_reason = "llm_output_truncated"
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
                "candidate_count": len(candidates),
                "actions_count": len(plan.get("actions", [])),
                "fallback_used": fallback_used,
                "fallback_reason": fallback_reason
            },
        )
        
        return plan
