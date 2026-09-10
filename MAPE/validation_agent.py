import glob
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
from RAG import config
from knowledge.registry import IncidentRegistry
from .logging_agent import logging_agent

logger = logging.getLogger(__name__)

DEFAULT_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _load_json_files(folder: str) -> List[Dict[str, Any]]:
    documents = []
    for path in glob.glob(os.path.join(folder, "*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                documents.append(json.load(f))
        except Exception:
            logger.exception("Failed to load JSON file %s", path)
    return documents


class ValidationAgent:

    def __init__(self, registry: Optional[IncidentRegistry] = None):
        self.registry = registry or IncidentRegistry()

    def _load_action_catalog(self) -> Dict[str, Dict[str, Any]]:
        catalog: Dict[str, Dict[str, Any]] = {}
        for doc in _load_json_files(config.ACTIONS_CATALOG_DIR):
            for entry in doc.get("actions", []):
                name = entry.get("action")
                if name:
                    catalog[name] = entry
        return catalog

    def _load_policies(self) -> Dict[str, Any]:
        merged: Dict[str, Any] = {
            "severity_order": DEFAULT_SEVERITY_ORDER,
            "require_human_approval_above_severity": "high",
            "blocked_actions": [],
            "max_actions_per_plan": 5,
        }
        for doc in _load_json_files(config.POLICIES_DIR):
            merged.update(doc)
        return merged

    def validate(self, incident_id: int, action_plan: Dict[str, Any], severity: Optional[str]) -> Tuple[bool, Dict[str, Any]]:
        with logging_agent.track("validation_agent", "validate", incident_id=incident_id):
            catalog = self._load_action_catalog()
            policies = self._load_policies()
            severity_order = policies.get("severity_order", DEFAULT_SEVERITY_ORDER)
            blocked = set(policies.get("blocked_actions", []))
            max_actions = policies.get("max_actions_per_plan", 5)
            approval_ceiling = policies.get("require_human_approval_above_severity", "high")

            actions = action_plan.get("actions", []) if isinstance(action_plan, dict) else []
            reasons: List[str] = []
            approved: List[Dict[str, Any]] = []

            if len(actions) > max_actions:
                reasons.append(f"plan exceeds max_actions_per_plan ({max_actions})")
                actions = actions[:max_actions]

            severity_rank = severity_order.index(severity) if severity in severity_order else len(severity_order) - 1
            ceiling_rank = severity_order.index(approval_ceiling) if approval_ceiling in severity_order else len(severity_order) - 1
            requires_human_approval = severity_rank >= ceiling_rank

            for action in actions:
                name = action.get("action") if isinstance(action, dict) else None
                if not name:
                    reasons.append(f"malformed action entry: {action!r}")
                    continue
                if name in blocked:
                    reasons.append(f"action '{name}' is blocked by policy")
                    continue
                catalog_entry = catalog.get(name)
                if catalog_entry is None:
                    reasons.append(f"action '{name}' is not present in the action catalog")
                    continue
                missing = [f for f in catalog_entry.get("required_fields", []) if not action.get(f)]
                if missing:
                    reasons.append(f"action '{name}' is missing required fields: {missing}")
                    continue
                action_ceiling = catalog_entry.get("max_auto_severity", approval_ceiling)
                action_ceiling_rank = severity_order.index(action_ceiling) if action_ceiling in severity_order else len(severity_order) - 1
                action["requires_human_approval"] = requires_human_approval or severity_rank >= action_ceiling_rank
                approved.append(action)

            is_valid = len(approved) > 0

            result = {
                "valid": is_valid,
                "approved_actions": approved,
                "reasons": reasons,
                "requires_human_approval": requires_human_approval,
            }

            self.registry.log_action(
                incident_id,
                agent="validation_agent",
                action="validated" if is_valid else "rejected",
                details=result,
            )
            return is_valid, result
