import glob
import ipaddress
import json
import logging
import os
import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit
import config
from knowledge.registry import IncidentRegistry
from .logging_agent import logging_agent

logger = logging.getLogger(__name__)

DEFAULT_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _load_json_files(folder: str) -> List[Dict[str, Any]]:
    documents = []
    for path in glob.glob(os.path.join(folder, "*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                document = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.exception("Failed to load JSON file %s", path)
            raise ValueError(f"Failed to load JSON file {path}") from exc
        if not isinstance(document, dict):
            raise ValueError(f"JSON file {path} must contain an object")
        documents.append(document)
    return documents


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and "\x00" not in value


def _is_absolute_file_path(value: str) -> bool:
    return PureWindowsPath(value).is_absolute() or PurePosixPath(value).is_absolute()


def _is_domain(value: str) -> bool:
    if not value or len(value) > 253 or any(char in value for char in "/:@?#"):
        return False
    try:
        ascii_domain = value.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = ascii_domain.split(".")
    return bool(labels) and all(
        len(label) <= 63
        and re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?", label)
        for label in labels
    )


def _is_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        try:
            ipaddress.ip_address(hostname)
            valid_host = True
        except ValueError:
            valid_host = _is_domain(hostname)
        return (
            not any(char.isspace() for char in value)
            and parsed.scheme in ("http", "https")
            and valid_host
            and parsed.username is None
            and parsed.password is None
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except ValueError:
        return False


def _is_network_indicator(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    if _is_url(value) or _is_domain(value):
        return True
    port_match = re.fullmatch(r"(?:tcp|udp|port)[:/](\d{1,5})", value.lower())
    return bool(port_match and 1 <= int(port_match.group(1)) <= 65535)


def _valid_target(target_type: str, value: Any) -> bool:
    if not _non_empty_string(value):
        return False
    value = value.strip()
    if target_type == "endpoint_id":
        return (
            not _is_absolute_file_path(value)
            and "/" not in value
            and "\\" not in value
        )
    if target_type == "ip_address":
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    if target_type == "network_indicator":
        return _is_network_indicator(value)
    if target_type == "domain":
        try:
            ipaddress.ip_address(value)
            return False
        except ValueError:
            return _is_domain(value)
    if target_type == "url":
        return _is_url(value)
    if target_type == "file_hash":
        return bool(re.fullmatch(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value))
    if target_type == "file_reference":
        is_hash = bool(re.fullmatch(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value))
        is_filename = "/" not in value and "\\" not in value
        return is_hash or _is_absolute_file_path(value) or is_filename
    if target_type == "file_path":
        return _is_absolute_file_path(value)
    if target_type in {
        "account_id",
        "process_reference",
        "persistence_reference",
        "traffic_scope",
    }:
        return len(value) <= 512
    return False


def _raw_evidence_text(incident: Optional[Dict[str, Any]]) -> str:
    if not isinstance(incident, dict):
        return ""
    raw_payload = incident.get("raw_payload")
    if isinstance(raw_payload, str):
        try:
            raw_payload = json.loads(raw_payload)
        except json.JSONDecodeError:
            return raw_payload

    values: List[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for nested in value.values():
                collect(nested)
        elif isinstance(value, list):
            for nested in value:
                collect(nested)
        elif isinstance(value, str):
            values.append(value)

    collect(raw_payload)
    return "\n".join(values)


class ValidationAgent:

    def __init__(self, registry: Optional[IncidentRegistry] = None):
        self.registry = registry or IncidentRegistry()

    def _load_action_catalog(self) -> Dict[str, Dict[str, Any]]:
        catalog: Dict[str, Dict[str, Any]] = {}
        for doc in _load_json_files(config.ACTIONS_CATALOG_DIR):
            entries = doc.get("actions")
            if not isinstance(entries, list):
                raise ValueError("Action catalog must contain an 'actions' list")
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError("Action catalog entries must be JSON objects")
                name = entry.get("action")
                if not isinstance(name, str) or not name.strip():
                    raise ValueError("Every catalog action must have a non-empty name")
                if name in catalog:
                    raise ValueError(f"Duplicate action in catalog: {name}")
                required_fields = entry.get("required_fields")
                field_types = entry.get("field_types", {})
                if (
                    not isinstance(required_fields, list)
                    or any(not isinstance(field, str) for field in required_fields)
                    or not isinstance(field_types, dict)
                ):
                    raise ValueError(f"Action {name!r} has invalid field metadata")
                if (
                    len(required_fields) != len(set(required_fields))
                    or any(
                        not isinstance(field, str) or not isinstance(field_type, str)
                        for field, field_type in field_types.items()
                    )
                ):
                    raise ValueError(f"Action {name!r} has invalid field type metadata")
                target_type = entry.get("target_type")
                if "target" in required_fields and not isinstance(target_type, str):
                    raise ValueError(f"Action {name!r} requires a target_type")
                if any(
                    field != "target" and field not in field_types
                    for field in required_fields
                ):
                    raise ValueError(f"Action {name!r} is missing field_types metadata")
                target_types = set(field_types.values())
                if target_type:
                    target_types.add(target_type)
                unknown_target_types = target_types - {
                    "endpoint_id",
                    "ip_address",
                    "network_indicator",
                    "domain",
                    "url",
                    "file_hash",
                    "file_reference",
                    "file_path",
                    "account_id",
                    "process_reference",
                    "persistence_reference",
                    "traffic_scope",
                }
                if unknown_target_types:
                    raise ValueError(
                        f"Action {name!r} has unsupported target types: "
                        f"{sorted(unknown_target_types)}"
                    )
                catalog[name] = entry
        if not catalog:
            raise ValueError("No valid actions found in the action catalog")
        return catalog

    def _load_policies(self) -> Dict[str, Any]:
        documents = _load_json_files(config.POLICIES_DIR)

        if not documents:
            raise ValueError("No policy file found")

        return documents[0]


    def validate(
        self,
        incident_id: int,
        action_plan: Dict[str, Any],
        severity: Optional[str],
        incident: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        with logging_agent.track("validation_agent", "validate", incident_id=incident_id):
            catalog = self._load_action_catalog()
            policies = self._load_policies()
            incident = incident if incident is not None else self.registry.get_incident(incident_id)
            evidence_text = _raw_evidence_text(incident).casefold()
            severity_order = policies.get("severity_order", DEFAULT_SEVERITY_ORDER)
            blocked_actions = policies.get("blocked_actions", [])
            max_actions = policies.get("max_actions_per_plan", 5)
            approval_ceiling = policies.get("require_human_approval_above_severity", "high")

            reasons: List[str] = []
            approved: List[Dict[str, Any]] = []
            if not isinstance(severity_order, list) or not severity_order:
                raise ValueError("Policy severity_order must be a non-empty list")
            if any(not isinstance(level, str) for level in severity_order) or len(
                severity_order
            ) != len(set(severity_order)):
                raise ValueError("Policy severity_order must contain unique strings")
            if severity not in severity_order:
                reasons.append(f"invalid incident severity: {severity!r}")
            if approval_ceiling not in severity_order:
                raise ValueError("Policy human-approval severity is not in severity_order")
            if isinstance(max_actions, bool) or not isinstance(max_actions, int) or max_actions < 1:
                raise ValueError("Policy max_actions_per_plan must be a positive integer")
            if (
                not isinstance(blocked_actions, list)
                or any(not isinstance(name, str) for name in blocked_actions)
            ):
                raise ValueError("Policy blocked_actions must be a list of action names")
            blocked = set(blocked_actions)

            actions = action_plan.get("actions") if isinstance(action_plan, dict) else None
            if (
                not isinstance(action_plan, dict)
                or not _non_empty_string(action_plan.get("summary"))
            ):
                reasons.append("action plan must contain a non-empty summary")
            if not isinstance(actions, list) or not actions:
                reasons.append("action plan must contain a non-empty actions list")
                actions = []
            elif len(actions) > max_actions:
                reasons.append(f"plan exceeds max_actions_per_plan ({max_actions})")

            severity_rank = severity_order.index(severity) if severity in severity_order else -1
            ceiling_rank = severity_order.index(approval_ceiling)
            requires_human_approval = severity_rank < 0 or severity_rank >= ceiling_rank
            seen_actions = set()

            for action_index, action in enumerate(actions):
                name = action.get("action") if isinstance(action, dict) else None
                if not isinstance(name, str) or not name.strip():
                    reasons.append(f"malformed action entry: {action!r}")
                    continue
                if name in blocked:
                    reasons.append(f"action '{name}' is blocked by policy")
                    continue
                catalog_entry = catalog.get(name)
                if catalog_entry is None:
                    reasons.append(f"action '{name}' is not present in the action catalog")
                    continue
                fields = dict(action)
                required_fields = catalog_entry["required_fields"]
                missing = [
                    field
                    for field in required_fields
                    if not _non_empty_string(fields.get(field))
                ]
                if missing:
                    reasons.append(
                        f"action '{name}' at index {action_index} is missing or has "
                        f"invalid required fields: {missing}"
                    )
                    continue
                if not _non_empty_string(fields.get("justification")):
                    reasons.append(
                        f"action '{name}' at index {action_index} has no valid justification"
                    )
                    continue
                if not catalog_entry.get("target_type") and "target" in fields:
                    if not _non_empty_string(fields["target"]):
                        fields.pop("target")
                    else:
                        reasons.append(f"action '{name}' does not accept a target")
                        continue
                allowed_fields = {
                    "action",
                    "description",
                    "justification",
                    "requires_human_approval",
                    *required_fields,
                    *catalog_entry.get("field_types", {}).keys(),
                }
                if catalog_entry.get("target_type"):
                    allowed_fields.add("target")
                unexpected_fields = set(fields) - allowed_fields
                if unexpected_fields:
                    reasons.append(
                        f"action '{name}' at index {action_index} has unsupported "
                        f"fields: {sorted(unexpected_fields)}"
                    )
                    continue
                if catalog_entry.get("target_type"):
                    if not _valid_target(catalog_entry["target_type"], fields["target"]):
                        reasons.append(
                            f"action '{name}' at index {action_index} has an invalid "
                            f"target for type {catalog_entry['target_type']!r}"
                        )
                        continue

                field_types = catalog_entry.get("field_types", {})
                invalid_typed_fields = [
                    field
                    for field, field_type in field_types.items()
                    if field in fields and not _valid_target(field_type, fields[field])
                ]
                target_types = dict(field_types)
                if catalog_entry.get("target_type"):
                    target_types["target"] = catalog_entry["target_type"]
                unsupported_evidence_fields = [
                    field
                    for field in target_types
                    if field in fields
                    and _non_empty_string(fields[field])
                    and fields[field].strip().casefold() not in evidence_text
                ]
                if invalid_typed_fields:
                    reasons.append(
                        f"action '{name}' at index {action_index} has invalid fields: "
                        f"{invalid_typed_fields}"
                    )
                    continue
                if unsupported_evidence_fields:
                    reasons.append(
                        f"action '{name}' at index {action_index} uses fields not "
                        f"present in the raw alert: {unsupported_evidence_fields}"
                    )
                    continue

                duplicate_key = (name, tuple(sorted(
                    (field, str(fields.get(field, "")))
                    for field in required_fields
                )))
                if duplicate_key in seen_actions:
                    reasons.append(f"duplicate action and target: {name}")
                    continue
                seen_actions.add(duplicate_key)

                if name == "no_action" and len(actions) != 1:
                    reasons.append("'no_action' cannot be combined with other actions")
                    continue

                action_ceiling = catalog_entry.get("max_auto_severity", approval_ceiling)
                if action_ceiling not in severity_order:
                    raise ValueError(f"Action {name!r} has an invalid max_auto_severity")
                action_ceiling_rank = severity_order.index(action_ceiling)
                fields["requires_human_approval"] = (
                    requires_human_approval or severity_rank >= action_ceiling_rank
                )
                approved.append(fields)

            is_valid = not reasons and len(approved) == len(actions)
            if not is_valid:
                approved = []
            requires_human_approval = requires_human_approval or any(
                action["requires_human_approval"] for action in approved
            )

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
