import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple
from .validation_agent import _raw_evidence_text, _valid_target


_SECURITY_TAGS = {"c2", "malicious", "malware", "phishing", "suspicious"}
_FILE_TAGS = {"attachment", "document", "file", "macro"}
_HASH_PATTERN = re.compile(r"(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})")


@dataclass(frozen=True)
class AlertEvidence:
    kind: str
    value: str
    source: str
    verified: bool = True
    tags: frozenset = frozenset()


@dataclass(frozen=True)
class ActionCandidate:
    candidate_id: str
    action: Dict[str, str]
    description: str
    evidence: Tuple[AlertEvidence, ...]

    def to_prompt_dict(self) -> dict:
        return {
            "id": self.candidate_id,
            "action": self.action["action"],
            "description": self.description,
            "parameters": {
                key: value
                for key, value in self.action.items()
                if key not in {"action", "justification"}
            },
            "evidence": [
                {
                    "type": evidence.kind,
                    "source": evidence.source,
                    "verified": evidence.verified,
                    "tags": sorted(evidence.tags),
                }
                for evidence in self.evidence
            ],
        }


@dataclass(frozen=True)
class NormalizedAlert:
    source_family: str
    evidence: Tuple[AlertEvidence, ...]
    malicious_detection: bool


def _source_family(raw_payload: Dict[str, Any]) -> str:
    source = str(
        raw_payload.get("alert_source")
        or raw_payload.get("_source")
        or raw_payload.get("source")
        or ""
    ).casefold()
    if "sentinelone" in source or source.strip() in {"s1", "edr"}:
        return "endpoint_edr"
    if (
        "defender" in source and ("office" in source or "o365" in source)
    ) or source.strip() == "mdo":
        return "email_defender"
    if (
        "defender" in source
        and ("endpoint" in source or "atp" in source or "mdatp" in source)
    ) or source.strip() == "mde":
        return "endpoint_edr"
    return "unknown"


def _walk_dicts(value: Any, path: str = "") -> Iterable[Tuple[str, Dict[str, Any]]]:
    if isinstance(value, dict):
        yield path, value
        for key, nested in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from _walk_dicts(nested, child_path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _walk_dicts(nested, f"{path}[{index}]")


def _split_tags(value: Any) -> frozenset:
    if isinstance(value, list):
        value = ",".join(str(tag) for tag in value)
    if not isinstance(value, str):
        return frozenset()
    return frozenset(
        tag.strip().casefold()
        for tag in re.split(r"[,;]", value)
        if tag.strip()
    )


def _classify_ioc(value: str, tags: frozenset) -> Optional[str]:
    if _valid_target("url", value):
        return "url"
    if _valid_target("ip_address", value):
        return "ip_address"
    if _valid_target("file_hash", value):
        return "file_hash"
    if "domain" in tags and _valid_target("domain", value):
        return "domain"
    if "email" in tags and "@" in value:
        return "email"
    if tags.intersection(_FILE_TAGS) and _valid_target("file_reference", value):
        return "file_reference"
    return None


def normalize_alert(raw_payload: Any) -> NormalizedAlert:
    if isinstance(raw_payload, str):
        try:
            raw_payload = json.loads(raw_payload)
        except json.JSONDecodeError:
            raw_payload = {}
    if not isinstance(raw_payload, dict):
        raw_payload = {}

    family = _source_family(raw_payload)
    evidence: List[AlertEvidence] = []
    seen = set()

    def add(
        kind: str,
        value: Any,
        source: str,
        *,
        verified: bool = True,
        tags: Iterable[str] = (),
        target_type: Optional[str] = None,
    ) -> None:
        if not isinstance(value, str):
            return
        value = value.strip()
        if not value:
            return
        if target_type and not _valid_target(target_type, value):
            return
        normalized_tags = frozenset(tags)
        key = (kind, value.casefold(), source, verified, normalized_tags)
        if key in seen:
            return
        seen.add(key)
        evidence.append(AlertEvidence(kind, value, source, verified, normalized_tags))

    for path, item in _walk_dicts(raw_payload):
        for raw_key, value in item.items():
            key = str(raw_key).casefold()
            source = f"{path}.{raw_key}" if path else str(raw_key)
            if key in {
                "file_path", "filepath", "path", "filelocation", "filename",
            }:
                add("file_reference", value, source, target_type="file_reference")
            elif key in {
                "sha1", "sha256", "md5", "file_hash", "filehash", "hash",
            }:
                add("file_hash", value, source, target_type="file_hash")
            elif key in {
                "ip", "ip_address", "ipaddress", "remote_ip", "remoteip",
                "source_ip", "sourceip", "destination_ip", "destinationip",
            }:
                add("ip_address", value, source, target_type="ip_address")
            elif key in {"url", "uri", "remote_url", "remoteurl"}:
                add("url", value, source, target_type="url")
            elif key == "domain":
                add("domain", value, source, target_type="domain")
            elif key in {"endpoint_id", "endpointid"}:
                add("endpoint_id", value, source, target_type="endpoint_id")
            elif key in {
                "host_id", "hostid", "device_id", "deviceid",
                "machine_id", "machineid",
            } and family == "endpoint_edr":
                add("endpoint_id", value, source, target_type="endpoint_id")
            elif key in {
                "host", "hostname", "device_name", "devicename",
            } and family == "endpoint_edr":
                add("endpoint_id", value, source, target_type="endpoint_id")
            elif key == "agent":
                add(
                    "endpoint_id",
                    value,
                    source,
                    verified=False,
                    target_type="endpoint_id",
                )

            if key in {"alert_iocs", "iocs", "indicators"} and isinstance(value, list):
                for index, ioc in enumerate(value):
                    if not isinstance(ioc, dict):
                        continue
                    ioc_value = ioc.get("ioc_value", ioc.get("value"))
                    if not isinstance(ioc_value, str):
                        continue
                    tags = _split_tags(ioc.get("ioc_tags", ioc.get("tags")))
                    ioc_type = _classify_ioc(ioc_value.strip(), tags)
                    if ioc_type:
                        target_type = {
                            "url": "url",
                            "ip_address": "ip_address",
                            "file_hash": "file_hash",
                            "domain": "domain",
                            "file_reference": "file_reference",
                        }.get(ioc_type)
                        add(
                            ioc_type,
                            ioc_value,
                            f"{source}[{index}].ioc_value",
                            tags=tags,
                            target_type=target_type,
                        )

    if family == "endpoint_edr":
        for path, item in _walk_dicts(raw_payload):
            log = item.get("generic_full_log")
            if not isinstance(log, str):
                continue
            path_match = re.search(
                r"\bPath:\s*(.+?)(?=\s+(?:SHA1|SHA256|MD5|IP):)",
                log,
                flags=re.IGNORECASE,
            )
            if path_match:
                file_path = path_match.group(1).strip().rstrip(".")
                add(
                    "file_reference",
                    file_path,
                    f"{path}.generic_full_log:Path",
                    target_type="file_reference",
                )
            for label, kind, target_type in (
                ("SHA1", "file_hash", "file_hash"),
                ("SHA256", "file_hash", "file_hash"),
                ("MD5", "file_hash", "file_hash"),
            ):
                match = re.search(
                    rf"\b{label}:\s*({_HASH_PATTERN.pattern})(?![0-9a-fA-F])",
                    log,
                    flags=re.IGNORECASE,
                )
                if match:
                    add(
                        kind,
                        match.group(1),
                        f"{path}.generic_full_log:{label}",
                        target_type=target_type,
                    )
            ip_match = re.search(r"\bIP:\s*([^\s,;]+)", log, flags=re.IGNORECASE)
            if ip_match:
                ip_value = ip_match.group(1).rstrip(".)]")
                add(
                    "ip_address",
                    ip_value,
                    f"{path}.generic_full_log:IP",
                    target_type="ip_address",
                )

    raw_text = _raw_evidence_text({"raw_payload": raw_payload}).casefold()
    explicitly_negated = bool(
        re.search(
            r"\b(?:benign|false positive|non[- ]?malicious|not malicious|"
            r"no malware|malware not detected)\b",
            raw_text,
        )
    )
    malicious_detection = (
        not explicitly_negated
        and ("malicious" in raw_text or "malware" in raw_text)
    )
    return NormalizedAlert(family, tuple(evidence), malicious_detection)


def build_action_candidates(
    raw_payload: Any,
    actions_catalog: Dict[str, Any],
) -> List[ActionCandidate]:
    normalized = normalize_alert(raw_payload)
    catalog = {
        action["action"]: action
        for action in actions_catalog.get("actions", [])
        if isinstance(action, dict) and isinstance(action.get("action"), str)
    }
    candidates: List[ActionCandidate] = []
    seen_actions = set()
    raw_evidence_text = _raw_evidence_text({"raw_payload": raw_payload}).casefold()

    def add_candidate(
        action_name: str,
        values: Dict[str, AlertEvidence],
        justification: str,
    ) -> None:
        entry = catalog.get(action_name)
        if entry is None:
            return
        typed_fields = dict(entry.get("field_types", {}))
        if entry.get("target_type"):
            typed_fields["target"] = entry["target_type"]
        required_fields = entry.get("required_fields", [])
        if any(field not in values for field in required_fields):
            return
        if any(field not in typed_fields for field in required_fields):
            return

        action: Dict[str, str] = {
            "action": action_name,
            "justification": justification,
        }
        selected_evidence = []
        for field in required_fields:
            fact = values[field]
            if not fact.verified:
                return
            target_type = typed_fields[field]
            if not _valid_target(target_type, fact.value):
                return
            if fact.value.casefold() not in raw_evidence_text:
                return
            action[field] = fact.value
            selected_evidence.append(fact)

        duplicate_key = (
            action_name,
            tuple((field, action[field]) for field in required_fields),
        )
        if duplicate_key in seen_actions:
            return
        seen_actions.add(duplicate_key)
        candidate_id = f"C{len(candidates) + 1:02d}"
        candidates.append(
            ActionCandidate(
                candidate_id=candidate_id,
                action=action,
                description=entry.get("description", action_name),
                evidence=tuple(selected_evidence),
            )
        )

    evidence_by_kind: Dict[str, List[AlertEvidence]] = {}
    for fact in normalized.evidence:
        evidence_by_kind.setdefault(fact.kind, []).append(fact)

    security_indicators = [
        fact
        for fact in normalized.evidence
        if fact.tags.intersection(_SECURITY_TAGS)
    ]
    suspicious_ips = [
        fact
        for fact in security_indicators
        if fact.kind == "ip_address"
    ]
    if not suspicious_ips and normalized.source_family == "endpoint_edr" and normalized.malicious_detection:
        suspicious_ips = [
            fact
            for fact in evidence_by_kind.get("ip_address", [])
            if "generic_full_log:IP" in fact.source
        ]
    for fact in suspicious_ips:
        add_candidate(
            "block_ip",
            {"target": fact},
            "The IP is explicitly present in the alert as a security indicator; verify scope before blocking.",
        )

    for fact in security_indicators:
        if fact.kind == "url":
            add_candidate(
                "block_url",
                {"target": fact},
                "The URL is explicitly tagged as a phishing, command-and-control, or malicious indicator.",
            )
        elif fact.kind == "domain":
            add_candidate(
                "block_domain",
                {"target": fact},
                "The domain is explicitly tagged as a phishing, command-and-control, or malicious indicator.",
            )

    if normalized.malicious_detection:
        for fact in evidence_by_kind.get("file_hash", []):
            add_candidate(
                "block_hash",
                {"target": fact},
                "The alert identifies a malicious file and contains this exact file hash.",
            )

        endpoint_facts = [
            fact
            for fact in evidence_by_kind.get("endpoint_id", [])
            if fact.verified and normalized.source_family == "endpoint_edr"
        ]
        file_facts = [
            fact
            for kind in ("file_reference", "file_hash")
            for fact in evidence_by_kind.get(kind, [])
        ]
        for endpoint in endpoint_facts:
            for file_fact in file_facts:
                add_candidate(
                    "quarantine_file",
                    {"target": file_fact, "endpoint": endpoint},
                    "The alert identifies the malicious file and a verified affected endpoint.",
                )

            for action_name, justification in (
                (
                    "force_edr_scan",
                    "A malicious detection is associated with this verified endpoint.",
                ),
                (
                    "collect_endpoint_artifacts",
                    "Collect endpoint evidence for the malicious detection.",
                ),
            ):
                add_candidate(
                    action_name,
                    {"target": endpoint},
                    justification,
                )

    add_candidate(
        "notify_analyst",
        {},
        "Escalate the alert for human review.",
    )
    return candidates
