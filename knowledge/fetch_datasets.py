import argparse
import csv
import io
import json
import os
import re
from typing import Dict, List, Optional
import requests
from RAG import config

MITRE_DATASET = "sarahwei/cyber_MITRE_attack_tactics-and-techniques"
MITRE_ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
NSL_KDD_TEST_URL = (
    "https://huggingface.co/datasets/An24/IntrusionDetectionSystem-NSL_KDD/"
    "resolve/main/NSL_KDD_Test.csv"
)
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label",
    "difficulty_level",
]


def _slugify(text: str, max_len: int = 60) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug[:max_len] or "item"


def _safe_filename(text: str, max_len: int = 80) -> str:
    text = re.sub(r"[^\w\s.-]", "", text, flags=re.UNICODE)
    text = re.sub(r"\s+", "_", text.strip())
    return text[:max_len] or "item"


def _write_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _write_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def fetch_mitre_attack_qa() -> int:
    from datasets import load_dataset

    dataset = load_dataset(MITRE_DATASET, split="train")
    out_dir = os.path.join(config.BASE_DIR, "mitre_attack")
    os.makedirs(out_dir, exist_ok=True)

    count = 0
    for idx, row in enumerate(dataset):
        question = (row.get("question") or "").strip()
        answer = (row.get("answer") or "").strip()
        if not question or not answer:
            continue

        filename = f"hf_{idx:04d}_{_slugify(question)}.md"
        content = (
            f"# {question}\n\n{answer}\n\n"
            f"*Fonte: HuggingFace dataset `{MITRE_DATASET}`.*\n"
        )
        _write_text(os.path.join(out_dir, filename), content)
        count += 1

    return count


def fetch_mitre_attack_stix() -> Dict:
    print("Downloading official MITRE ATT&CK STIX bundle...")
    response = requests.get(MITRE_ATTACK_STIX_URL, timeout=120)
    response.raise_for_status()
    return response.json()


def _external_attack_id(obj: dict) -> Optional[str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id")
            if external_id:
                return external_id
    return None


def _is_valid_attack_object(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def fetch_attack_patterns(stix_bundle: Dict) -> int:
    out_dir = os.path.join(config.BASE_DIR, "attack_patterns")
    os.makedirs(out_dir, exist_ok=True)

    count = 0
    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or not _is_valid_attack_object(obj):
            continue

        attack_id = _external_attack_id(obj)
        if not attack_id:
            continue

        name = obj.get("name", "Unknown Technique")
        description = (obj.get("description") or "").strip()

        tactics = [
            phase.get("phase_name", "")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("phase_name")
        ]
        platforms = obj.get("x_mitre_platforms", [])
        permissions = obj.get("x_mitre_permissions_required", [])
        detection = (obj.get("x_mitre_detection") or "").strip()

        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                url = ref.get("url", "")
                break

        content_parts = [
            f"# {attack_id} - {name}",
            "",
            "## Description",
            "",
            description,
            "",
            "## Tactics",
            "",
        ]

        content_parts.extend(
            f"- {tactic}" for tactic in tactics
        ) if tactics else content_parts.append("- Not specified")

        content_parts.extend(["", "## Platforms", ""])
        content_parts.extend(
            f"- {platform}" for platform in platforms
        ) if platforms else content_parts.append("- Not specified")

        content_parts.extend(["", "## Required Permissions", ""])
        content_parts.extend(
            f"- {permission}" for permission in permissions
        ) if permissions else content_parts.append("- Not specified")

        if detection:
            content_parts.extend(["", "## Detection", "", detection])

        if url:
            content_parts.extend(["", "## MITRE ATT&CK Reference", "", url])

        content_parts.extend([
            "",
            "---",
            "",
            "*Source: MITRE ATT&CK Enterprise STIX 2.1.*",
            "",
        ])

        filename = f"{attack_id}_{_safe_filename(name)}.md"
        _write_text(os.path.join(out_dir, filename), "\n".join(content_parts))
        count += 1

    return count


def fetch_procedures(stix_bundle: Dict, sample_size: int = 200) -> int:
    out_dir = os.path.join(config.BASE_DIR, "procedures")
    os.makedirs(out_dir, exist_ok=True)

    objects = stix_bundle.get("objects", [])
    object_by_id = {obj.get("id"): obj for obj in objects if obj.get("id")}

    count = 0
    for relationship in objects:
        if count >= sample_size:
            break

        if relationship.get("type") != "relationship":
            continue
        if relationship.get("relationship_type") != "uses":
            continue
        if not _is_valid_attack_object(relationship):
            continue

        source_obj = object_by_id.get(relationship.get("source_ref"))
        target_obj = object_by_id.get(relationship.get("target_ref"))

        if not source_obj or not target_obj:
            continue
        if target_obj.get("type") != "attack-pattern":
            continue
        if source_obj.get("type") not in {"intrusion-set", "malware", "tool"}:
            continue

        attack_id = _external_attack_id(target_obj)
        if not attack_id:
            continue

        description = (relationship.get("description") or "").strip()
        if not description:
            continue

        source_name = source_obj.get("name", "Unknown")
        source_type = source_obj.get("type", "unknown")
        technique_name = target_obj.get("name", "Unknown Technique")

        relationship_id = relationship.get(
            "id",
            f"{relationship.get('source_ref')}_{relationship.get('target_ref')}"
        )
        safe_id = _safe_filename(
            relationship_id.replace("relationship--", "")
        )

        content = "\n".join([
            f"# Procedure - {source_name} - {attack_id}",
            "",
            "## Technique",
            "",
            f"{attack_id} - {technique_name}",
            "",
            "## Implementing Entity",
            "",
            f"- Name: {source_name}",
            f"- Type: {source_type}",
            "",
            "## Procedure Example",
            "",
            description,
            "",
            "---",
            "",
            "*Source: MITRE ATT&CK Enterprise STIX 2.1.*",
            "",
        ])

        filename = (
            f"{attack_id}_{_safe_filename(source_name)}_{safe_id[:24]}.md"
        )
        _write_text(os.path.join(out_dir, filename), content)
        count += 1

    return count



def fetch_threatfox_observables(
    days: int = 3,
    auth_key: Optional[str] = None,
) -> int:
    if not auth_key:
        print("ThreatFox: no AUTH KEY configured; skipping.")
        return 0

    payload = {
        "query": "get_iocs",
        "days": max(1, min(days, 7)),
    }

    response = requests.post(
        THREATFOX_URL,
        json=payload,
        headers={"Auth-Key": auth_key},
        timeout=60,
    )
    response.raise_for_status()
    data = response.json()

    if data.get("query_status") != "ok":
        print(f"ThreatFox returned: {data.get('query_status')}")
        return 0

    out_dir = os.path.join(config.BASE_DIR, "observables")
    count = 0

    for idx, item in enumerate(data.get("data") or []):
        ioc = item.get("ioc")
        if not ioc:
            continue

        observable = {
            "source": "ThreatFox",
            "source_id": item.get("id"),
            "observable": ioc,
            "observable_type": item.get("ioc_type"),
            "threat_type": item.get("threat_type"),
            "threat_type_description": item.get("threat_type_desc"),
            "malware": item.get("malware"),
            "malware_printable": item.get("malware_printable"),
            "confidence_level": item.get("confidence_level"),
            "first_seen": item.get("first_seen"),
            "last_seen": item.get("last_seen"),
            "reference": item.get("reference"),
            "tags": item.get("tags"),
        }

        filename = f"threatfox_{item.get('id', idx)}.json"
        _write_json(os.path.join(out_dir, filename), observable)
        count += 1

    return count


def fetch_urlhaus_observables(sample_size: int = 500) -> int:
    print("Downloading recent URLhaus observables...")

    try:
        response = requests.get(URLHAUS_URL, timeout=120)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        print(f"URLhaus download failed: {exc}")
        return 0

    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        records = payload.get("urls") or payload.get("data") or []
    else:
        records = []

    out_dir = os.path.join(config.BASE_DIR, "observables")
    count = 0

    for idx, item in enumerate(records[:sample_size]):
        url = item.get("url")
        if not url:
            continue

        observable = {
            "source": "URLhaus",
            "source_id": item.get("id"),
            "observable": url,
            "observable_type": "url",
            "url_status": item.get("url_status"),
            "threat": item.get("threat"),
            "date_added": item.get("date_added"),
            "last_online": item.get("last_online"),
            "reporter": item.get("reporter"),
            "tags": item.get("tags"),
            "host": item.get("host"),
            "payloads": item.get("payloads"),
        }

        filename = f"urlhaus_{item.get('id', idx)}.json"
        _write_json(os.path.join(out_dir, filename), observable)
        count += 1

    return count


def fetch_malwarebazaar_observables(sample_size: int = 500) -> int:
    print("Downloading recent MalwareBazaar observables...")

    payload = {
        "query": "get_recent",
        "selector": "time",
    }

    try:
        response = requests.post(
            MALWAREBAZAAR_URL,
            data=payload,
            timeout=120,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        print(f"MalwareBazaar download failed: {exc}")
        return 0

    if data.get("query_status") != "ok":
        print(f"MalwareBazaar returned: {data.get('query_status')}")
        return 0

    out_dir = os.path.join(config.BASE_DIR, "observables")
    count = 0

    for item in (data.get("data") or [])[:sample_size]:
        sha256 = item.get("sha256_hash")
        if not sha256:
            continue

        observable = {
            "source": "MalwareBazaar",
            "observable": sha256,
            "observable_type": "sha256",
            "sha256": item.get("sha256_hash"),
            "sha1": item.get("sha1_hash"),
            "md5": item.get("md5_hash"),
            "first_seen": item.get("first_seen"),
            "last_seen": item.get("last_seen"),
            "file_name": item.get("file_name"),
            "file_type": item.get("file_type"),
            "signature": item.get("signature"),
            "tags": item.get("tags"),
            "vendor_intel": item.get("vendor_intel"),
        }

        filename = f"malwarebazaar_{sha256[:32]}.json"
        _write_json(os.path.join(out_dir, filename), observable)
        count += 1

    return count


def fetch_nsl_kdd_sample(sample_size: int = 500) -> int:
    response = requests.get(NSL_KDD_TEST_URL, timeout=60)
    response.raise_for_status()

    first_line = response.text.splitlines()[0]
    has_header = not first_line.split(",")[0].strip().isdigit()

    reader = csv.reader(io.StringIO(response.text))
    rows = list(reader)

    if has_header:
        rows = rows[1:]

    records = []
    for row in rows[:sample_size]:
        if len(row) < 42:
            continue
        records.append(dict(zip(NSL_KDD_COLUMNS, row)))

    out_dir = os.path.join(
        config.KNOWLEDGE_DIR,
        "raw_data",
        "xrd_telemetry",
    )
    out_path = os.path.join(out_dir, "nsl_kdd_sample.json")
    _write_json(out_path, records)

    return len(records)


def main():
    parser = argparse.ArgumentParser(
        description="Fetch cybersecurity datasets into the RAG Knowledge Base."
    )
    parser.add_argument(
        "--mitre",
        action="store_true",
        help="Download MITRE ATT&CK Q&A and official ATT&CK knowledge.",
    )
    parser.add_argument(
        "--telemetry",
        action="store_true",
        help="Download a NSL-KDD network telemetry sample.",
    )
    parser.add_argument(
        "--observables",
        action="store_true",
        help="Download IOC data from ThreatFox, URLhaus and MalwareBazaar.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=200,
        help="Maximum number of records for large datasets.",
    )
    parser.add_argument(
        "--threatfox-days",
        type=int,
        default=3,
        help="Number of recent days to retrieve from ThreatFox.",
    )

    args = parser.parse_args()

    if not args.mitre and not args.telemetry and not args.observables:
        args.mitre = True
        args.telemetry = True
        args.observables = True

    if args.mitre:
        n = fetch_mitre_attack_qa()
        print(f"Wrote {n} MITRE ATT&CK Q&A documents to knowledge/base/mitre_attack/")

        stix_bundle = fetch_mitre_attack_stix()

        n = fetch_attack_patterns(stix_bundle)
        print(f"Wrote {n} attack patterns to knowledge/base/attack_patterns/")

        n = fetch_procedures(stix_bundle, args.sample_size)
        print(f"Wrote {n} procedures to knowledge/base/procedures/")

    if args.telemetry:
        n = fetch_nsl_kdd_sample(args.sample_size)
        print(f"Wrote {n} NSL-KDD records to knowledge/raw_data/xrd_telemetry/")

    if args.observables:
        threatfox_key = os.getenv("THREATFOX_AUTH_KEY")

        n = fetch_threatfox_observables(
            days=args.threatfox_days,
            auth_key=threatfox_key,
        )
        print(f"Wrote {n} ThreatFox observables to knowledge/base/observables/")

        n = fetch_urlhaus_observables(args.sample_size)
        print(f"Wrote {n} URLhaus observables to knowledge/base/observables/")

        n = fetch_malwarebazaar_observables(args.sample_size)
        print(f"Wrote {n} MalwareBazaar observables to knowledge/base/observables/")


if __name__ == "__main__":
    main()