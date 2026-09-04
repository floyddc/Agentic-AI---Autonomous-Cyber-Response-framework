import argparse
import csv
import io
import json
import re
import requests
from . import config

MITRE_DATASET = "sarahwei/cyber_MITRE_attack_tactics-and-techniques"

NSL_KDD_TEST_URL = (
    "https://huggingface.co/datasets/An24/IntrusionDetectionSystem-NSL_KDD/"
    "resolve/main/NSL_KDD_Test.csv"
)

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


def fetch_mitre_attack_qa() -> int:
    """Downloads the MITRE ATT&CK Q&A dataset and writes one .md file per row."""
    from datasets import load_dataset

    dataset = load_dataset(MITRE_DATASET, split="train")

    import os
    out_dir = os.path.join(config.BASE_DIR, "mitre_attack")
    os.makedirs(out_dir, exist_ok=True)

    count = 0
    for idx, row in enumerate(dataset):
        question = (row.get("question") or "").strip()
        answer = (row.get("answer") or "").strip()
        if not question or not answer:
            continue

        filename = f"hf_{idx:04d}_{_slugify(question)}.md"
        content = f"# {question}\n\n{answer}\n\n*Fonte: HuggingFace dataset `{MITRE_DATASET}`.*\n"
        with open(os.path.join(out_dir, filename), "w", encoding="utf-8") as f:
            f.write(content)
        count += 1
    return count


def fetch_nsl_kdd_sample(sample_size: int = 500) -> int:
    """Downloads a sample of the NSL-KDD network intrusion dataset as JSON
    telemetry records under knowledge/raw_data/xrd_telemetry/."""
    import os

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
        if len(row) < 42:  # 41 features + label; difficulty_level is optional
            continue
        records.append(dict(zip(NSL_KDD_COLUMNS, row)))

    out_dir = os.path.join(config.KNOWLEDGE_DIR, "raw_data", "xrd_telemetry")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "nsl_kdd_sample.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    return len(records)


def main():
    parser = argparse.ArgumentParser(description="Fetch real datasets into knowledge/")
    parser.add_argument("--mitre", action="store_true", help="Download the MITRE ATT&CK Q&A dataset")
    parser.add_argument("--telemetry", action="store_true", help="Download a NSL-KDD network telemetry sample")
    parser.add_argument("--sample-size", type=int, default=500)
    args = parser.parse_args()

    if not args.mitre and not args.telemetry:
        args.mitre = args.telemetry = True

    if args.mitre:
        n = fetch_mitre_attack_qa()
        print(f"Wrote {n} MITRE ATT&CK Q&A documents to knowledge/base/mitre_attack/")

    if args.telemetry:
        n = fetch_nsl_kdd_sample(args.sample_size)
        print(f"Wrote {n} NSL-KDD telemetry records to knowledge/raw_data/xrd_telemetry/nsl_kdd_sample.json")


if __name__ == "__main__":
    main()
