import os
from . import config
from .knowledge_store import KnowledgeBaseStore

CATEGORY_DIRS = {
    "mitre_attack": os.path.join(config.BASE_DIR, "mitre_attack"),
    "attack_patterns": os.path.join(config.BASE_DIR, "attack_patterns"),
    "observables": os.path.join(config.BASE_DIR, "observables"),
    "procedures": os.path.join(config.BASE_DIR, "procedures"),
}

SUPPORTED_EXTENSIONS = (".md", ".txt", ".json")


def _iter_files(root: str):
    if not os.path.isdir(root):
        return
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if os.path.isfile(path) and path.lower().endswith(SUPPORTED_EXTENSIONS):
            yield path


def main():
    store = KnowledgeBaseStore()
    total = 0
    for category, folder in CATEGORY_DIRS.items():
        for path in _iter_files(folder):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                continue
            title = os.path.splitext(os.path.basename(path))[0]
            store.upsert_document(source_path=path, category=category, content=content, title=title)
            total += 1

    print(f"Seeded {total} documents into the Knowledge Base (Postgres '{config.POSTGRES_KNOWLEDGE_DB}' db).")


if __name__ == "__main__":
    main()
