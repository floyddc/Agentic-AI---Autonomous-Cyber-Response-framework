from .ingestion import build_chunks
from .vectorstore import index_records

def main():
    records = build_chunks()
    print(f"Loaded {len(records)} chunks from the Knowledge DB (Docs store + Incident History) and knowledge/policies, knowledge/actions_catalog.")

    if not records:
        print(
            "No documents found. Run 'python -m RAG.seed_knowledge_base' to populate the "
            "Knowledge Base from knowledge/base/*, add incidents to the Incident History, "
            "or add files under knowledge/policies/ and knowledge/actions_catalog/, then re-run this script."
        )
        return

    total = index_records(records, reset=True)
    print(f"Indexed {total} chunks into the vector store at knowledge/indices/.")


if __name__ == "__main__":
    main()
