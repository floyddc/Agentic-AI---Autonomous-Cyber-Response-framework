from .ingestion import build_chunks, load_new_database_documents
from .knowledge_store import IndexStateStore
from .vector_store import index_records

def main():
    state_store = IndexStateStore()
    knowledge_cursor = state_store.get_cursor("kb_documents")
    history_cursor = state_store.get_cursor("incident_history")
    documents, knowledge_rows, history_rows = load_new_database_documents(knowledge_cursor, history_cursor)
    records = build_chunks(documents)
    print(
        f"Found {len(knowledge_rows)} new PostgreSQL knowledge documents and "
        f"{len(history_rows)} new incident history records."
    )

    if records:
        total = index_records(records)
        print(f"Added {total} new chunks to the vector store at knowledge/indices/.")
    else:
        print("No new chunks to index.")

    if knowledge_rows:
        state_store.advance_cursor("kb_documents", max(row["id"] for row in knowledge_rows))
    if history_rows:
        state_store.advance_cursor("incident_history", max(row["id"] for row in history_rows))


if __name__ == "__main__":
    main()
