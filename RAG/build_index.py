import argparse
from .ingestion import build_chunks, load_new_database_documents
from .knowledge_store import IndexStateStore
from .vector_store import index_records, reset_collection

def main(reset: bool = False):
    state_store = IndexStateStore()
    if reset:
        state_store.reset_cursor("kb_documents")
        state_store.reset_cursor("incident_history")
        reset_collection()

    knowledge_cursor = state_store.get_cursor("kb_documents")
    history_cursor = state_store.get_cursor("incident_history")
    documents, knowledge_rows, history_rows = load_new_database_documents(knowledge_cursor, history_cursor)
    records = build_chunks(documents)
    skipped_history = 0
    for row in history_rows:
        metadata = row.get("metadata")
        customer = metadata.get("customer") if isinstance(metadata, dict) else None
        if isinstance(customer, bool) or not isinstance(customer, int) or customer <= 0:
            skipped_history += 1
    print(
        f"Found {len(knowledge_rows)} new PostgreSQL knowledge documents and "
        f"{len(history_rows)} new incident history records."
    )
    if skipped_history:
        print(f"Skipped {skipped_history} history records without valid customer metadata; they are excluded from retrieval until assigned and reindexed.")

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

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Rebuild the vector index from database records and reset index cursors",
    )
    main(reset=parser.parse_args().reset)
