from .api import query_rag

def ask(question: str) -> str:
    return query_rag(question)["answer"]

def main():
    print("RAG chat - type 'exit' to quit.\n")
    while True:
        question = input("You: ").strip()
        if question.lower() in ("exit", "quit"):
            break
        if not question:
            continue
        print("\nAssistant:", ask(question), "\n")

if __name__ == "__main__":
    main()
