import time
from ollama import Client

client = Client(host="http://ollama:11434")

messages = [
    {
        "role": "system",
        "content": (
            "Sei un assistente italiano. "
            "Rispondi in modo chiaro, conciso e diretto."
        )
    }
]

print("=" * 50)
print("       Chat con Qwen3:4b")
print("=" * 50)
print("Scrivi 'exit' per uscire.\n")


while True:
    try:
        user_input = input("Tu: ").strip()

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit", "esci"):
            print("Ciao!")
            break

        messages.append({
            "role": "user",
            "content": user_input
        })

        print("\n[DEBUG] Invio richiesta a Qwen3...")
        print("[DEBUG] Qwen3 sta elaborando...\n")

        start_time = time.time()

        response = client.chat(
            model="qwen3:4b-instruct",
            messages=messages,
            options={
                "num_ctx": 2048,
                "temperature": 0.6,
                "num_thread": 8,
            },
            stream=True,
        )

        answer = ""

        print("Qwen: ", end="", flush=True)

        for chunk in response:
            text = chunk["message"]["content"]

            if text:
                print(text, end="", flush=True)
                answer += text

        elapsed = time.time() - start_time

        print("\n")
        print(f"[DEBUG] Risposta completata in {elapsed:.2f} secondi.")
        print(f"[DEBUG] Caratteri generati: {len(answer)}")
        print()

        messages.append({
            "role": "assistant",
            "content": answer
        })

    except KeyboardInterrupt:
        print("\n\nCiao!")
        break

    except Exception as e:
        print(f"\n[DEBUG] Errore: {e}\n")