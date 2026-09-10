import json
import time
from ollama import Client
from MAPE.orchestrator import Orchestrator

client = Client(host="http://ollama:11434")
orchestrator = Orchestrator()

messages = [
    {
        "role": "system",
        "content": (
            "You are an english assistant. "
            "Answer clearly, concisely, and directly.."
        )
    }
]

print("=" * 50)
print("       Chat with Qwen3:4b-instruct")
print("=" * 50)
print("Type 'exit' to close this chat.")
print("Type 'alert <path_to_json>' to run the orchestrator on a raw security alert.\n")

while True:
    try:
        user_input = input("You: ").strip()

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit", "esci"):
            print("Hi!")
            break

        if user_input.lower().startswith("alert"):
            parts = user_input.split(maxsplit=1)
            if len(parts) < 2:
                print("Usage: alert <path_to_json>\n")
                continue

            try:
                with open(parts[1], "r", encoding="utf-8-sig") as f:
                    payload = json.load(f)
                source = payload.pop("_source", "manual")
                report = orchestrator.handle_alert(source=source, raw_payload=payload)
                print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
                print()
            except Exception as e:
                print(f"[DEBUG] Orchestrator error: {e}\n")
            continue

        messages.append({
            "role": "user",
            "content": user_input
        })

        print("\n[DEBUG] Request sent to Qwen3...")

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
        print(f"[DEBUG] Completed in {elapsed:.2f} seconds.")
        print()

        messages.append({
            "role": "assistant",
            "content": answer
        })

    except KeyboardInterrupt:
        print("\nHi!")
        break

    except Exception as e:
        print(f"\n[DEBUG] Error: {e}\n")