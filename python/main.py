import json
import time

from ollama import Client
from MAPE.orchestrator import Orchestrator
from RAG import config
from RAG.reranker import warmup as warmup_reranker_model


# ============================================================
# Ollama client
# ============================================================

client = Client(host=config.OLLAMA_HOST)


# ============================================================
# Model warm-up
# ============================================================

def warmup_embedding():
    print(
        "-------------------- "
        "Warming up embedding model... "
        "--------------------"
    )

    query = ("EDR alert suspicious PowerShell execution with possible credential theft and lateral movement")

    try:
        # First call: model loading / initialization
        start = time.perf_counter()

        client.embed(
            model=config.EMBEDDING_MODEL,
            input=query,
            keep_alive=-1,
        )

        warmup_ms = (time.perf_counter() - start) * 1000

        # Second call: verifies that the model is actually resident
        start = time.perf_counter()

        client.embed(
            model=config.EMBEDDING_MODEL,
            input=query,
            keep_alive=-1,
        )

        verification_ms = (time.perf_counter() - start) * 1000

        print(
            f"-------------------- "
            f"Embedding warm-up complete. "
            f"Initial: {warmup_ms:.2f} ms | "
            f"Verification: {verification_ms:.2f} ms "
            f"--------------------"
        )

        return verification_ms

    except Exception as e:
        print(
            f"-------------------- "
            f"Embedding warm-up failed: {e} "
            f"--------------------"
        )

        return None


def warmup_reranker():
    print(
        "-------------------- "
        "Warming up reranker... "
        "--------------------"
    )

    try:
        start = time.perf_counter()
        warmup_reranker_model()
        elapsed_ms = (time.perf_counter() - start) * 1000

        print(
            f"-------------------- "
            f"Reranker warm-up complete: "
            f"{elapsed_ms:.2f} ms "
            f"--------------------"
        )

        return elapsed_ms

    except Exception as e:
        print(
            f"-------------------- "
            f"Reranker warm-up failed: {e} "
            f"--------------------"
        )

        return None


def warmup_qwen(model_name):
    print(
        f"-------------------- "
        f"Warming up {model_name}... "
        f"--------------------"
    )

    try:
        start = time.perf_counter()

        client.chat(
            model=model_name,
            messages=[{"role": "user", "content": "Warm-up"}],
            keep_alive=-1,
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        print(
            f"-------------------- "
            f"{model_name} warm-up complete: "
            f"{elapsed_ms:.2f} ms "
            f"(keep_alive=-1) "
            f"--------------------"
        )

        return elapsed_ms

    except Exception as e:
        print(
            f"-------------------- "
            f"{model_name} warm-up failed: {e} "
            f"--------------------"
        )

        return None


# ============================================================
# Warm-up all models
# ============================================================

print("\n")
print("=" * 60)
print("                    MODEL WARM-UP")
print("=" * 60)

embedding_warmup_ms = warmup_embedding()
reranker_warmup_ms = warmup_reranker()
triage_warmup_ms = warmup_qwen(config.TRIAGE_MODEL)
planner_warmup_ms = warmup_qwen(config.PLAN_MODEL)

print("=" * 60)
print("                    WARM-UP COMPLETE")
print("=" * 60)
print("\n")


# ============================================================
# Orchestrator
# ============================================================

orchestrator = Orchestrator()


# ============================================================
# Interactive chat
# ============================================================

messages = [
    {
        "role": "system",
        "content": (
            "You are an english assistant. "
            "Answer clearly, concisely, and directly."
        ),
    }
]


print("=" * 50)
print("       Chat with Qwen3:4b-instruct")
print("=" * 50)
print("Type 'exit' to close this chat.")
print(
    "Type 'alert <path_to_json>' to run the "
    "orchestrator on a raw security alert.\n"
)


# ============================================================
# Main loop
# ============================================================

while True:

    try:

        user_input = input("You: ").strip()

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit", "esci"):
            print("Hi!")
            break


        # ----------------------------------------------------
        # Orchestrator alert
        # ----------------------------------------------------

        if user_input.lower().startswith("alert"):

            parts = user_input.split(maxsplit=1)

            if len(parts) < 2:
                print("Usage: alert <path_to_json>\n")
                continue

            try:

                with open(
                    parts[1],
                    "r",
                    encoding="utf-8-sig",
                ) as f:

                    payload = json.load(f)

                source = payload.pop(
                    "_source",
                    "manual",
                )

                report = orchestrator.handle_alert(
                    source=source,
                    raw_payload=payload,
                )

                print(
                    json.dumps(
                        report,
                        indent=2,
                        ensure_ascii=False,
                        default=str,
                    )
                )

                print()

            except Exception as e:

                print(
                    f"[DEBUG] Orchestrator error: {e}\n"
                )

            continue


        # ----------------------------------------------------
        # Normal chat with Qwen3
        # ----------------------------------------------------
        messages.append({"role": "user", "content": user_input})
        print("\n[DEBUG] Request sent to Qwen3...")
        start_time = time.time()
        response = client.chat(
            model=config.PLAN_MODEL,
            messages=messages,
            options={
                "num_ctx": 2048,
                "temperature": 0.6,
                "num_thread": 8,
            },
            keep_alive=-1,
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
        print("[DEBUG] Completed in "f"{elapsed:.2f} seconds.")

        print()
        messages.append({"role": "assistant", "content": answer})


    except KeyboardInterrupt:
        print("\nHi!")
        break


    except Exception as e:
        print(f"\n[DEBUG] Error: {e}\n")