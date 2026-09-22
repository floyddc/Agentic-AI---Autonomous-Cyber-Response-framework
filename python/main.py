import time
from ollama import Client
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
print("                    WARM-UP COMPLETE - CONTAINER READY")
print("=" * 60)
print("\n")

while True:
    time.sleep(3600)