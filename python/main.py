import logging
import signal
import threading
import time
from ollama import Client
from RAG import config
from RAG.reranker import warmup as warmup_reranker_model
from MQTT.outbox_publisher import OutboxPublisher
from knowledge.recovery_daemon import MaintenanceDaemon

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)
_shutdown_event = threading.Event()
client = Client(host=config.OLLAMA_HOST)


# BACKGROUND SERVICES ----------------------------------------------------------------------------------------------------------------------------------------------------------    
def _run_resilient(name: str, factory) -> None:
    delay = 1.0
    while not _shutdown_event.is_set():
        service = factory()
        try:
            service.run()
            return 
        except Exception:
            logger.exception("Background service '%s' crashed, restarting in %.1fs", name, delay)
            _shutdown_event.wait(delay)
            delay = min(delay * 2, 30)


def start_background_services() -> list[threading.Thread]:
    services = [
        ("outbox-publisher", lambda: OutboxPublisher(publisher_name="outbox-publisher")),
        ("maintenance-daemon", lambda: MaintenanceDaemon(interval_seconds=30, stale_timeout_seconds=120)),
    ]
    threads = []
    for name, factory in services:
        thread = threading.Thread(target=_run_resilient, args=(name, factory), name=name, daemon=True)
        thread.start()
        threads.append(thread)
    logger.info("Background services started: %s", ", ".join(name for name, _ in services))
    return threads


def _handle_shutdown(signum, frame):
    logger.info("Received signal %s, shutting down background services...", signum)
    _shutdown_event.set()


signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT, _handle_shutdown)

start_background_services()


# EMBEDDING MODEL WARMUP ----------------------------------------------------------------------------------------------------------------------------------------------------------    
def warmup_embedding():
    print(
        "-------------------- "
        "Warming up embedding model... "
        "--------------------"
    )

    query = ("EDR alert suspicious PowerShell execution with possible credential theft and lateral movement")

    try:
        # Model loading / initialization
        start = time.perf_counter()
        client.embed(
            model=config.EMBEDDING_MODEL,
            input=query,
            keep_alive=-1,
        )
        warmup_ms = (time.perf_counter() - start) * 1000

        # Check if model is actually resident
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


# RERANKER MODEL WARMUP ----------------------------------------------------------------------------------------------------------------------------------------------------------    
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


# LLM MODEL WARMUP ----------------------------------------------------------------------------------------------------------------------------------------------------------    
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


# RUN ALL WARMUP ----------------------------------------------------------------------------------------------------------------------------------------------------------    
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

while not _shutdown_event.is_set():
    _shutdown_event.wait(timeout=3600)