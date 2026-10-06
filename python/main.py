import logging
import signal
import threading
import time
import requests
from api import create_server
from ollama import Client
import config
from MAPE.orchestrator import Orchestrator
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


# PIPELINE WARMUP ----------------------------------------------------------------------------------------------------------------------------------------------------------    
def warmup_pipeline():
    print("=" * 60)
    print(f"                    Warming up the entire pipeline...")
    print("=" * 60)

    try:
        start = time.perf_counter()
        with open(
            "/app/knowledge/raw_data/edr_alerts/warmup_alert.json",
            "r",
            encoding="utf-8"
        ) as f:
            alert_data = f.read()

            response = requests.post(
                "http://localhost:8000/alerts",
                headers={"Content-Type": "application/json"},
                data=alert_data
            )
            response.raise_for_status()
            elapsed_ms = (time.perf_counter() - start) * 1000
            print("=" * 60)
            print(f"                    Pipeline warm-up complete: {elapsed_ms:.2f} ms | status={response.status_code}")
            print("=" * 60)
            return elapsed_ms
    
    except Exception as e:
        print("!" * 60)
        print(f"                    Pipeline warm-up failed: {e}")
        print("!" * 60)
        return None
    
    

print("\n")
print("⏳" * 60)
print("                    SERVER CREATION")
print("⏳" * 60)

orchestrator = Orchestrator()
alert_server = create_server(
    orchestrator,
    host=config.API_HOST,
    port=config.API_PORT,
)
api_thread = threading.Thread(
    target=alert_server.serve_forever,
    name="alert-api",
    daemon=True,
)
api_thread.start()
print("✅" * 60)
logger.info("Alert API listening on %s:%s", config.API_HOST, config.API_PORT)
print("✅" * 60)


if(config.WARMUP_ON):
    print("\n")
    print("⏳" * 60)
    print("                    MODEL WARM-UP")
    print("⏳" * 60)
    pipeline_warmup_ms = warmup_pipeline()
else:
    print("\n")
    print("                    WARM-UP OFF")

    
print("✅" * 60)
print("                    CONTAINER READY")
print("✅" * 60)
print("\n")

try:
    while not _shutdown_event.wait(timeout=3600):
        pass
finally:
    alert_server.shutdown()
    alert_server.server_close()
    api_thread.join(timeout=5)