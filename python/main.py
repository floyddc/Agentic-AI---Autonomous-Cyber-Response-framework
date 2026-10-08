import logging
import signal
import threading
import time
import requests
from api import create_server
import config
from knowledge.registry import IncidentRegistry
from knowledge.recovery_daemon import MaintenanceDaemon
from importlib import import_module

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)
_shutdown_event = threading.Event()
_services_lock = threading.Lock()
_running_services = set()


# BACKGROUND SERVICES ----------------------------------------------------------------------------------------------------------------------------------------------------------    
def _run_resilient(name: str, factory) -> None:
    delay = 1.0
    while not _shutdown_event.is_set():
        try:
            service = factory()
            with _services_lock:
                _running_services.add(service)
            service.run()
            return 
        except Exception:
            logger.exception("Background service '%s' crashed, restarting in %.1fs", name, delay)
            _shutdown_event.wait(delay)
            delay = min(delay * 2, 30)
        finally:
            if "service" in locals():
                with _services_lock:
                    _running_services.discard(service)
                service = None


def start_services() -> list[threading.Thread]:
    services = [
        ("maintenance-daemon", lambda: MaintenanceDaemon(interval_seconds=30, stale_timeout_seconds=120)),
        (
            "retrieve-worker",
            lambda: _create_worker("MAPE.workers.retrieve_worker", "RetrieveWorker"),
        ),
        (
            "triage-worker",
            lambda: _create_worker("MAPE.workers.triage_worker", "TriageWorker"),
        ),
        (
            "action-planner-worker",
            lambda: _create_worker(
                "MAPE.workers.action_planner_worker", "ActionPlannerWorker"
            ),
        ),
        (
            "validation-worker",
            lambda: _create_worker("MAPE.workers.validation_worker", "ValidationWorker"),
        ),
    ]
    threads = []
    for name, factory in services:
        thread = threading.Thread(target=_run_resilient, args=(name, factory), name=name, daemon=True)
        thread.start()
        threads.append(thread)
    logger.info("Background services started: %s", ", ".join(name for name, _ in services))
    return threads


def _create_worker(module_name: str, class_name: str):
    worker_class = getattr(import_module(module_name), class_name)
    return worker_class()


def stop_background_services() -> None:
    _shutdown_event.set()
    with _services_lock:
        services = list(_running_services)
    for service in services:
        try:
            service.stop()
        except Exception:
            logger.exception("Failed to stop background service %r", service)


def _handle_shutdown(signum, frame):
    logger.info("Received signal %s, shutting down background services...", signum)
    stop_background_services()


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
            incident_id = response.json()["incident_id"]

            # heartbeat
            deadline = time.monotonic() + 500
            while time.monotonic() < deadline:
                status_response = requests.get(f"http://localhost:8000/incidents/{incident_id}", timeout=5)
                status_response.raise_for_status()
                status = status_response.json()["status"]
                if status in {
                    "validated",
                    "awaiting_human_approval",
                    "failed",
                    "responded",
                    "closed",
                }:
                    if status == "failed":
                        raise RuntimeError(f"Warm-up incident {incident_id} entered failed state")
                    break
                time.sleep(10)
            else:
                raise TimeoutError(f"Warm-up incident {incident_id} did not finish within 500 seconds")

            elapsed_ms = (time.perf_counter() - start) * 1000
            print("=" * 60)
            print(f"                    Pipeline warm-up complete: {elapsed_ms:.2f} ms | incident={incident_id} | status={status}")
            print("=" * 60)
            return elapsed_ms
    
    except Exception as e:
        print("!" * 60)
        print(f"                    Pipeline warm-up failed: {e}")
        print("!" * 60)
        return None
    
    
# MAIN
signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT, _handle_shutdown)

print("▶️" * 60)
print("                    SERVICES AND WORKERS START")
print("▶️" * 60)
start_services()

print("\n")
print("⏳" * 60)
print("                    SERVER CREATION")
print("⏳" * 60)

registry = IncidentRegistry()
server = create_server(
    registry,
    host=config.API_HOST,
    port=config.API_PORT,
)
api_thread = threading.Thread(
    target=server.serve_forever,
    name="api",
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
    server.shutdown()
    server.server_close()
    api_thread.join(timeout=5)