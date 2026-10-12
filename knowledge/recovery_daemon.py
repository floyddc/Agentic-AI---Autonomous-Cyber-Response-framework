import logging
import threading
from typing import Optional
from knowledge.registry import IncidentRegistry

logger = logging.getLogger(__name__)

class MaintenanceDaemon:
    def __init__(
        self,
        interval_seconds: int = 60,
        stale_timeout_seconds: int = 300,
        recovery_start_event: Optional[threading.Event] = None,
    ):
        self.interval_seconds = interval_seconds
        self.stale_timeout_seconds = stale_timeout_seconds
        self.recovery_start_event = recovery_start_event
        self.registry = IncidentRegistry()
        self._stop_event = threading.Event()

    def run(self) -> None:
        logger.info("Starting Maintenance & Recovery Daemon...")
        while (
            self.recovery_start_event is not None
            and not self._stop_event.is_set()
            and not self.recovery_start_event.wait(timeout=0.1)
        ):
            pass

        while not self._stop_event.is_set():
            try:
                recovered = self.registry.recover_stale_events(timeout_seconds=self.stale_timeout_seconds)
                if recovered > 0:
                    logger.warning("Recovered %d stale processing events in inbox!", recovered)

            except Exception:
                logger.exception("Error during maintenance cycle")

            self._stop_event.wait(self.interval_seconds)

    def stop(self) -> None:
        self._stop_event.set()
        if self.recovery_start_event is not None:
            self.recovery_start_event.set()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    daemon = MaintenanceDaemon(interval_seconds=30, stale_timeout_seconds=120)
    try:
        daemon.run()
    except KeyboardInterrupt:
        daemon.stop()