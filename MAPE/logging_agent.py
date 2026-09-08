import json
import logging
import sys
import time
from contextlib import contextmanager
from typing import Any, Dict, Optional
from RAG import config
from postgres.db import cursor as _cursor

logger = logging.getLogger(__name__)


def _build_meter():
    
    try:
        from opentelemetry import metrics
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource

        exporter = OTLPMetricExporter(endpoint=config.OTEL_EXPORTER_OTLP_ENDPOINT, insecure=True)
        reader = PeriodicExportingMetricReader(
            exporter, export_interval_millis=config.OTEL_METRIC_EXPORT_INTERVAL_MS
        )
        provider = MeterProvider(
            resource=Resource.create({"service.name": config.OTEL_SERVICE_NAME}),
            metric_readers=[reader],
        )
        metrics.set_meter_provider(provider)
        meter = metrics.get_meter(config.OTEL_SERVICE_NAME)

        events_counter = meter.create_counter(
            "agent_events_total",
            unit="1",
            description="Number of event records emitted by each system component",
        )
        duration_histogram = meter.create_histogram(
            "agent_duration_ms",
            unit="ms",
            description="Duration of operations performed by each system component",
        )
        return events_counter, duration_histogram
    except Exception:
        logger.warning("OpenTelemetry metrics export disabled (SDK/exporter unavailable)", exc_info=True)
        return None, None


class LoggingAgent:

    def __init__(self):
        self._events_counter, self._duration_histogram = _build_meter()

    def record(
        self,
        component: str,
        action: str,
        status: str = "success",
        duration_ms: Optional[float] = None,
        incident_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:

        try:
            with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
                cur.execute(
                    """
                    INSERT INTO agent_metrics (component, action, status, duration_ms, incident_id, details)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (component, action, status, duration_ms, incident_id, json.dumps(details or {})),
                )
        except Exception:
            logger.exception("Failed to persist agent_metrics record for %s/%s", component, action)

        attributes = {"component": component, "action": action, "status": status}
        try:
            if self._events_counter is not None:
                self._events_counter.add(1, attributes=attributes)
            if self._duration_histogram is not None and duration_ms is not None:
                self._duration_histogram.record(duration_ms, attributes=attributes)
        except Exception:
            logger.exception("Failed to export OpenTelemetry metric for %s/%s", component, action)

    @contextmanager
    def track(self, component: str, action: str, incident_id: Optional[int] = None, details: Optional[Dict[str, Any]] = None):

        start = time.perf_counter()
        status = "success"
        try:
            yield
        except Exception:
            status = "error"
            raise
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            self.record(component, action, status=status, duration_ms=duration_ms, incident_id=incident_id, details=details)

    def tail(self, limit: int = 20):
        with _cursor(config.POSTGRES_OPERATIONAL_DB) as cur:
            cur.execute("SELECT * FROM agent_metrics ORDER BY created_at DESC LIMIT %s", (limit,))
            return cur.fetchall()


# Module-level singleton, shared by every agent that wants to emit metrics.
logging_agent = LoggingAgent()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    limit = 20
    if len(sys.argv) > 1 and sys.argv[1] not in ("--tail",):
        limit = int(sys.argv[1])
    elif len(sys.argv) > 2:
        limit = int(sys.argv[2])

    for row in logging_agent.tail(limit=limit):
        print(json.dumps(row, indent=2, default=str, ensure_ascii=False))
