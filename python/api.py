import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Protocol

logger = logging.getLogger(__name__)
MAX_REQUEST_BYTES = 1_048_576


class Orchestrator(Protocol):
    def handle_alert(
        self,
        *,
        source: str,
        raw_payload: Dict[str, Any],
        external_id: Optional[str] = None,
    ) -> Dict[str, Any]: ...


def create_server(orchestrator: Orchestrator, host: str, port: int) -> ThreadingHTTPServer:
    processing_lock = threading.Lock()

    class AlertRequestHandler(BaseHTTPRequestHandler):
        def _send_json(self, status: int, body: Dict[str, Any]) -> None:
            encoded = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send_json(200, {"status": "ok"})
                return
            self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            if self.path != "/alerts":
                self._send_json(404, {"error": "Not found"})
                return

            content_length = self.headers.get("Content-Length")
            try:
                length = int(content_length) if content_length is not None else -1
            except ValueError:
                self._send_json(400, {"error": "Invalid Content-Length"})
                return

            if length < 0:
                self._send_json(411, {"error": "Content-Length is required"})
                return
            if length > MAX_REQUEST_BYTES:
                self._send_json(413, {"error": "Request body is too large"})
                return

            try:
                payload = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json(400, {"error": "Request body must be valid JSON"})
                return

            if not isinstance(payload, dict):
                self._send_json(400, {"error": "Alert body must be a JSON object"})
                return

            source = payload.pop("_source", "manual")
            if not isinstance(source, str) or not source.strip():
                self._send_json(400, {"error": "'_source' must be a non-empty string"})
                return

            external_id = payload.pop("external_id", None)
            if external_id is not None and not isinstance(external_id, str):
                self._send_json(400, {"error": "'external_id' must be a string"})
                return

            try:
                with processing_lock:
                    report = orchestrator.handle_alert(
                        source=source,
                        raw_payload=payload,
                        external_id=external_id,
                    )
                self._send_json(200, report)
            except Exception:
                logger.exception("Unexpected error while processing an alert")
                self._send_json(500, {"error": "Alert processing failed"})

        def log_message(self, format: str, *args: Any) -> None:
            logger.info("Alert API %s - %s", self.address_string(), format % args)

    return ThreadingHTTPServer((host, port), AlertRequestHandler)
