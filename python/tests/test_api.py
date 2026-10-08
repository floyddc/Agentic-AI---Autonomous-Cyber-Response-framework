import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from api import create_server


class FakeRegistry:
    def __init__(self):
        self.created = None
        self.incidents = {17: {"status": "new", "updated_at": None}}

    def create_incident(self, **kwargs):
        self.created = kwargs
        return 17

    def get_incident(self, incident_id):
        return self.incidents.get(incident_id)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.registry = FakeRegistry()
        self.server = create_server(self.registry, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = "http://127.0.0.1:{}".format(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, path, method="GET", body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method=method,
        )
        return urlopen(request, timeout=2)

    def test_health_endpoint(self):
        with self.request("/health") as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read()), {"status": "ok"})

    def test_post_alert_persists_incident_and_accepts_async_processing(self):
        payload = {
            "_source": "EDR",
            "external_id": "test-123",
            "host": "workstation-1",
        }

        with self.request("/alerts", method="POST", body=payload) as response:
            report = json.loads(response.read())
            self.assertEqual(response.status, 202)
            self.assertEqual(response.headers["Location"], "/incidents/17")

        self.assertEqual(report, {"incident_id": 17, "status": "new"})
        self.assertEqual(
            self.registry.created,
            {
                "source": "EDR",
                "raw_payload": {"host": "workstation-1"},
                "external_id": "test-123",
            },
        )

    def test_rejects_non_object_json(self):
        request = Request(
            self.base_url + "/alerts",
            data=b"[]",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as error:
            urlopen(request, timeout=2)

        self.assertEqual(error.exception.code, 400)
        self.assertEqual(
            json.loads(error.exception.read()),
            {"error": "Alert body must be a JSON object"},
        )
        self.assertIsNone(self.registry.created)

    def test_get_incident_returns_current_status(self):
        with self.request("/incidents/17") as response:
            self.assertEqual(
                json.loads(response.read()),
                {"incident_id": 17, "status": "new", "updated_at": None},
            )

    def test_get_unknown_incident_returns_not_found(self):
        with self.assertRaises(HTTPError) as error:
            self.request("/incidents/999")

        self.assertEqual(error.exception.code, 404)

    def test_unknown_route_returns_not_found(self):
        with self.assertRaises(HTTPError) as error:
            self.request("/unknown")

        self.assertEqual(error.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
