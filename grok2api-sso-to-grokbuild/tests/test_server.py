from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

import server


def _fake_token() -> dict:
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "fake-user", "exp": 2_000_000_000}).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return {
        "access_token": f"header.{payload}.signature",
        "refresh_token": "fake-refresh-token",
    }


def _mint(sso: str, **_: object) -> dict:
    if sso == "fail-cookie":
        raise RuntimeError("simulated failure containing fail-cookie")
    return _fake_token()


class HTTPServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        config = server.ServiceConfig(
            api_token="test-api-token",
            host="127.0.0.1",
            port=0,
            max_body_bytes=512,
            max_items=2,
            max_concurrency=2,
            max_inflight_requests=2,
            request_read_timeout=0.2,
            item_timeout=1,
            flow_concurrency=1,
            flow_gap=0,
        )
        self.server = server.create_server(config, mint_fn=_mint)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)

    def request(
        self,
        method: str,
        path: str,
        payload: object | None = None,
        *,
        token: str | None = None,
        raw_body: bytes | None = None,
    ) -> tuple[int, dict]:
        body = raw_body if raw_body is not None else (
            json.dumps(payload).encode("utf-8") if payload is not None else None
        )
        headers: dict[str, str] = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        parsed = json.loads(response.read())
        status = response.status
        connection.close()
        return status, parsed

    def test_healthz_does_not_require_authentication(self) -> None:
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})

    def test_convert_requires_bearer_token(self) -> None:
        status, payload = self.request("POST", "/v1/convert", {"items": [{"sso": "x"}]})
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "unauthorized")

    def test_non_ascii_bearer_is_rejected_without_handler_exception(self) -> None:
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=1)
        try:
            connection.settimeout(1)
            connection.sendall(
                b"POST /v1/convert HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Authorization: Bearer \xe9\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 2\r\n\r\n{}"
            )
            chunks = []
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            response = b"".join(chunks)
        finally:
            connection.close()
        self.assertIn(b" 401 ", response)
        self.assertIn(b'"code":"unauthorized"', response)

    def test_malformed_absolute_request_target_returns_400(self) -> None:
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=1)
        try:
            connection.settimeout(1)
            connection.sendall(b"GET http://[bad HTTP/1.0\r\n\r\n")
            chunks = []
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            response = b"".join(chunks)
        finally:
            connection.close()
        self.assertIn(b" 400 ", response)
        self.assertIn(b'"code":"invalid_target"', response)

    def test_convert_returns_ordered_credentials_without_sso(self) -> None:
        status, payload = self.request(
            "POST",
            "/v1/convert",
            {
                "items": [
                    {"sso": "secret-one", "email": "one@example.com", "source": "one"},
                    {"sso": "secret-two", "source": "two"},
                ]
            },
            token="test-api-token",
        )
        self.assertEqual(status, 200)
        self.assertEqual([item["index"] for item in payload["results"]], [0, 1])
        self.assertEqual(payload["results"][0]["credential"]["source_key"], "one")
        self.assertEqual(payload["summary"], {"total": 2, "succeeded": 2, "failed": 0})
        rendered = json.dumps(payload)
        self.assertNotIn("secret-one", rendered)
        self.assertNotIn("secret-two", rendered)

    def test_convert_preserves_partial_success_without_secret_leak(self) -> None:
        status, payload = self.request(
            "POST",
            "/v1/convert",
            {"items": [{"sso": "good-cookie"}, {"sso": "fail-cookie"}]},
            token="test-api-token",
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["results"][0]["ok"])
        self.assertFalse(payload["results"][1]["ok"])
        self.assertEqual(payload["summary"], {"total": 2, "succeeded": 1, "failed": 1})
        rendered = json.dumps(payload)
        self.assertNotIn("good-cookie", rendered)
        self.assertNotIn("fail-cookie", rendered)

    def test_body_item_and_timeout_limits_are_enforced(self) -> None:
        status, payload = self.request(
            "POST",
            "/v1/convert",
            raw_body=b'{' + (b'"x":"' + b'a' * 600 + b'"}'),
            token="test-api-token",
        )
        self.assertEqual(status, 413)
        self.assertEqual(payload["error"]["code"], "body_too_large")

        status, payload = self.request(
            "POST",
            "/v1/convert",
            {"items": [{"sso": "1"}, {"sso": "2"}, {"sso": "3"}]},
            token="test-api-token",
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "too_many_items")

        status, payload = self.request(
            "POST",
            "/v1/convert",
            {"items": [{"sso": "1"}], "timeout_seconds": 2},
            token="test-api-token",
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_timeout")

    def test_overload_is_rejected_without_queueing_request(self) -> None:
        self.assertTrue(self.server.request_slots.acquire(blocking=False))
        self.assertTrue(self.server.request_slots.acquire(blocking=False))
        try:
            status, payload = self.request(
                "POST",
                "/v1/convert",
                {"items": [{"sso": "not-queued"}]},
                token="test-api-token",
            )
        finally:
            self.server.request_slots.release()
            self.server.request_slots.release()
        self.assertEqual(status, 429)
        self.assertEqual(payload["error"]["code"], "busy")

    def test_slow_partial_headers_are_timed_out_and_connection_bounded(self) -> None:
        slow_connections = [
            socket.create_connection(("127.0.0.1", self.port), timeout=1)
            for _ in range(2)
        ]
        try:
            for slow in slow_connections:
                slow.settimeout(1)
                slow.sendall(b"POST /v1/convert HTTP/1.1\r\nHost: localhost\r\n")
            deadline = time.monotonic() + 0.5
            while self.server.active_connection_count != 2 and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertEqual(self.server.active_connection_count, 2)

            blocked = socket.create_connection(("127.0.0.1", self.port), timeout=1)
            try:
                blocked.settimeout(0.5)
                blocked.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                try:
                    rejected = blocked.recv(1)
                except ConnectionResetError:
                    rejected = b""
                self.assertEqual(rejected, b"")
            finally:
                blocked.close()
            self.assertLessEqual(self.server.active_connection_count, 2)

            for slow in slow_connections:
                try:
                    timed_out = slow.recv(1)
                except ConnectionResetError:
                    timed_out = b""
                self.assertEqual(timed_out, b"")
        finally:
            for slow in slow_connections:
                slow.close()
        deadline = time.monotonic() + 0.5
        while self.server.active_connection_count and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertEqual(self.server.active_connection_count, 0)

        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})

    def test_absolute_header_deadline_rejects_slow_drip(self) -> None:
        slow = socket.create_connection(("127.0.0.1", self.port), timeout=1)
        started = time.monotonic()
        try:
            slow.settimeout(0.5)
            slow.sendall(b"POST /v1/convert HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
            for _ in range(4):
                time.sleep(0.12)
                try:
                    slow.sendall(b"a")
                except (BrokenPipeError, ConnectionResetError, OSError):
                    break
            try:
                closed = slow.recv(1)
            except ConnectionResetError:
                closed = b""
            self.assertEqual(closed, b"")
            self.assertLess(time.monotonic() - started, 0.8)
        finally:
            slow.close()

        deadline = time.monotonic() + 0.5
        while self.server.active_connection_count and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertEqual(self.server.active_connection_count, 0)
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})

    def test_http_conversion_does_not_write_credentials_or_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            previous = os.getcwd()
            os.chdir(directory)
            try:
                status, payload = self.request(
                    "POST",
                    "/v1/convert",
                    {"items": [{"sso": "memory-only"}]},
                    token="test-api-token",
                )
                self.assertEqual(status, 200)
                self.assertTrue(payload["results"][0]["ok"])
                self.assertEqual(list(Path(directory).iterdir()), [])
            finally:
                os.chdir(previous)


class PackagingSafetyTests(unittest.TestCase):
    def test_docker_context_is_deny_by_default(self) -> None:
        root = Path(__file__).resolve().parents[1]
        rules = [
            line.strip()
            for line in (root / ".dockerignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(rules[0], "*")
        self.assertEqual(
            set(rules[1:]),
            {
                "!.dockerignore",
                "!Dockerfile",
                "!README",
                "!requirements.txt",
                "!server.py",
                "!sso2auth.py",
            },
        )


if __name__ == "__main__":
    unittest.main()
