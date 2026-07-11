from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import sso2auth


def _segment(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def fake_token(user_id: str = "user-1") -> dict:
    access = f"{_segment({'alg': 'none'})}.{_segment({'sub': user_id, 'iat': 100, 'exp': 200})}.sig"
    return {
        "access_token": access,
        "refresh_token": f"refresh-{user_id}",
        "expires_in": 100,
    }


class BatchConversionTests(unittest.TestCase):
    def test_stdlib_response_size_is_bounded(self) -> None:
        class Response:
            status = 200

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def read(self, size: int = -1) -> bytes:
                self.requested = size
                return b"x" * (sso2auth.HARD_MAX_UPSTREAM_RESPONSE_BYTES + 1)

        class Opener:
            def open(self, *_: object, **__: object) -> Response:
                return Response()

        with mock.patch.object(sso2auth, "_opener", return_value=Opener()):
            with self.assertRaisesRegex(sso2auth.OAuthDeviceError, "exceeds"):
                sso2auth._post_form(
                    sso2auth.TOKEN_URL,
                    {"grant_type": "test"},
                    retries=0,
                )

    def test_curl_response_size_is_bounded(self) -> None:
        class Response:
            status_code = 200
            url = "https://accounts.x.ai/"
            headers: dict[str, str] = {}
            closed = False

            def iter_content(self):
                yield b"x" * sso2auth.HARD_MAX_UPSTREAM_RESPONSE_BYTES
                yield b"y"

            def close(self) -> None:
                self.closed = True

        class Session:
            def __init__(self) -> None:
                self.response = Response()
                self.kwargs: dict[str, object] = {}

            def request(self, *_: object, **kwargs: object) -> Response:
                self.kwargs = kwargs
                return self.response

        session = Session()
        with self.assertRaisesRegex(sso2auth.OAuthDeviceError, "exceeds"):
            sso2auth._request_xai(session, "GET", "https://accounts.x.ai/")
        self.assertFalse(session.kwargs["stream"])
        self.assertTrue(session.response.closed)

    def test_real_curl_slow_headers_obey_absolute_deadline(self) -> None:
        if sso2auth.cf_requests is None:
            self.skipTest("curl_cffi is not installed")

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve() -> None:
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(1)
                    try:
                        conn.recv(4096)
                    except OSError:
                        return
                    conn.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                    for _ in range(30):
                        try:
                            conn.sendall(b"a")
                        except OSError:
                            return
                        time.sleep(0.05)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        session = sso2auth.cf_requests.Session()
        started = time.monotonic()
        try:
            with mock.patch.object(
                sso2auth, "_validate_xai_url", side_effect=lambda raw, **_: raw
            ):
                with self.assertRaises(sso2auth.ConversionDeadlineExceeded):
                    sso2auth._request_xai(
                        session,
                        "GET",
                        f"http://127.0.0.1:{port}/",
                        deadline=started + 0.1,
                    )
            self.assertLess(time.monotonic() - started, 0.6)
        finally:
            session.close()
            listener.close()
            thread.join(timeout=1)

    def test_stdlib_slow_response_honors_cancel_and_releases_worker(self) -> None:
        class Response:
            status = 200
            closed = False

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_: object) -> None:
                self.closed = True

            def read(self, _size: int = -1) -> bytes:
                time.sleep(0.01)
                return b"x"

        response = Response()

        class Opener:
            def open(self, *_: object, **__: object) -> Response:
                return response

        def mint(
            _: str,
            *,
            deadline: float,
            cancel_event: threading.Event,
            **__: object,
        ) -> dict:
            sso2auth._post_form(
                sso2auth.TOKEN_URL,
                {"grant_type": "test"},
                retries=0,
                deadline=deadline,
                cancel_event=cancel_event,
            )
            return fake_token()

        executor = ThreadPoolExecutor(max_workers=1)
        try:
            with mock.patch.object(sso2auth, "_opener", return_value=Opener()):
                results = sso2auth.convert_sso_batch(
                    [{"sso": "stdlib-slow"}],
                    mint_fn=mint,
                    executor=executor,
                    item_timeout=0.05,
                )
            self.assertEqual(results[0]["error"]["code"], "timeout")
            self.assertEqual(executor.submit(lambda: "released").result(timeout=0.3), "released")
            self.assertTrue(response.closed)
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

    def test_curl_slow_response_honors_cancel_and_releases_worker(self) -> None:
        class Response:
            status_code = 200
            url = "https://accounts.x.ai/"
            headers: dict[str, str] = {}
            closed = False

            def iter_content(self):
                while True:
                    time.sleep(0.01)
                    yield b"x"

            def close(self) -> None:
                self.closed = True

        response = Response()

        class Session:
            def request(self, *_: object, **__: object) -> Response:
                return response

        def mint(
            _: str,
            *,
            deadline: float,
            cancel_event: threading.Event,
            **__: object,
        ) -> dict:
            sso2auth._request_xai(
                Session(),
                "GET",
                "https://accounts.x.ai/",
                deadline=deadline,
                cancel_event=cancel_event,
            )
            return fake_token()

        executor = ThreadPoolExecutor(max_workers=1)
        try:
            results = sso2auth.convert_sso_batch(
                [{"sso": "curl-slow"}],
                mint_fn=mint,
                executor=executor,
                item_timeout=0.05,
            )
            self.assertEqual(results[0]["error"]["code"], "timeout")
            self.assertEqual(executor.submit(lambda: "released").result(timeout=0.3), "released")
            self.assertTrue(response.closed)
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

    def test_xai_url_validation_rejects_untrusted_verification_targets(self) -> None:
        allowed = sso2auth._validate_xai_url(
            "https://accounts.x.ai/oauth2/device?user_code=ABC",
            device_path=True,
        )
        self.assertIn("accounts.x.ai", allowed)
        for target in (
            "http://accounts.x.ai/oauth2/device",
            "https://evil.example/oauth2/device",
            "https://accounts.x.ai.evil.example/oauth2/device",
            "https://user@accounts.x.ai/oauth2/device",
            "https://accounts.x.ai:444/oauth2/device",
            "https://accounts.x.ai/not-device",
            "https://preview.x.ai/oauth2/device",
        ):
            with self.subTest(target=target):
                with self.assertRaises(sso2auth.OAuthDeviceError):
                    sso2auth._validate_xai_url(target, device_path=True)

    def test_xai_request_checks_redirect_before_following(self) -> None:
        class Response:
            status_code = 302
            url = "https://accounts.x.ai/oauth2/device"
            headers = {"Location": "https://metadata.google.internal/computeMetadata/v1/"}

        class Session:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def request(self, _method: str, url: str, **_kwargs: object) -> Response:
                self.calls.append(url)
                return Response()

        session = Session()
        with self.assertRaises(sso2auth.OAuthDeviceError):
            sso2auth._request_xai(session, "GET", "https://accounts.x.ai/oauth2/device")
        self.assertEqual(session.calls, ["https://accounts.x.ai/oauth2/device"])

    def test_stdlib_oauth_endpoints_reject_redirects_and_overrides(self) -> None:
        self.assertEqual(
            sso2auth._validate_oauth_endpoint(sso2auth.TOKEN_URL),
            sso2auth.TOKEN_URL,
        )
        for target in (
            "https://accounts.x.ai/oauth2/token",
            "https://auth.x.ai/oauth2/authorize",
            "https://auth.x.ai/oauth2/token?next=x",
        ):
            with self.subTest(target=target):
                with self.assertRaises(sso2auth.OAuthDeviceError):
                    sso2auth._validate_oauth_endpoint(target)
        handler = sso2auth._RejectRedirectHandler()
        with self.assertRaises(sso2auth.OAuthDeviceError):
            handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/")

    def test_batch_is_ordered_normalized_and_does_not_write_files(self) -> None:
        def mint(sso: str, **_: object) -> dict:
            if sso == "slow-cookie":
                time.sleep(0.03)
            return fake_token(sso.removesuffix("-cookie"))

        with tempfile.TemporaryDirectory() as directory:
            previous = os.getcwd()
            os.chdir(directory)
            try:
                results = sso2auth.convert_sso_batch(
                    [
                        {"sso": "slow-cookie", "email": "one@example.com", "source": "first"},
                        {"sso": "fast-cookie", "email": "two@example.com"},
                    ],
                    mint_fn=mint,
                    workers=2,
                    item_timeout=1,
                )
                self.assertEqual(list(Path(directory).iterdir()), [])
            finally:
                os.chdir(previous)

        self.assertEqual([result["index"] for result in results], [0, 1])
        self.assertEqual(results[0]["credential"]["source_key"], "first")
        self.assertEqual(results[0]["credential"]["email"], "one@example.com")
        self.assertEqual(results[0]["credential"]["user_id"], "slow")
        self.assertEqual(results[0]["credential"]["oidc_issuer"], "https://auth.x.ai")
        self.assertEqual(results[0]["credential"]["oidc_client_id"], sso2auth.CLIENT_ID)
        self.assertEqual(
            results[1]["credential"]["source_key"], f"{sso2auth.AUTH_KEY}::fast"
        )
        rendered = json.dumps(results)
        self.assertNotIn("slow-cookie", rendered)
        self.assertNotIn("fast-cookie", rendered)

    def test_batch_enforces_global_worker_limit(self) -> None:
        lock = threading.Lock()
        active = 0
        peak = 0

        def mint(sso: str, **_: object) -> dict:
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(0.02)
                return fake_token(sso)
            finally:
                with lock:
                    active -= 1

        results = sso2auth.convert_sso_batch(
            [{"sso": f"cookie-{index}"} for index in range(6)],
            mint_fn=mint,
            workers=2,
            item_timeout=1,
        )
        self.assertTrue(all(result["ok"] for result in results))
        self.assertEqual(peak, 2)

    def test_failures_are_per_item_and_redacted(self) -> None:
        secret = "super-secret-sso"

        def mint(sso: str, **_: object) -> dict:
            raise RuntimeError(f"upstream rejected {sso}")

        results = sso2auth.convert_sso_batch(
            [
                {"email": "missing@example.com", "source": "bad-input"},
                {"sso": secret, "source": "mint-failure"},
            ],
            mint_fn=mint,
            workers=1,
            item_timeout=1,
        )
        self.assertEqual(results[0]["error"]["code"], "invalid_item")
        self.assertEqual(results[1]["error"]["code"], "conversion_failed")
        self.assertNotIn(secret, json.dumps(results))

    def test_item_timeout_is_reported_without_secret(self) -> None:
        def mint(_: str, **__: object) -> dict:
            time.sleep(0.1)
            return fake_token()

        results = sso2auth.convert_sso_batch(
            [{"sso": "timeout-secret"}],
            mint_fn=mint,
            item_timeout=0.02,
        )
        self.assertEqual(results[0]["error"]["code"], "timeout")
        self.assertNotIn("timeout-secret", json.dumps(results))

    def test_item_deadline_interrupts_retry_backoff_and_releases_worker(self) -> None:
        attempts = 0

        def fail_once(*_: object, **__: object) -> dict:
            nonlocal attempts
            attempts += 1
            raise sso2auth.RateLimitedError("rate limited")

        executor = ThreadPoolExecutor(max_workers=1)
        started = time.monotonic()
        try:
            with mock.patch.object(sso2auth, "sso_to_token_once", side_effect=fail_once):
                results = sso2auth.convert_sso_batch(
                    [{"sso": "deadline-secret"}],
                    mint_fn=sso2auth.sso_to_token,
                    executor=executor,
                    item_timeout=0.05,
                    max_retries=10,
                )
            self.assertEqual(results[0]["error"]["code"], "timeout")
            self.assertLess(time.monotonic() - started, 0.3)
            self.assertEqual(executor.submit(lambda: "released").result(timeout=0.3), "released")
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
        self.assertEqual(attempts, 1)

    def test_deadline_interrupts_device_flow_semaphore_wait(self) -> None:
        sso2auth.configure_device_flow_limit(concurrency=1, gap=0)
        semaphore = sso2auth._device_flow_sem
        assert semaphore is not None
        self.assertTrue(semaphore.acquire(timeout=0.1))
        executor = ThreadPoolExecutor(max_workers=1)

        def wait_for_flow(
            _: str,
            *,
            deadline: float,
            cancel_event: threading.Event,
            **__: object,
        ) -> dict:
            sso2auth._acquire_device_flow(deadline, cancel_event)
            try:
                return fake_token()
            finally:
                sso2auth._release_device_flow()

        try:
            results = sso2auth.convert_sso_batch(
                [{"sso": "semaphore-secret"}],
                mint_fn=wait_for_flow,
                executor=executor,
                item_timeout=0.05,
            )
            self.assertEqual(results[0]["error"]["code"], "timeout")
            self.assertEqual(executor.submit(lambda: "released").result(timeout=0.3), "released")
        finally:
            semaphore.release()
            executor.shutdown(wait=True, cancel_futures=True)

    def test_deadline_interrupts_token_poll_sleep(self) -> None:
        with mock.patch.object(
            sso2auth,
            "_post_form",
            return_value=(400, {"error": "authorization_pending"}),
        ):
            started = time.monotonic()
            with self.assertRaises(sso2auth.ConversionDeadlineExceeded):
                sso2auth.poll_device_token(
                    "device-code",
                    interval=5,
                    deadline=time.monotonic() + 0.05,
                )
            self.assertLess(time.monotonic() - started, 0.3)

    def test_poll_timeout_below_thirty_seconds_is_respected(self) -> None:
        with mock.patch.object(
            sso2auth,
            "_post_form",
            return_value=(400, {"error": "authorization_pending"}),
        ):
            started = time.monotonic()
            with self.assertRaises(sso2auth.ConversionDeadlineExceeded):
                sso2auth.poll_device_token(
                    "device-code",
                    interval=5,
                    expires_in=0.05,
                )
            self.assertLess(time.monotonic() - started, 0.3)

    def test_cli_still_writes_auth_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "auth.json"
            argv = [
                "sso2auth.py",
                "--sso-cookie",
                "cli-cookie",
                "--out",
                str(output),
                "--no-failed",
            ]
            with (
                mock.patch.object(sso2auth, "sso_to_token", return_value=fake_token("cli-user")),
                mock.patch.object(sso2auth.sys, "argv", argv),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(sso2auth.main(), 0)
            document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(document[sso2auth.AUTH_KEY]["user_id"], "cli-user")


if __name__ == "__main__":
    unittest.main()
