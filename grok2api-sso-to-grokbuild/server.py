#!/usr/bin/env python3
from __future__ import annotations

import hmac
import json
import logging
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
from urllib.parse import urlsplit

from sso2auth import (
    DEFAULT_MAX_BATCH_ITEMS,
    DEFAULT_MAX_EMAIL_LENGTH,
    DEFAULT_MAX_SOURCE_LENGTH,
    DEFAULT_MAX_SSO_LENGTH,
    HARD_MAX_BATCH_ITEMS,
    HARD_MAX_ITEM_TIMEOUT,
    HARD_MAX_WORKERS,
    configure_device_flow_limit,
    convert_sso_batch,
    proxy_log_label,
    resolve_proxy,
    sso_to_token,
)

LOGGER = logging.getLogger("sso-converter")
HARD_MAX_BODY_BYTES = 1_048_576


def _env_int(
    env: Mapping[str, str], name: str, default: int, *, minimum: int, maximum: int
) -> int:
    raw = env.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_float(
    env: Mapping[str, str], name: str, default: float, *, minimum: float, maximum: float
) -> float:
    raw = env.get(name, "").strip()
    try:
        value = float(raw) if raw else default
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum:g} and {maximum:g}")
    return value


@dataclass(frozen=True)
class ServiceConfig:
    api_token: str
    host: str = "127.0.0.1"
    port: int = 8090
    max_body_bytes: int = 262_144
    max_items: int = DEFAULT_MAX_BATCH_ITEMS
    max_concurrency: int = 4
    max_inflight_requests: int = 4
    request_read_timeout: float = 15.0
    item_timeout: float = 120.0
    network_timeout: float = 30.0
    poll_timeout: float = 90.0
    max_retries: int = 3
    flow_concurrency: int = 2
    flow_gap: float = 0.5
    max_sso_length: int = DEFAULT_MAX_SSO_LENGTH
    max_email_length: int = DEFAULT_MAX_EMAIL_LENGTH
    max_source_length: int = DEFAULT_MAX_SOURCE_LENGTH
    proxy: str | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "ServiceConfig":
        env = os.environ if environ is None else environ
        api_token = env.get("SSO_CONVERTER_API_TOKEN", "").strip()
        if not api_token:
            raise ValueError("SSO_CONVERTER_API_TOKEN is required")
        try:
            api_token.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("SSO_CONVERTER_API_TOKEN must contain only ASCII characters") from exc
        max_concurrency = _env_int(
            env, "SSO_CONVERTER_MAX_CONCURRENCY", 4, minimum=1, maximum=HARD_MAX_WORKERS
        )
        max_inflight_requests = _env_int(
            env,
            "SSO_CONVERTER_MAX_INFLIGHT_REQUESTS",
            max_concurrency,
            minimum=1,
            maximum=HARD_MAX_WORKERS * 2,
        )
        return cls(
            api_token=api_token,
            host=env.get("SSO_CONVERTER_HOST", "127.0.0.1").strip() or "127.0.0.1",
            port=_env_int(env, "SSO_CONVERTER_PORT", 8090, minimum=1, maximum=65_535),
            max_body_bytes=_env_int(
                env,
                "SSO_CONVERTER_MAX_BODY_BYTES",
                262_144,
                minimum=1_024,
                maximum=HARD_MAX_BODY_BYTES,
            ),
            max_items=_env_int(
                env,
                "SSO_CONVERTER_MAX_ITEMS",
                DEFAULT_MAX_BATCH_ITEMS,
                minimum=1,
                maximum=HARD_MAX_BATCH_ITEMS,
            ),
            max_concurrency=max_concurrency,
            max_inflight_requests=max_inflight_requests,
            request_read_timeout=_env_float(
                env,
                "SSO_CONVERTER_REQUEST_READ_TIMEOUT_SECONDS",
                15.0,
                minimum=0.1,
                maximum=60.0,
            ),
            item_timeout=_env_float(
                env,
                "SSO_CONVERTER_ITEM_TIMEOUT_SECONDS",
                120.0,
                minimum=0.1,
                maximum=HARD_MAX_ITEM_TIMEOUT,
            ),
            network_timeout=_env_float(
                env,
                "SSO_CONVERTER_NETWORK_TIMEOUT_SECONDS",
                30.0,
                minimum=0.1,
                maximum=60.0,
            ),
            poll_timeout=_env_float(
                env,
                "SSO_CONVERTER_POLL_TIMEOUT_SECONDS",
                90.0,
                minimum=0.1,
                maximum=HARD_MAX_ITEM_TIMEOUT,
            ),
            max_retries=_env_int(
                env, "SSO_CONVERTER_MAX_RETRIES", 3, minimum=1, maximum=10
            ),
            flow_concurrency=_env_int(
                env,
                "SSO_CONVERTER_FLOW_CONCURRENCY",
                min(2, max_concurrency),
                minimum=1,
                maximum=max_concurrency,
            ),
            flow_gap=_env_float(
                env, "SSO_CONVERTER_FLOW_GAP_SECONDS", 0.5, minimum=0.0, maximum=30.0
            ),
            max_sso_length=_env_int(
                env,
                "SSO_CONVERTER_MAX_SSO_LENGTH",
                DEFAULT_MAX_SSO_LENGTH,
                minimum=256,
                maximum=65_536,
            ),
            max_email_length=_env_int(
                env,
                "SSO_CONVERTER_MAX_EMAIL_LENGTH",
                DEFAULT_MAX_EMAIL_LENGTH,
                minimum=64,
                maximum=1_024,
            ),
            max_source_length=_env_int(
                env,
                "SSO_CONVERTER_MAX_SOURCE_LENGTH",
                DEFAULT_MAX_SOURCE_LENGTH,
                minimum=16,
                maximum=2_048,
            ),
            proxy=resolve_proxy(env.get("SSO_CONVERTER_PROXY")) or None,
        )


class ConverterHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: ServiceConfig, mint_fn: Any):
        self.config = config
        self.mint_fn = mint_fn
        self.conversion_executor = ThreadPoolExecutor(
            max_workers=config.max_concurrency, thread_name_prefix="sso-service"
        )
        self.request_slots = threading.BoundedSemaphore(config.max_inflight_requests)
        self.connection_slots = threading.BoundedSemaphore(config.max_inflight_requests)
        self._connection_count = 0
        self._connection_count_lock = threading.Lock()
        self._request_read_timers: dict[int, threading.Timer] = {}
        self._expired_request_reads: set[int] = set()
        self._request_read_timers_lock = threading.Lock()
        self._last_handler_error_log = 0.0
        self._handler_error_log_lock = threading.Lock()
        super().__init__(address, ConverterHandler)

    @property
    def active_connection_count(self) -> int:
        with self._connection_count_lock:
            return self._connection_count

    def get_request(self) -> tuple[socket.socket, Any]:
        request, client_address = super().get_request()
        # Header parsing happens in BaseHTTPRequestHandler.__init__, before any
        # do_* method can apply a timeout. Set it immediately after accept so a
        # slow partial header cannot hold a handler thread indefinitely.
        request.settimeout(self.config.request_read_timeout)
        return request, client_address

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        # ThreadingMixIn normally creates an unbounded thread for every accepted
        # socket. Reserve capacity before it starts the thread instead.
        if not self.connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self._connection_count_lock:
            self._connection_count += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._connection_count_lock:
                self._connection_count -= 1
            self.connection_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        self._start_request_read_deadline(request)
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.finish_request_read(request)
            with self._connection_count_lock:
                self._connection_count -= 1
            self.connection_slots.release()

    def _start_request_read_deadline(self, request: socket.socket) -> None:
        timer = threading.Timer(
            self.config.request_read_timeout,
            self._expire_request_read,
            args=(request,),
        )
        timer.daemon = True
        key = id(request)
        with self._request_read_timers_lock:
            self._request_read_timers[key] = timer
        timer.start()

    def _expire_request_read(self, request: socket.socket) -> None:
        key = id(request)
        with self._request_read_timers_lock:
            timer = self._request_read_timers.pop(key, None)
            if timer is not None:
                self._expired_request_reads.add(key)
        if timer is None:
            return
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            request.close()
        except OSError:
            pass

    def finish_request_read(self, request: socket.socket) -> bool:
        key = id(request)
        with self._request_read_timers_lock:
            timer = self._request_read_timers.pop(key, None)
            expired = key in self._expired_request_reads
            self._expired_request_reads.discard(key)
        if timer is not None:
            timer.cancel()
        # Retain an idle write bound after the absolute read deadline is retired.
        try:
            request.settimeout(self.config.request_read_timeout)
        except OSError:
            pass
        return not expired

    def server_close(self) -> None:
        super().server_close()
        self.conversion_executor.shutdown(wait=False, cancel_futures=True)

    def handle_error(self, request: Any, client_address: Any) -> None:
        # socketserver's default prints a full traceback for every malformed
        # client connection. Keep diagnostics bounded and never echo request
        # bytes or secrets into logs.
        now = time.monotonic()
        with self._handler_error_log_lock:
            if now - self._last_handler_error_log < 30.0:
                return
            self._last_handler_error_log = now
        LOGGER.warning("request handler error (further errors suppressed for 30s)")


class ConverterHandler(BaseHTTPRequestHandler):
    server: ConverterHTTPServer
    server_version = "grok-sso-converter"
    sys_version = ""

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            if getattr(self, "_holds_request_slot", False):
                self._holds_request_slot = False
                self.server.request_slots.release()

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _write_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(encoded)

    def _error(self, status: int, code: str, message: str) -> None:
        self._write_json(status, {"error": {"code": code, "message": message}})

    def _finish_request_read(self) -> bool:
        return self.server.finish_request_read(self.connection)

    def _request_path(self) -> str | None:
        try:
            return urlsplit(self.path).path
        except ValueError:
            return None

    def _is_authorized(self) -> bool:
        authorization = self.headers.get("Authorization", "")
        scheme, separator, supplied = authorization.partition(" ")
        try:
            supplied_bytes = supplied.encode("ascii")
            expected_bytes = self.server.config.api_token.encode("ascii")
        except UnicodeEncodeError:
            return False
        return bool(
            separator
            and scheme.lower() == "bearer"
            and supplied
            and hmac.compare_digest(supplied_bytes, expected_bytes)
        )

    def do_GET(self) -> None:
        if not self._finish_request_read():
            self.close_connection = True
            return
        path = self._request_path()
        if path is None:
            self.close_connection = True
            self._error(HTTPStatus.BAD_REQUEST, "invalid_target", "request target is invalid")
            return
        if path != "/healthz":
            self._error(HTTPStatus.NOT_FOUND, "not_found", "route not found")
            return
        self._write_json(HTTPStatus.OK, {"status": "ok"})

    def do_POST(self) -> None:
        path = self._request_path()
        if path is None:
            if not self._finish_request_read():
                return
            self.close_connection = True
            self._error(HTTPStatus.BAD_REQUEST, "invalid_target", "request target is invalid")
            return
        if path != "/v1/convert":
            if not self._finish_request_read():
                return
            self._error(HTTPStatus.NOT_FOUND, "not_found", "route not found")
            return
        if not self._is_authorized():
            if not self._finish_request_read():
                return
            self.close_connection = True
            self._error(HTTPStatus.UNAUTHORIZED, "unauthorized", "valid Bearer token required")
            return
        if not self.server.request_slots.acquire(blocking=False):
            if not self._finish_request_read():
                return
            self.close_connection = True
            self._error(
                HTTPStatus.TOO_MANY_REQUESTS,
                "busy",
                "converter request capacity is exhausted",
            )
            return
        self._holds_request_slot = True
        self.close_connection = True
        if self.headers.get("Transfer-Encoding"):
            if not self._finish_request_read():
                return
            self.close_connection = True
            self._error(
                HTTPStatus.BAD_REQUEST, "unsupported_transfer_encoding", "Content-Length required"
            )
            return
        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            if not self._finish_request_read():
                return
            self._error(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Content-Type must be application/json",
            )
            return
        content_length_value = self.headers.get("Content-Length")
        if content_length_value is None:
            if not self._finish_request_read():
                return
            self.close_connection = True
            self._error(HTTPStatus.LENGTH_REQUIRED, "length_required", "Content-Length required")
            return
        try:
            content_length = int(content_length_value)
        except ValueError:
            if not self._finish_request_read():
                return
            self.close_connection = True
            self._error(HTTPStatus.BAD_REQUEST, "invalid_length", "invalid Content-Length")
            return
        if content_length < 0 or content_length > self.server.config.max_body_bytes:
            if not self._finish_request_read():
                return
            self.close_connection = True
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_too_large", "request body too large")
            return
        try:
            body = self.rfile.read(content_length)
        except (OSError, socket.timeout, TimeoutError):
            if not self._finish_request_read():
                return
            self._error(HTTPStatus.REQUEST_TIMEOUT, "read_timeout", "request body read timed out")
            return
        if not self._finish_request_read():
            return
        if len(body) != content_length:
            self._error(HTTPStatus.BAD_REQUEST, "incomplete_body", "request body was incomplete")
            return
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json", "request body must be valid JSON")
            return
        if not isinstance(payload, dict):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request", "request body must be an object")
            return
        if set(payload) - {"items", "timeout_seconds"}:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request", "unsupported request fields")
            return
        items = payload.get("items")
        if not isinstance(items, list) or not items:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_items", "items must be a non-empty array")
            return
        if len(items) > self.server.config.max_items:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "too_many_items",
                f"items exceeds limit of {self.server.config.max_items}",
            )
            return
        item_timeout = self.server.config.item_timeout
        if "timeout_seconds" in payload:
            requested_timeout = payload["timeout_seconds"]
            if isinstance(requested_timeout, bool) or not isinstance(requested_timeout, (int, float)):
                self._error(
                    HTTPStatus.BAD_REQUEST, "invalid_timeout", "timeout_seconds must be a number"
                )
                return
            if not 0 < float(requested_timeout) <= item_timeout:
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_timeout",
                    f"timeout_seconds must be between 0 and {item_timeout:g}",
                )
                return
            item_timeout = float(requested_timeout)

        results = convert_sso_batch(
            items,
            mint_fn=self.server.mint_fn,
            proxy=self.server.config.proxy,
            workers=self.server.config.max_concurrency,
            item_timeout=item_timeout,
            network_timeout=min(self.server.config.network_timeout, item_timeout),
            poll_timeout=min(self.server.config.poll_timeout, item_timeout),
            max_retries=self.server.config.max_retries,
            max_items=self.server.config.max_items,
            max_sso_length=self.server.config.max_sso_length,
            max_email_length=self.server.config.max_email_length,
            max_source_length=self.server.config.max_source_length,
            executor=self.server.conversion_executor,
        )
        succeeded = sum(1 for result in results if result["ok"])
        self._write_json(
            HTTPStatus.OK,
            {
                "results": results,
                "summary": {
                    "total": len(results),
                    "succeeded": succeeded,
                    "failed": len(results) - succeeded,
                },
            },
        )


def create_server(
    config: ServiceConfig, *, mint_fn: Any = sso_to_token
) -> ConverterHTTPServer:
    configure_device_flow_limit(
        concurrency=config.flow_concurrency,
        gap=config.flow_gap,
    )
    return ConverterHTTPServer((config.host, config.port), config, mint_fn)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = ServiceConfig.from_env()
    except ValueError as exc:
        LOGGER.error("configuration error: %s", exc)
        return 2
    server = create_server(config)
    LOGGER.info(
        "listening on %s:%d max_items=%d concurrency=%d proxy=%s",
        config.host,
        config.port,
        config.max_items,
        config.max_concurrency,
        proxy_log_label(config.proxy or ""),
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
