#!/usr/bin/env python3
"""
SSO cookie → ~/.grok/auth.json 格式（纯 HTTP Device Flow，协议直换）

用法:
  # 批量 SSO，并发协议换 token，合并输出；失败写入 failed.txt
  python3 sso2auth.py --sso new_tokens.txt --out merged.json --merge

  # 指定并发与失败文件
  python3 sso2auth.py --sso new_tokens.txt --out merged.json --merge \\
      --workers 8 --failed failed.txt

  # 每个账号一个独立 auth 文件
  python3 sso2auth.py --sso sso_list.txt --out-dir ./auth_out --workers 8

  # 单行 sso
  python3 sso2auth.py --sso-cookie 'eyJ...' --out ~/.grok/auth.json

  # 重试失败的
  python3 sso2auth.py --sso failed.txt --out merged.json --merge
"""
from __future__ import annotations

import argparse
import base64
import inspect
import json
import os
import secrets
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import Executor, Future, ThreadPoolExecutor, TimeoutError as FutureTimeoutError, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

try:
    from curl_cffi import requests as cf_requests
except ImportError:  # pragma: no cover
    cf_requests = None  # type: ignore

CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
OIDC_ISSUER = "https://auth.x.ai"
AUTH_KEY = f"{OIDC_ISSUER}::{CLIENT_ID}"
DEVICE_CODE_URL = f"{OIDC_ISSUER}/oauth2/device/code"
TOKEN_URL = f"{OIDC_ISSUER}/oauth2/token"
VERIFY_URL = f"{OIDC_ISSUER}/oauth2/device/verify"
APPROVE_URL = f"{OIDC_ISSUER}/oauth2/device/approve"
SCOPES = (
    "openid profile email offline_access grok-cli:access "
    "api:access conversations:read conversations:write"
)

DEFAULT_MAX_BATCH_ITEMS = 32
HARD_MAX_BATCH_ITEMS = 100
DEFAULT_MAX_SSO_LENGTH = 16_384
DEFAULT_MAX_EMAIL_LENGTH = 320
DEFAULT_MAX_SOURCE_LENGTH = 256
HARD_MAX_WORKERS = 16
HARD_MAX_ITEM_TIMEOUT = 300.0
HARD_MAX_UPSTREAM_RESPONSE_BYTES = 1_048_576
UPSTREAM_READ_CHUNK_BYTES = 64 * 1024

# 线程安全写文件 / 全局 device-flow 节流（避免 IP 级 rate_limited）
_write_lock = threading.Lock()
_print_lock = threading.Lock()
# 同时进行 verify+approve 的数量；device/code 本身较轻
_device_flow_sem: threading.Semaphore | None = None
_device_flow_gap = 0.0  # 两次关键路径之间的最小间隔
_device_flow_last = 0.0
_device_flow_gate = threading.Lock()


class ConversionDeadlineExceeded(TimeoutError):
    """A conversion cooperatively stopped at its absolute item deadline."""


def log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def _check_deadline(
    deadline: float | None = None, cancel_event: threading.Event | None = None
) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise ConversionDeadlineExceeded("conversion cancelled")
    if deadline is not None and time.monotonic() >= deadline:
        raise ConversionDeadlineExceeded("conversion deadline exceeded")


def _remaining_timeout(
    timeout: float,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> float:
    _check_deadline(deadline, cancel_event)
    value = max(float(timeout), 0.001)
    if deadline is not None:
        value = min(value, max(deadline - time.monotonic(), 0.001))
    return value


def _cooperative_sleep(
    seconds: float,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> None:
    _check_deadline(deadline, cancel_event)
    wait = max(float(seconds), 0.0)
    if deadline is not None:
        wait = min(wait, max(deadline - time.monotonic(), 0.0))
    if wait > 0:
        if cancel_event is not None:
            cancel_event.wait(wait)
        else:
            time.sleep(wait)
    _check_deadline(deadline, cancel_event)


def _read_limited(
    stream: Any,
    *,
    label: str,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    read = getattr(stream, "read1", None)
    if not callable(read):
        read = stream.read
    while True:
        _check_deadline(deadline, cancel_event)
        raw = read(UPSTREAM_READ_CHUNK_BYTES)
        _check_deadline(deadline, cancel_event)
        if not raw:
            return b"".join(chunks)
        chunk = bytes(raw)
        total += len(chunk)
        if total > HARD_MAX_UPSTREAM_RESPONSE_BYTES:
            raise OAuthDeviceError(
                f"{label} exceeds {HARD_MAX_UPSTREAM_RESPONSE_BYTES} bytes"
            )
        chunks.append(chunk)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def decode_jwt_payload(token: str) -> dict:
    try:
        return json.loads(b64url_decode(token.split(".")[1]))
    except Exception:
        return {}


def rfc3339_ns(ts: float | None = None) -> str:
    """2026-07-10T01:00:00.000000000Z"""
    if ts is None:
        ts = time.time()
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".000000000Z"


def resolve_proxy(explicit: str | None = None) -> str:
    for cand in (
        (explicit or "").strip(),
        (os.environ.get("https_proxy") or "").strip(),
        (os.environ.get("HTTPS_PROXY") or "").strip(),
        (os.environ.get("http_proxy") or "").strip(),
        (os.environ.get("HTTP_PROXY") or "").strip(),
        (os.environ.get("all_proxy") or "").strip(),
        (os.environ.get("ALL_PROXY") or "").strip(),
    ):
        if cand:
            return cand
    return ""


def proxy_log_label(proxy: str) -> str:
    p = (proxy or "").strip()
    if not p:
        return "(none)"
    try:
        u = urlparse(p if "://" in p else f"http://{p}")
        host = u.hostname or "?"
        port = u.port or ""
        auth = "user:***@" if u.username else ""
        return f"{u.scheme or 'http'}://{auth}{host}{(':' + str(port)) if port else ''}"
    except Exception:
        return "(proxy)"


def _ssl_context() -> ssl.SSLContext | None:
    try:
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return None


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        raise OAuthDeviceError("OAuth endpoint redirect is not allowed")


def _opener(proxy: str | None = None) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [_RejectRedirectHandler()]
    ctx = _ssl_context()
    if ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    p = resolve_proxy(proxy)
    if p:
        handlers.append(urllib.request.ProxyHandler({"http": p, "https": p}))
    return urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()


def _is_transient_net_error(exc: BaseException) -> bool:
    if isinstance(
        exc,
        (
            TimeoutError,
            BrokenPipeError,
            ConnectionResetError,
            ConnectionAbortedError,
            ConnectionRefusedError,
        ),
    ):
        return True
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", None)
        if isinstance(reason, BaseException) and _is_transient_net_error(reason):
            return True
        msg = str(exc).lower()
        needles = (
            "broken pipe",
            "connection reset",
            "connection aborted",
            "timed out",
            "timeout",
            "temporarily unavailable",
            "network is unreachable",
            "name or service not known",
            "unexpected_eof",
            "eof occurred",
            "ssl",
            "handshake",
            "remote end closed",
            "bad gateway",
            "connection refused",
        )
        return any(n in msg for n in needles)
    try:
        if isinstance(exc, ssl.SSLError):
            return True
    except Exception:
        pass
    if isinstance(exc, OSError):
        if getattr(exc, "errno", None) in {32, 104, 110, 111, 113, 101}:
            return True
        msg = str(exc).lower()
        return any(n in msg for n in ("broken pipe", "timed out", "connection reset", "ssl"))
    return False


def _post_form(
    url: str,
    form: dict[str, str],
    timeout: float = 30.0,
    *,
    proxy: str | None = None,
    retries: int = 2,
    retry_sleep: float = 1.0,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[int, dict[str, Any] | str]:
    _validate_oauth_endpoint(url)
    data = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "grok-sso2auth/2.0",
        },
    )
    last: BaseException | None = None
    attempts = max(int(retries), 0) + 1
    for i in range(attempts):
        _check_deadline(deadline, cancel_event)
        opener = _opener(proxy)
        try:
            with opener.open(
                req, timeout=_remaining_timeout(timeout, deadline, cancel_event)
            ) as resp:
                body = _read_limited(
                    resp,
                    label="OAuth response",
                    deadline=deadline,
                    cancel_event=cancel_event,
                ).decode(
                    "utf-8", errors="replace"
                )
                status = getattr(resp, "status", 200) or 200
                try:
                    return int(status), json.loads(body)
                except json.JSONDecodeError:
                    return int(status), body
        except urllib.error.HTTPError as e:
            body = _read_limited(
                e,
                label="OAuth error response",
                deadline=deadline,
                cancel_event=cancel_event,
            ).decode(
                "utf-8", errors="replace"
            )
            try:
                return int(e.code), json.loads(body)
            except json.JSONDecodeError:
                return int(e.code), body
        except ConversionDeadlineExceeded:
            raise
        except BaseException as e:  # noqa: BLE001
            last = e
            if not _is_transient_net_error(e) or i + 1 >= attempts:
                raise
            _cooperative_sleep(retry_sleep * (i + 1), deadline, cancel_event)
    assert last is not None
    raise last


# ---------------------------------------------------------------------------
# OAuth device flow (stdlib, with proxy/retry)
# ---------------------------------------------------------------------------

@dataclass
class DeviceCodeSession:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


class OAuthDeviceError(RuntimeError):
    pass


class ProtocolMintError(RuntimeError):
    """Protocol path failed for one SSO."""


class RateLimitedError(ProtocolMintError):
    """xAI rate limited this device flow attempt; caller should retry."""


def _validate_xai_url(raw: str, *, device_path: bool = False) -> str:
    """Return a normalized x.ai HTTPS URL or reject it before any request."""
    value = str(raw or "").strip()
    try:
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise OAuthDeviceError("untrusted x.ai URL") from exc
    if (
        parsed.scheme.lower() != "https"
        or not host
        or host not in {"accounts.x.ai", "auth.x.ai"}
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
    ):
        raise OAuthDeviceError("untrusted x.ai URL")
    if device_path and not (parsed.path or "/").startswith("/oauth2/device"):
        raise OAuthDeviceError("unexpected device verification path")
    return value


def _validate_oauth_endpoint(raw: str) -> str:
    value = _validate_xai_url(raw)
    parsed = urlparse(value)
    if (parsed.hostname or "").lower().rstrip(".") != "auth.x.ai":
        raise OAuthDeviceError("OAuth endpoint host is not allowed")
    if parsed.path not in {"/oauth2/device/code", "/oauth2/token"} or parsed.query or parsed.fragment:
        raise OAuthDeviceError("OAuth endpoint path is not allowed")
    return value


def _close_response(response: Any) -> None:
    close = getattr(response, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


def _consume_curl_response(
    response: Any,
    *,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> None:
    _check_deadline(deadline, cancel_event)
    headers = getattr(response, "headers", {}) or {}
    length = headers.get("Content-Length") or headers.get("content-length")
    if length:
        try:
            if int(length) > HARD_MAX_UPSTREAM_RESPONSE_BYTES:
                _close_response(response)
                raise OAuthDeviceError(
                    f"x.ai response exceeds {HARD_MAX_UPSTREAM_RESPONSE_BYTES} bytes"
                )
        except ValueError:
            pass

    iterator = getattr(response, "iter_content", None)
    if callable(iterator):
        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in iterator():
                _check_deadline(deadline, cancel_event)
                if not chunk:
                    continue
                raw = bytes(chunk)
                total += len(raw)
                if total > HARD_MAX_UPSTREAM_RESPONSE_BYTES:
                    raise OAuthDeviceError(
                        f"x.ai response exceeds {HARD_MAX_UPSTREAM_RESPONSE_BYTES} bytes"
                    )
                chunks.append(raw)
                _check_deadline(deadline, cancel_event)
        except Exception:
            _close_response(response)
            raise
        body = b"".join(chunks)
    else:
        content = getattr(response, "content", None)
        if content is None:
            text_value = getattr(response, "text", "") or ""
            body = str(text_value).encode("utf-8", errors="replace")
        elif isinstance(content, bytes):
            body = content
        else:
            body = bytes(content)
        _check_deadline(deadline, cancel_event)
        if len(body) > HARD_MAX_UPSTREAM_RESPONSE_BYTES:
            _close_response(response)
            raise OAuthDeviceError(
                f"x.ai response exceeds {HARD_MAX_UPSTREAM_RESPONSE_BYTES} bytes"
            )
    try:
        response.content = body
        if hasattr(response, "_text"):
            del response._text
    except Exception:
        pass


def _request_xai(
    session: Any,
    method: str,
    url: str,
    *,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
    **kwargs: Any,
) -> Any:
    """Perform a request while validating every redirect before following it."""
    current = _validate_xai_url(url)
    current_method = method.upper()
    request_kwargs = dict(kwargs)
    request_kwargs.pop("allow_redirects", None)
    request_kwargs.pop("stream", None)
    configured_timeout = float(request_kwargs.pop("timeout", 30.0))
    for _ in range(8):
        _check_deadline(deadline, cancel_event)
        chunks: list[bytes] = []
        received = 0
        callback_used = False
        response_too_large = False
        callback_deadline = False

        def receive(chunk: bytes) -> int:
            nonlocal received, callback_used, response_too_large, callback_deadline
            callback_used = True
            try:
                _check_deadline(deadline, cancel_event)
            except ConversionDeadlineExceeded:
                callback_deadline = True
                return 0
            raw = bytes(chunk)
            received += len(raw)
            if received > HARD_MAX_UPSTREAM_RESPONSE_BYTES:
                response_too_large = True
                return 0
            chunks.append(raw)
            return len(raw)

        try:
            # curl_cffi treats a streaming timeout as connect/low-speed only.
            # A synchronous request sets libcurl TIMEOUT_MS, so slow response
            # headers and bodies are both bounded by the absolute item deadline.
            # The callback avoids buffering an oversized body before Python can
            # enforce HARD_MAX_UPSTREAM_RESPONSE_BYTES.
            response = session.request(
                current_method,
                current,
                allow_redirects=False,
                stream=False,
                content_callback=receive,
                timeout=_remaining_timeout(configured_timeout, deadline, cancel_event),
                **request_kwargs,
            )
        except Exception as exc:
            if response_too_large:
                raise OAuthDeviceError(
                    f"x.ai response exceeds {HARD_MAX_UPSTREAM_RESPONSE_BYTES} bytes"
                ) from exc
            if callback_deadline or (cancel_event is not None and cancel_event.is_set()) or (
                deadline is not None and time.monotonic() >= deadline
            ):
                raise ConversionDeadlineExceeded("conversion deadline exceeded") from exc
            raise
        if callback_used:
            body = b"".join(chunks)
            try:
                response.content = body
                if hasattr(response, "_text"):
                    del response._text
            except Exception:
                pass
        try:
            _check_deadline(deadline, cancel_event)
        except Exception:
            _close_response(response)
            raise
        final_url = getattr(response, "url", "") or current
        try:
            _validate_xai_url(final_url)
        except Exception:
            _close_response(response)
            raise
        status = int(getattr(response, "status_code", 0) or 0)
        if status not in (301, 302, 303, 307, 308):
            if not callback_used:
                _consume_curl_response(
                    response, deadline=deadline, cancel_event=cancel_event
                )
            return response
        headers = getattr(response, "headers", {}) or {}
        location = headers.get("Location") or headers.get("location")
        if not location:
            if not callback_used:
                _consume_curl_response(
                    response, deadline=deadline, cancel_event=cancel_event
                )
            return response
        next_url = _validate_xai_url(urljoin(final_url, str(location)))
        _close_response(response)
        current = next_url
        if status == 303 or (status in (301, 302) and current_method == "POST"):
            current_method = "GET"
            request_kwargs.pop("data", None)
            request_kwargs.pop("json", None)
    raise OAuthDeviceError("too many x.ai redirects")


def request_device_code(
    *,
    timeout: float = 30.0,
    proxy: str | None = None,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> DeviceCodeSession:
    status, body = _post_form(
        DEVICE_CODE_URL,
        {"client_id": CLIENT_ID, "scope": SCOPES},
        timeout=timeout,
        proxy=proxy,
        retries=2,
        retry_sleep=1.0,
        deadline=deadline,
        cancel_event=cancel_event,
    )
    if status != 200 or not isinstance(body, dict):
        raise OAuthDeviceError(f"device code HTTP {status}: {body!r}")
    device_code = str(body.get("device_code") or "").strip()
    user_code = str(body.get("user_code") or "").strip()
    if not device_code or not user_code:
        raise OAuthDeviceError(f"device code missing fields: {body}")
    vuri = str(body.get("verification_uri") or "https://accounts.x.ai/oauth2/device").strip()
    vcomplete = str(
        body.get("verification_uri_complete") or f"{vuri}?user_code={user_code}"
    ).strip()
    try:
        vuri = _validate_xai_url(vuri, device_path=True)
        vcomplete = _validate_xai_url(vcomplete, device_path=True)
    except OAuthDeviceError as exc:
        raise OAuthDeviceError("device code returned an untrusted verification URL") from exc
    return DeviceCodeSession(
        device_code=device_code,
        user_code=user_code,
        verification_uri=vuri,
        verification_uri_complete=vcomplete,
        expires_in=int(body.get("expires_in") or 1800),
        interval=max(int(body.get("interval") or 5), 1),
    )


def poll_device_token(
    device_code: str,
    *,
    interval: int = 5,
    expires_in: float = 1800,
    timeout: float = 30.0,
    proxy: str | None = None,
    log_fn: Callable[[str], None] | None = None,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Poll token endpoint. First attempt is immediate (no pre-sleep)."""
    _log = log_fn or (lambda _: None)
    # expires_in is the caller's effective polling budget, which may be much
    # shorter than the device code lifetime. Respect sub-30-second operational
    # limits instead of silently pinning every worker for at least 30 seconds.
    poll_deadline = time.monotonic() + max(float(expires_in), 0.1)
    if deadline is not None:
        poll_deadline = min(poll_deadline, deadline)
    sleep_for = max(int(interval), 1)
    net_streak = 0
    max_net_streak = 20
    first = True

    while time.monotonic() < poll_deadline:
        _check_deadline(deadline, cancel_event)
        if not first:
            _cooperative_sleep(sleep_for, poll_deadline, cancel_event)
        first = False

        try:
            status, body = _post_form(
                TOKEN_URL,
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": CLIENT_ID,
                },
                timeout=timeout,
                proxy=proxy,
                retries=2,
                retry_sleep=1.0,
                deadline=poll_deadline,
                cancel_event=cancel_event,
            )
            net_streak = 0
        except BaseException as e:  # noqa: BLE001
            if not _is_transient_net_error(e):
                raise
            net_streak += 1
            wait = min(sleep_for + min(net_streak, 5), 20)
            _log(f"  poll network blip ({net_streak}/{max_net_streak}): {e}")
            if net_streak >= max_net_streak:
                raise OAuthDeviceError(f"poll aborted after {net_streak} network errors: {e}") from e
            _cooperative_sleep(wait, poll_deadline, cancel_event)
            first = True  # already slept
            continue

        if status == 200 and isinstance(body, dict) and body.get("access_token"):
            return body

        err = ""
        desc = ""
        if isinstance(body, dict):
            err = str(body.get("error") or "")
            desc = str(body.get("error_description") or "")

        if err in ("authorization_pending", "slow_down"):
            if err == "slow_down":
                sleep_for = min(sleep_for + 5, 30)
            continue
        if err in ("expired_token", "access_denied"):
            raise OAuthDeviceError(f"device auth failed: {err}: {desc}")
        if status == 400 and err:
            raise OAuthDeviceError(f"token error: {err}: {desc or body}")
        if status >= 500 or not isinstance(body, dict):
            net_streak += 1
            sleep_for = min(sleep_for + 2, 20)
            _log(f"  poll soft HTTP {status}")
            if net_streak >= max_net_streak:
                raise OAuthDeviceError(f"poll aborted soft HTTP status={status}")
            continue
        raise OAuthDeviceError(f"unexpected token response HTTP {status}: {body!r}")

    raise OAuthDeviceError("device auth timed out waiting for approval")


# ---------------------------------------------------------------------------
# Protocol mint: SSO cookie → tokens (curl_cffi Chrome TLS)
# ---------------------------------------------------------------------------

def _make_session(proxy: str | None):
    if cf_requests is None:
        raise ProtocolMintError("curl_cffi not installed; pip install curl_cffi")
    s = cf_requests.Session()
    p = resolve_proxy(proxy)
    if p:
        s.proxies = {"http": p, "https": p}
    return s


def _set_sso_cookie(session: Any, sso_cookie: str) -> None:
    sso_cookie = (sso_cookie or "").strip()
    if not sso_cookie:
        raise ProtocolMintError("empty sso cookie")
    for domain in (".x.ai", "accounts.x.ai", "auth.x.ai", ".accounts.x.ai"):
        try:
            session.cookies.set("sso", sso_cookie, domain=domain)
        except Exception:
            try:
                session.cookies.set("sso", sso_cookie, domain=domain, path="/")
            except Exception:
                pass
        try:
            session.cookies.set("sso-rw", sso_cookie, domain=domain)
        except Exception:
            pass


def _url_path(url: str) -> str:
    try:
        return urlparse(url or "").path or ""
    except Exception:
        return url or ""


def _looks_rate_limited(url: str = "", body: str = "", status: int = 0) -> bool:
    """Detect xAI rate limit. Prefer URL query/error params over page body.

    Done/success pages must not be treated as rate-limited even if HTML
    contains unrelated 'rate' wording.
    """
    if status == 429:
        return True
    u = (url or "").lower()
    # Success markers win
    if "device/done" in u or u.rstrip("/").endswith("/done") or "error=" not in u and "/done" in u:
        # still allow explicit error=rate_limited in query
        if "error=rate_limited" not in u and "error=rate%20limited" not in u:
            return False
    # Query/path explicit error
    if "error=rate_limited" in u or "error=rate%20limited" in u or "rate_limited" in u:
        return True
    # Body only when short / JSON-ish — avoid matching marketing HTML
    b = (body or "").strip().lower()
    if not b:
        return False
    if len(b) < 500 and ("rate_limited" in b or '"error":"rate' in b or "too many requests" in b):
        return True
    return False



def configure_device_flow_limit(concurrency: int = 2, gap: float = 0.4) -> None:
    """Configure global throttle for verify+approve critical path."""
    global _device_flow_sem, _device_flow_gap, _device_flow_last
    conc = max(int(concurrency), 1)
    _device_flow_sem = threading.Semaphore(conc)
    _device_flow_gap = max(float(gap), 0.0)
    _device_flow_last = 0.0


def _acquire_device_flow(
    deadline: float | None = None, cancel_event: threading.Event | None = None
) -> None:
    global _device_flow_last
    sem = _device_flow_sem
    acquired_sem = False
    try:
        if sem is not None:
            while not acquired_sem:
                _check_deadline(deadline, cancel_event)
                wait = 0.1
                if deadline is not None:
                    wait = min(wait, max(deadline - time.monotonic(), 0.001))
                acquired_sem = sem.acquire(timeout=wait)
        if _device_flow_gap > 0:
            acquired_gate = False
            try:
                while not acquired_gate:
                    _check_deadline(deadline, cancel_event)
                    acquired_gate = _device_flow_gate.acquire(timeout=0.1)
                now = time.monotonic()
                wait = _device_flow_last + _device_flow_gap - now
                if wait > 0:
                    _cooperative_sleep(wait, deadline, cancel_event)
                _device_flow_last = time.monotonic()
            finally:
                if acquired_gate:
                    _device_flow_gate.release()
    except BaseException:
        if acquired_sem and sem is not None:
            sem.release()
        raise


def _release_device_flow() -> None:
    sem = _device_flow_sem
    if sem is not None:
        sem.release()


def sso_to_token_once(
    sso_cookie: str,
    *,
    proxy: str | None = None,
    timeout: float = 30.0,
    poll_timeout_sec: float = 90.0,
    log_fn: Callable[[str], None] | None = None,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Single attempt: SSO cookie → OIDC token dict."""
    _log = log_fn or (lambda _: None)
    sso_cookie = (sso_cookie or "").strip()
    if not sso_cookie:
        raise ProtocolMintError("missing sso cookie")
    _check_deadline(deadline, cancel_event)

    session = _make_session(proxy)
    _set_sso_cookie(session, sso_cookie)

    # 1) Validate SSO
    try:
        r = _request_xai(
            session,
            "GET",
            "https://accounts.x.ai/",
            impersonate="chrome",
            timeout=timeout,
            deadline=deadline,
            cancel_event=cancel_event,
        )
    except Exception as e:  # noqa: BLE001
        raise ProtocolMintError(f"accounts.x.ai network error: {e}") from e

    final_url = getattr(r, "url", "") or ""
    if "sign-in" in final_url or "sign-up" in final_url:
        raise ProtocolMintError(f"sso invalid (landed {final_url[:120]})")
    _log("  ✅ sso 有效")

    # 2) Device code
    try:
        sess = request_device_code(
            proxy=proxy,
            timeout=timeout,
            deadline=deadline,
            cancel_event=cancel_event,
        )
    except OAuthDeviceError as e:
        raise ProtocolMintError(f"device code: {e}") from e
    except Exception as e:  # noqa: BLE001
        raise ProtocolMintError(f"device code: {e}") from e
    _log(f"  📋 user_code: {sess.user_code}")

    # 3-5) verify + approve 走全局节流，降低 IP 级 rate_limited
    _acquire_device_flow(deadline, cancel_event)
    try:
        # 3) Open verification URI
        try:
            r = _request_xai(
                session,
                "GET",
                sess.verification_uri_complete,
                impersonate="chrome",
                timeout=timeout,
                deadline=deadline,
                cancel_event=cancel_event,
            )
        except Exception as e:  # noqa: BLE001
            raise ProtocolMintError(f"verification_uri get failed: {e}") from e

        verify_get_url = getattr(r, "url", "") or ""
        try:
            verify_get_body = (r.text or "")[:300]
        except Exception:
            verify_get_body = ""
        if _looks_rate_limited(verify_get_url, verify_get_body, getattr(r, "status_code", 0)):
            raise RateLimitedError(f"rate_limited on verification_uri: {verify_get_url[:160]}")

        # 4) POST device/verify
        try:
            r = _request_xai(
                session,
                "POST",
                VERIFY_URL,
                data={"user_code": sess.user_code},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                impersonate="chrome",
                timeout=timeout,
                deadline=deadline,
                cancel_event=cancel_event,
            )
        except Exception as e:  # noqa: BLE001
            raise ProtocolMintError(f"device/verify exception: {e}") from e

        verify_url = getattr(r, "url", "") or ""
        status = getattr(r, "status_code", 0)
        path = _url_path(verify_url)
        try:
            body_snip = (r.text or "")[:300]
        except Exception:
            body_snip = ""

        if _looks_rate_limited(verify_url, body_snip, status):
            raise RateLimitedError(f"rate_limited on device/verify: {verify_url[:160]}")

        if "consent" not in verify_url and "consent" not in path:
            soft_ok = (
                "consent" in (body_snip or "").lower()
                or "authorize grok build" in (body_snip or "").lower()
                or "授权 grok build" in (body_snip or "").lower()
            )
            if not soft_ok:
                raise ProtocolMintError(
                    f"device/verify failed status={status} url={verify_url[:160]}"
                )
        _log("  ✅ verify ok")

        # 5) POST device/approve
        try:
            r = _request_xai(
                session,
                "POST",
                APPROVE_URL,
                data={
                    "user_code": sess.user_code,
                    "action": "allow",
                    "principal_type": "User",
                    "principal_id": "",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                impersonate="chrome",
                timeout=timeout,
                deadline=deadline,
                cancel_event=cancel_event,
            )
        except Exception as e:  # noqa: BLE001
            raise ProtocolMintError(f"device/approve exception: {e}") from e

        approve_url = getattr(r, "url", "") or ""
        status = getattr(r, "status_code", 0)
        try:
            approve_body = r.text or ""
        except Exception:
            approve_body = ""

        if _looks_rate_limited(approve_url, approve_body, status):
            raise RateLimitedError(f"rate_limited on device/approve: {approve_url[:160]}")

        if "done" not in approve_url and "device/done" not in _url_path(approve_url):
            if (
                "设备已授权" not in approve_body
                and "device authorized" not in approve_body.lower()
                and "done" not in approve_body.lower()
            ):
                raise ProtocolMintError(
                    f"device/approve failed status={status} url={approve_url[:160]}"
                )
        _log("  ✅ 授权确认")
    finally:
        _release_device_flow()

    # 6) Poll tokens (first attempt immediate — approve just finished)
    poll_expires = min(float(sess.expires_in), max(float(poll_timeout_sec), 0.1))
    try:
        token = poll_device_token(
            sess.device_code,
            interval=max(int(sess.interval), 2),
            expires_in=poll_expires,
            timeout=timeout,
            proxy=proxy,
            log_fn=_log,
            deadline=deadline,
            cancel_event=cancel_event,
        )
    except OAuthDeviceError as e:
        raise ProtocolMintError(f"token poll: {e}") from e
    except Exception as e:  # noqa: BLE001
        raise ProtocolMintError(f"token poll: {e}") from e

    _log(
        f"  ✅ access_token (expires_in={token.get('expires_in')}s)"
        + (" + refresh_token" if token.get("refresh_token") else "")
    )
    return token


def sso_to_token(
    sso_cookie: str,
    *,
    proxy: str | None = None,
    timeout: float = 30.0,
    poll_timeout_sec: float = 90.0,
    max_retries: int = 3,
    log_fn: Callable[[str], None] | None = None,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """SSO → token, with retries on rate_limited / transient network errors."""
    _log = log_fn or (lambda _: None)
    last_err: Exception | None = None
    for attempt in range(1, max_retries + 1):
        _check_deadline(deadline, cancel_event)
        try:
            return sso_to_token_once(
                sso_cookie,
                proxy=proxy,
                timeout=timeout,
                poll_timeout_sec=poll_timeout_sec,
                log_fn=_log,
                deadline=deadline,
                cancel_event=cancel_event,
            )
        except RateLimitedError as e:
            last_err = e
            # 指数退避 + 抖动，避免所有 worker 同时重试
            wait = min(2 ** attempt + (secrets.randbelow(1000) / 1000.0) * attempt, 20)
            if attempt < max_retries:
                _log(f"  ⏳ rate_limited，{wait:.1f}s 后重试 ({attempt}/{max_retries})")
                _cooperative_sleep(wait, deadline, cancel_event)
                continue
            raise
        except ProtocolMintError as e:
            # 网络类可重试；sso invalid 等直接失败
            msg = str(e).lower()
            retriable = any(
                k in msg
                for k in (
                    "network error",
                    "timed out",
                    "timeout",
                    "connection",
                    "ssl",
                    "eof",
                    "broken pipe",
                    "device code:",
                    "token poll:",
                )
            )
            if not retriable or attempt >= max_retries:
                raise
            last_err = e
            wait = min(1.5 * attempt, 8)
            _log(f"  ⏳ 瞬时错误，{wait:.1f}s 后重试 ({attempt}/{max_retries}): {e}")
            _cooperative_sleep(wait, deadline, cancel_event)
    assert last_err is not None
    raise last_err


# ---------------------------------------------------------------------------
# auth.json entry
# ---------------------------------------------------------------------------

def token_to_auth_entry(token: dict, email: str = "") -> tuple[str, dict]:
    access = token.get("access_token") or token.get("key") or ""
    refresh = token.get("refresh_token") or ""
    payload = decode_jwt_payload(access)

    user_id = payload.get("sub") or payload.get("principal_id") or ""
    principal_id = payload.get("principal_id") or user_id
    principal_type = payload.get("principal_type") or "User"

    expires_in = int(token.get("expires_in") or 21600)
    if "exp" in payload:
        expires_at = rfc3339_ns(float(payload["exp"]))
    else:
        expires_at = rfc3339_ns(time.time() + expires_in)

    iat = payload.get("iat")
    create_time = rfc3339_ns(float(iat) if iat else time.time())

    entry = {
        "key": access,
        "auth_mode": "oidc",
        "create_time": create_time,
        "user_id": user_id,
        "email": email or "",
        "principal_type": principal_type,
        "principal_id": principal_id,
        "refresh_token": refresh,
        "expires_at": expires_at,
        "oidc_issuer": OIDC_ISSUER,
        "oidc_client_id": CLIENT_ID,
    }
    return AUTH_KEY, entry


@dataclass(frozen=True)
class ConversionItem:
    sso: str
    email: str = ""
    source: str = ""


def _conversion_error(index: int, source: str, code: str, message: str) -> dict[str, Any]:
    return {
        "index": index,
        "source": source,
        "ok": False,
        "error": {"code": code, "message": message},
    }


def _parse_conversion_item(
    raw: Any,
    index: int,
    *,
    max_sso_length: int,
    max_email_length: int,
    max_source_length: int,
) -> tuple[ConversionItem | None, dict[str, Any] | None]:
    if not isinstance(raw, dict):
        return None, _conversion_error(index, "", "invalid_item", "item must be an object")

    unknown = set(raw) - {"sso", "email", "source"}
    source_value = raw.get("source", "")
    source = source_value.strip() if isinstance(source_value, str) else ""
    if unknown:
        return None, _conversion_error(
            index, source, "invalid_item", "item contains unsupported fields"
        )

    sso_value = raw.get("sso")
    email_value = raw.get("email", "")
    if not isinstance(sso_value, str) or not sso_value.strip():
        return None, _conversion_error(index, source, "invalid_item", "sso is required")
    if not isinstance(email_value, str):
        return None, _conversion_error(index, source, "invalid_item", "email must be a string")
    if not isinstance(source_value, str):
        return None, _conversion_error(index, "", "invalid_item", "source must be a string")

    sso = sso_value.strip()
    email = email_value.strip()
    if len(sso) > max_sso_length:
        return None, _conversion_error(index, source, "invalid_item", "sso is too long")
    if len(email) > max_email_length:
        return None, _conversion_error(index, source, "invalid_item", "email is too long")
    if len(source) > max_source_length:
        return None, _conversion_error(index, "", "invalid_item", "source is too long")
    return ConversionItem(sso=sso, email=email, source=source), None


def _mint_conversion_item(
    index: int,
    item: ConversionItem,
    *,
    mint_fn: Callable[..., dict[str, Any]],
    proxy: str | None,
    network_timeout: float,
    poll_timeout: float,
    max_retries: int,
    deadline: float,
    cancel_event: threading.Event,
) -> dict[str, Any]:
    _check_deadline(deadline, cancel_event)
    kwargs: dict[str, Any] = {
        "proxy": proxy,
        "timeout": _remaining_timeout(network_timeout, deadline, cancel_event),
        "poll_timeout_sec": min(poll_timeout, max(deadline - time.monotonic(), 0.1)),
        "max_retries": max_retries,
        "log_fn": lambda _: None,
    }
    try:
        signature = inspect.signature(mint_fn)
        accepts_kwargs = any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        )
        if accepts_kwargs or "deadline" in signature.parameters:
            kwargs["deadline"] = deadline
        if accepts_kwargs or "cancel_event" in signature.parameters:
            kwargs["cancel_event"] = cancel_event
    except (TypeError, ValueError):
        pass
    token = mint_fn(item.sso, **kwargs)
    _check_deadline(deadline, cancel_event)
    if not isinstance(token, dict):
        raise ProtocolMintError("mint returned a non-object token")
    auth_key, entry = token_to_auth_entry(token, email=item.email)
    if not entry.get("key") and not entry.get("refresh_token"):
        raise ProtocolMintError("mint returned no usable token")
    user_id = str(entry.get("user_id") or "").strip()
    source_key = item.source or (f"{auth_key}::{user_id}" if user_id else auth_key)
    credential = {"source_key": source_key, **entry}
    return {
        "index": index,
        "source": item.source,
        "ok": True,
        "credential": credential,
    }


def convert_sso_batch(
    items: list[Any],
    *,
    mint_fn: Callable[..., dict[str, Any]] = sso_to_token,
    proxy: str | None = None,
    workers: int = 4,
    item_timeout: float = 120.0,
    network_timeout: float = 30.0,
    poll_timeout: float = 90.0,
    max_retries: int = 3,
    max_items: int = DEFAULT_MAX_BATCH_ITEMS,
    max_sso_length: int = DEFAULT_MAX_SSO_LENGTH,
    max_email_length: int = DEFAULT_MAX_EMAIL_LENGTH,
    max_source_length: int = DEFAULT_MAX_SOURCE_LENGTH,
    executor: Executor | None = None,
) -> list[dict[str, Any]]:
    """Convert SSO items entirely in memory, preserving input order.

    This function never reads or writes credential/failed files and never includes
    the input SSO value in its results. Callers may inject ``mint_fn`` and a shared
    executor, which makes it suitable for both tests and a bounded HTTP service.
    """
    if not isinstance(items, list):
        raise ValueError("items must be a list")
    if not items:
        raise ValueError("items must not be empty")
    max_items = max(1, min(int(max_items), HARD_MAX_BATCH_ITEMS))
    if len(items) > max_items:
        raise ValueError(f"items exceeds limit of {max_items}")
    workers = max(1, min(int(workers), HARD_MAX_WORKERS, len(items)))
    item_timeout = float(item_timeout)
    if not 0 < item_timeout <= HARD_MAX_ITEM_TIMEOUT:
        raise ValueError(f"item_timeout must be between 0 and {HARD_MAX_ITEM_TIMEOUT:g}")
    network_timeout = max(0.1, min(float(network_timeout), item_timeout))
    poll_timeout = max(0.1, min(float(poll_timeout), item_timeout))
    max_retries = max(1, int(max_retries))

    results: list[dict[str, Any] | None] = [None] * len(items)
    parsed: list[tuple[int, ConversionItem]] = []
    for index, raw in enumerate(items):
        item, error = _parse_conversion_item(
            raw,
            index,
            max_sso_length=max_sso_length,
            max_email_length=max_email_length,
            max_source_length=max_source_length,
        )
        if error is not None:
            results[index] = error
        elif item is not None:
            parsed.append((index, item))

    owned_executor = executor is None
    pool = executor or ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sso-convert")
    futures: list[tuple[int, str, float, threading.Event, Future[dict[str, Any]]]] = []
    try:
        for index, item in parsed:
            deadline = time.monotonic() + item_timeout
            cancel_event = threading.Event()
            future = pool.submit(
                _mint_conversion_item,
                index,
                item,
                mint_fn=mint_fn,
                proxy=proxy,
                network_timeout=network_timeout,
                poll_timeout=poll_timeout,
                max_retries=max_retries,
                deadline=deadline,
                cancel_event=cancel_event,
            )
            futures.append((index, item.source, deadline, cancel_event, future))

        for index, source, deadline, cancel_event, future in futures:
            try:
                results[index] = future.result(timeout=max(0.0, deadline - time.monotonic()))
            except FutureTimeoutError:
                cancel_event.set()
                future.cancel()
                results[index] = _conversion_error(
                    index, source, "timeout", "conversion exceeded the item timeout"
                )
            except ConversionDeadlineExceeded:
                results[index] = _conversion_error(
                    index, source, "timeout", "conversion exceeded the item timeout"
                )
            except Exception:  # noqa: BLE001
                results[index] = _conversion_error(
                    index, source, "conversion_failed", "SSO conversion failed"
                )
    finally:
        if owned_executor:
            assert isinstance(pool, ThreadPoolExecutor)
            pool.shutdown(wait=False, cancel_futures=True)

    return [result for result in results if result is not None]


def write_auth_json(path: Path, auth_key: str, entry: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {auth_key: entry}
    tmp = path.with_suffix(path.suffix + ".tmp")
    with _write_lock:
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(tmp, path)


def merge_auth_json(path: Path, auth_key: str, entry: dict, unique: bool = True) -> None:
    """合并写入。unique=True 时 key 变成 issuer::client_id::user_id。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    key = auth_key
    if unique and entry.get("user_id"):
        key = f"{auth_key}::{entry['user_id']}"
    with _write_lock:
        existing: dict = {}
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        existing[key] = entry
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(tmp, path)


def append_failed(path: Path, sso: str) -> None:
    """失败 SSO 追加一行，线程安全。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with _write_lock:
        with path.open("a", encoding="utf-8") as f:
            f.write(sso.strip() + "\n")


def load_sso_list(path: str | None, single: str | None) -> list[str]:
    if single:
        return [single.strip()]
    if not path:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 兼容 邮箱----密码----sso
        if "----" in line:
            parts = line.split("----")
            line = parts[-1].strip()
        if not line or line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


# ---------------------------------------------------------------------------
# worker
# ---------------------------------------------------------------------------

@dataclass
class WorkResult:
    index: int
    sso: str
    ok: bool
    user_id: str = ""
    error: str = ""


def process_one(
    index: int,
    total: int,
    sso: str,
    *,
    out: str | None,
    out_dir: str | None,
    merge: bool,
    email: str,
    proxy: str | None,
    poll_timeout: float,
    multi: bool,
    max_retries: int,
    stagger: float,
) -> WorkResult:
    tag = f"[{index}/{total}]"
    # 错峰启动，降低 rate_limited
    if stagger > 0 and index > 1:
        time.sleep(stagger * ((index - 1) % 8))

    log(f"\n{'=' * 60}\n{tag} 开始\n{'=' * 60}")

    def _log(msg: str) -> None:
        log(f"{tag}{msg}" if msg.startswith("  ") else f"{tag} {msg}")

    try:
        token = sso_to_token(
            sso,
            proxy=proxy,
            poll_timeout_sec=poll_timeout,
            max_retries=max_retries,
            log_fn=_log,
        )
        key, entry = token_to_auth_entry(token, email=email)
        uid = entry.get("user_id") or secrets.token_hex(4)

        if out_dir:
            p = Path(out_dir) / f"{uid}.json"
            write_auth_json(p, key, entry)
            _log(f"  💾 {p}")
        if out:
            if merge or multi:
                merge_auth_json(Path(out), key, entry, unique=True)
                _log(f"  💾 merge → {out}")
            else:
                write_auth_json(Path(out), key, entry)
                _log(f"  💾 {out}")

        _log(f"  ✅ 完成 user_id={uid[:16]}...")
        return WorkResult(index=index, sso=sso, ok=True, user_id=uid)
    except ProtocolMintError as e:
        _log(f"  ❌ 失败: {e}")
        return WorkResult(index=index, sso=sso, ok=False, error=str(e))
    except Exception as e:  # noqa: BLE001
        _log(f"  ❌ 异常: {e}")
        return WorkResult(index=index, sso=sso, ok=False, error=str(e))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="SSO cookie → grok auth.json（协议直换 + 并发）"
    )
    ap.add_argument("--sso", metavar="FILE", help="sso 列表文件（一行一个 JWT，或 邮箱----密码----sso）")
    ap.add_argument("--sso-cookie", metavar="JWT", help="单个 sso cookie")
    ap.add_argument("--out", default=None, help="输出 auth.json 路径（单账号或 --merge）")
    ap.add_argument(
        "--out-dir",
        default=None,
        help="批量时每个账号写一个 {user_id}.json",
    )
    ap.add_argument(
        "--merge",
        action="store_true",
        help="合并到 --out，key 用 issuer::client_id::user_id",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=6,
        help="并发数（默认 6；校验/device code 并行，关键路径另受 --flow-concurrency 限制）",
    )
    ap.add_argument(
        "--failed",
        default="failed.txt",
        help="失败 SSO 输出文件，每行一个（默认 failed.txt）",
    )
    ap.add_argument(
        "--no-failed",
        action="store_true",
        help="不写失败文件",
    )
    ap.add_argument("--proxy", default=None, help="代理 URL（默认读 https_proxy 环境变量）")
    ap.add_argument("--poll-timeout", type=float, default=90.0, help="token 轮询超时秒数")
    ap.add_argument(
        "--retries",
        type=int,
        default=3,
        help="单条 SSO 最大尝试次数（含 rate_limited 重试，默认 3）",
    )
    ap.add_argument(
        "--stagger",
        type=float,
        default=0.25,
        help="并发启动错峰秒数（默认 0.25，设 0 关闭）",
    )
    ap.add_argument(
        "--flow-concurrency",
        type=int,
        default=2,
        help="verify+approve 关键路径同时进行的数量（默认 2，防 rate_limited）",
    )
    ap.add_argument(
        "--flow-gap",
        type=float,
        default=0.5,
        help="两次关键路径之间的最小间隔秒数（默认 0.5）",
    )
    ap.add_argument("--delay", type=float, default=0, help="串行模式下每个间隔秒数（workers=1 时）")
    ap.add_argument("--email", default="", help="写入 entry.email（可选）")
    args = ap.parse_args()

    cookies = load_sso_list(args.sso, args.sso_cookie)
    if not cookies:
        ap.error("需要 --sso 或 --sso-cookie")

    multi = len(cookies) > 1
    if multi and not args.out_dir and not args.merge:
        args.out_dir = args.out_dir or "./auth_out"
        log(f"批量模式默认 --out-dir {args.out_dir}")

    if args.out is None and args.out_dir is None and len(cookies) == 1:
        args.out = str(Path.home() / ".grok" / "auth.json")

    proxy = resolve_proxy(args.proxy) or None
    workers = max(int(args.workers), 1)
    if len(cookies) == 1:
        workers = 1

    failed_path: Path | None = None
    if not args.no_failed:
        failed_path = Path(args.failed)
        # 本次运行覆盖写，避免和旧失败混在一起
        if failed_path.exists() and multi:
            failed_path.write_text("", encoding="utf-8")

    # 关键路径并发不宜过高；workers 可以更大（等待/校验可并行）
    flow_conc = max(1, min(workers, int(args.flow_concurrency)))
    configure_device_flow_limit(concurrency=flow_conc, gap=float(args.flow_gap))

    log(
        f"🚀 SSO → auth.json: {len(cookies)} 个, workers={workers}, "
        f"flow_concurrency={flow_conc}, flow_gap={args.flow_gap}s, "
        f"proxy={proxy_log_label(proxy or '')}, poll_timeout={args.poll_timeout}s, "
        f"retries={args.retries}, stagger={args.stagger}s"
    )
    if failed_path:
        log(f"📝 失败将写入: {failed_path}")

    ok = 0
    fail = 0
    t0 = time.time()

    def _run(i: int, sso: str) -> WorkResult:
        if workers == 1 and args.delay > 0 and i > 1:
            time.sleep(args.delay)
        return process_one(
            i,
            len(cookies),
            sso,
            out=args.out,
            out_dir=args.out_dir,
            merge=args.merge,
            email=args.email,
            proxy=proxy,
            poll_timeout=args.poll_timeout,
            multi=multi,
            max_retries=max(int(args.retries), 1),
            stagger=float(args.stagger) if workers > 1 else 0.0,
        )

    results: list[WorkResult] = []
    if workers == 1:
        for i, sso in enumerate(cookies, 1):
            results.append(_run(i, sso))
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {
                ex.submit(_run, i, sso): i
                for i, sso in enumerate(cookies, 1)
            }
            for fut in as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    idx = futs[fut]
                    sso = cookies[idx - 1]
                    log(f"[{idx}/{len(cookies)}] ❌ worker 崩溃: {e}")
                    results.append(WorkResult(index=idx, sso=sso, ok=False, error=str(e)))

    # 按 index 排序后写 failed，保证顺序稳定
    results.sort(key=lambda r: r.index)
    for r in results:
        if r.ok:
            ok += 1
        else:
            fail += 1
            if failed_path is not None:
                append_failed(failed_path, r.sso)

    elapsed = time.time() - t0
    log(
        f"\n{'=' * 60}\n"
        f"📊 完成: {ok}/{len(cookies)} 成功, {fail} 失败, "
        f"耗时 {elapsed:.1f}s ({elapsed / max(len(cookies), 1):.2f}s/个)"
    )
    if fail and failed_path is not None:
        log(f"📝 失败 SSO 已写入 {failed_path}（共 {fail} 行，可直接 --sso {failed_path} 重试）")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
