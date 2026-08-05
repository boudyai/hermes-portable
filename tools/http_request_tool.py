"""Explicit HTTP client tool for the strict operations profile.

The registry is the normal execution boundary and applies the global Telegram
approval.  The public function also checks the exact handler scope so direct
internal callers cannot turn a configured profile into implicit network access.
"""

from __future__ import annotations

import json
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from tools.registry import registry, tool_error

_MAX_RESPONSE_BYTES = 2_000_000
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


def _request_args(
    url: str,
    method: str,
    headers: Mapping[str, Any] | None,
    body: str | bytes | None,
    timeout: float,
) -> dict[str, Any]:
    return {
        "url": url,
        "method": method,
        "headers": dict(headers or {}),
        "body": body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body,
        "timeout": timeout,
    }


def http_request(
    url: str,
    method: str = "GET",
    headers: Mapping[str, Any] | None = None,
    body: str | None = None,
    timeout: float = 30,
    *,
    _approval_args: Mapping[str, Any] | None = None,
    _tool_call_id: str | None = None,
    _session_id: str | None = None,
) -> str:
    """Perform one explicit HTTP(S) request and return a bounded JSON result."""

    normalized_method = str(method or "GET").upper()
    approval_args = dict(_approval_args) if isinstance(_approval_args, Mapping) else _request_args(
        url, normalized_method, headers, body, timeout
    )
    try:
        from tools.strict_approval import ensure_handler_approval

        ensure_handler_approval(
            "http_request",
            approval_args,
            tool_call_id=str(_tool_call_id or ""),
            session_id=str(_session_id or ""),
            conversation_id=str(_session_id or ""),
        )
    except Exception:
        return tool_error(
            "Global approval blocked: security subsystem unavailable or call not approved"
        )

    parsed = urlsplit(str(url))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return tool_error("url must be an absolute http:// or https:// URL")
    if normalized_method not in _METHODS:
        return tool_error(f"unsupported HTTP method: {normalized_method}")
    try:
        timeout_value = float(timeout)
    except (TypeError, ValueError):
        return tool_error("timeout must be a positive number")
    if timeout_value <= 0:
        return tool_error("timeout must be a positive number")

    normalized_headers: dict[str, str] = {}
    for key, value in (headers or {}).items():
        normalized_headers[str(key)] = str(value)
    data = body.encode("utf-8") if isinstance(body, str) else body
    request = Request(
        str(url),
        data=data,
        headers=normalized_headers,
        method=normalized_method,
    )
    try:
        with urlopen(request, timeout=timeout_value) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
            truncated = len(raw) > _MAX_RESPONSE_BYTES
            if truncated:
                raw = raw[:_MAX_RESPONSE_BYTES]
            content = raw.decode("utf-8", errors="replace")
            return json.dumps(
                {
                    "status": int(response.status),
                    "headers": dict(response.headers.items()),
                    "body": content,
                    "truncated": truncated,
                },
                ensure_ascii=False,
            )
    except HTTPError as exc:
        try:
            error_body = exc.read(_MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
        except Exception:
            error_body = ""
        return json.dumps(
            {"status": int(exc.code), "error": str(exc.reason), "body": error_body},
            ensure_ascii=False,
        )
    except (URLError, TimeoutError, OSError) as exc:
        return tool_error(f"HTTP request failed: {exc}")


HTTP_REQUEST_SCHEMA = {
    "name": "http_request",
    "description": "Perform one explicit approved HTTP(S) request and return its response.",
    "parameters": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "default": "GET"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": {"type": "string"},
            "timeout": {"type": "number", "default": 30},
        },
        "required": ["url"],
    },
}


def _handle_http_request(args: dict[str, Any], **kwargs: Any) -> str:
    return http_request(
        url=args.get("url", ""),
        method=args.get("method", "GET"),
        headers=args.get("headers"),
        body=args.get("body"),
        timeout=args.get("timeout", 30),
        _approval_args=dict(args),
        _tool_call_id=kwargs.get("tool_call_id"),
        _session_id=kwargs.get("session_id"),
    )


registry.register(
    name="http_request",
    toolset="ops",
    schema=HTTP_REQUEST_SCHEMA,
    handler=_handle_http_request,
    emoji="🌐",
    max_result_size_chars=2_100_000,
)
