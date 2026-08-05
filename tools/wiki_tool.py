"""Small local operator-wiki toolset.

The wiki is deliberately a filesystem-backed knowledge base under the Hermes
home directory. Path validation prevents traversal and symlink escapes. The
dispatcher applies the global every-tool approval gate to both read and write
operations; this module does not contain an alternate execution path.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from hermes_constants import get_hermes_home
from tools.registry import registry, tool_error


def _wiki_root() -> Path:
    try:
        from hermes_cli.config import load_config_readonly

        cfg = load_config_readonly() or {}
        wiki_cfg = cfg.get("wiki") if isinstance(cfg, dict) else None
        configured = wiki_cfg.get("root") if isinstance(wiki_cfg, dict) else None
    except Exception as exc:
        raise RuntimeError("wiki configuration unavailable") from exc
    # Resolve the implicit root from HERMES_HOME rather than the process
    # user's HOME. This keeps profile/test homes isolated when Hermes is
    # launched with a managed HERMES_HOME override.
    configured_text = str(configured or "").strip()
    root = (
        get_hermes_home() / "wiki"
        if not configured_text or configured_text == "~/.hermes/wiki"
        else Path(configured_text).expanduser()
    )
    return root.resolve()


def _safe_path(path: str) -> Path:
    raw = str(path or "index.md").strip()
    candidate = Path(raw)
    if candidate.is_absolute():
        raise ValueError("wiki path must be relative to the wiki root")
    root = _wiki_root()
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("wiki path escapes the wiki root") from exc
    if resolved.name in {"", ".", ".."}:
        raise ValueError("invalid wiki path")
    return resolved


def wiki_read(
    path: str = "index.md",
    *,
    _approval_args: dict[str, Any] | None = None,
    _tool_call_id: str | None = None,
    _session_id: str | None = None,
) -> str:
    try:
        from tools.strict_approval import ensure_handler_approval

        ensure_handler_approval(
            "wiki_read",
            dict(_approval_args) if isinstance(_approval_args, dict) else {"path": path},
            tool_call_id=str(_tool_call_id or ""),
            session_id=str(_session_id or ""),
            conversation_id=str(_session_id or ""),
        )
    except Exception:
        return tool_error(
            "Global approval blocked: security subsystem unavailable or call not approved",
            success=False,
        )
    target = _safe_path(path)
    if not target.exists():
        return json.dumps({"success": False, "error": "wiki page not found", "path": str(path)}, ensure_ascii=False)
    if not target.is_file():
        return json.dumps({"success": False, "error": "wiki path is not a file", "path": str(path)}, ensure_ascii=False)
    return json.dumps(
        {"success": True, "path": str(path), "content": target.read_text(encoding="utf-8")},
        ensure_ascii=False,
    )


def wiki_write(
    path: str,
    content: str,
    *,
    _approval_args: dict[str, Any] | None = None,
    _tool_call_id: str | None = None,
    _session_id: str | None = None,
) -> str:
    try:
        from tools.strict_approval import ensure_handler_approval

        ensure_handler_approval(
            "wiki_write",
            dict(_approval_args) if isinstance(_approval_args, dict) else {"path": path, "content": content},
            tool_call_id=str(_tool_call_id or ""),
            session_id=str(_session_id or ""),
            conversation_id=str(_session_id or ""),
        )
    except Exception:
        return tool_error(
            "Global approval blocked: security subsystem unavailable or call not approved",
            success=False,
        )
    target = _safe_path(path)
    root = _wiki_root()
    root.mkdir(parents=True, exist_ok=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".wiki-", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(str(content))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return json.dumps({"success": True, "path": str(path), "bytes": len(str(content).encode("utf-8"))}, ensure_ascii=False)


WIKI_READ_SCHEMA = {
    "name": "wiki_read",
    "description": "Read an operator wiki page from the configured Hermes wiki root.",
    "parameters": {
        "type": "object",
        "properties": {"path": {"type": "string", "default": "index.md"}},
        "required": [],
    },
}

WIKI_WRITE_SCHEMA = {
    "name": "wiki_write",
    "description": "Write an operator wiki page under the configured Hermes wiki root.",
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
        },
        "required": ["path", "content"],
    },
}

def _handle_wiki_read(args, **kw):
    return wiki_read(
        args.get("path", "index.md"),
        _approval_args=dict(args) if isinstance(args, dict) else {},
        _tool_call_id=kw.get("tool_call_id"),
        _session_id=kw.get("session_id"),
    )


def _handle_wiki_write(args, **kw):
    return wiki_write(
        args.get("path", ""),
        args.get("content", ""),
        _approval_args=dict(args) if isinstance(args, dict) else {},
        _tool_call_id=kw.get("tool_call_id"),
        _session_id=kw.get("session_id"),
    )


registry.register(
    name="wiki_read",
    toolset="wiki",
    schema=WIKI_READ_SCHEMA,
    handler=_handle_wiki_read,
    emoji="📚",
)
registry.register(
    name="wiki_write",
    toolset="wiki",
    schema=WIKI_WRITE_SCHEMA,
    handler=_handle_wiki_write,
    emoji="📝",
)
