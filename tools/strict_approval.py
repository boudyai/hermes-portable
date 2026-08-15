"""Fail-closed, per-tool Telegram approval for strict approval modes.

In ``every_tool`` mode the decision is always made by the human who owns the
exact Telegram chat/user binding.  ``ops_guarded`` additionally recognizes a
narrow, fail-closed set of observational shell commands and trusted read tools,
notifies the owner, and auto-approves them.  The normal dangerous-command
approval code remains available for legacy modes; the strict path is a separate
narrow waist used by every dispatcher entry point.

The pending row contains the exact canonical payload used for execution.  The
payload is never replaced with its redacted display form.  A local MAC key and
the tool/argument SHA-256 make accidental or tampered argument changes fail
closed before dispatch.
"""

from __future__ import annotations

import contextvars
import hashlib
import hmac
import inspect
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from hermes_constants import get_hermes_home
from tools.codex_shell import is_ops_guarded_codex_command
from tools.readonly_shell import READONLY_SHELL_TOOLS, is_readonly_shell_command

logger = logging.getLogger(__name__)

APPROVAL_MODE = "every_tool"
OPS_GUARDED_MODE = "ops_guarded"
DEFAULT_TIMEOUT_SECONDS = 900
OPS_GUARDED_AUTO_TOOLS = frozenset({
    "clarify",
    "read_file",
    "search_files",
    "session_search",
    "skill_view",
    "skills_list",
    "wiki_read",
})


class StrictApprovalError(RuntimeError):
    """A tool call was denied or the security gate could not operate."""


class StrictApprovalBlocked(StrictApprovalError):
    """The security subsystem failed and execution was blocked."""


@dataclass(frozen=True)
class ApprovedInvocation:
    approval_id: str
    tool_call_id: str
    tool_name: str
    canonical_args: str
    args_hash: str
    args: dict[str, Any]


@dataclass(frozen=True)
class _Notifier:
    callback: Callable[[dict[str, Any]], Any]
    telegram_user_id: str
    telegram_chat_id: str


@dataclass(frozen=True)
class _Pending:
    approval_id: str
    tool_call_id: str
    tool_name: str
    canonical_args: str
    args_hash: str
    session_id: str
    conversation_id: str
    telegram_user_id: str
    telegram_chat_id: str
    created_at: float
    expires_at: float
    payload_mac: str
    decision_mac: str


# This is an execution-only marker.  It is consumed by the nested
# model_tools.dispatch call after the agent-level gate has approved a direct
# special branch.  It never contains a reusable approval decision.
_authorized_call: contextvars.ContextVar[tuple[str, str, str] | None] = contextvars.ContextVar(
    "strict_authorized_call", default=None
)

# Registry handlers run after ``_authorized_call`` has been consumed.  Keep a
# second, shorter-lived marker around the actual handler invocation so a
# handler cannot mistake ``approvals.mode=every_tool`` for proof that *this*
# exact call was approved.  The registry resets this marker in its finally
# block; it is not persisted and cannot approve a later call.
_authorized_execution: contextvars.ContextVar[tuple[str, str, str] | None] = contextvars.ContextVar(
    "strict_authorized_execution", default=None
)

_notifiers_lock = threading.RLock()
_notifiers: dict[str, _Notifier] = {}
_waiters_lock = threading.RLock()
_waiters: dict[str, threading.Event] = {}
_strict_latch_lock = threading.RLock()
_strict_latched_homes: set[str] = set()
_strict_latched_modes: dict[str, str] = {}


def canonical_json(args: Mapping[str, Any] | dict[str, Any]) -> str:
    """Serialize arguments deterministically, rejecting non-JSON values."""

    try:
        return json.dumps(
            dict(args),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise StrictApprovalBlocked("Tool arguments are not canonicalizable") from exc


def arguments_hash(tool_name: str, canonical_args: str) -> str:
    """Hash the exact tool name and canonical argument JSON."""

    material = f"{tool_name}\n{canonical_args}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


_SECRET_KEY_PARTS = (
    "api_key", "apikey", "password", "passwd", "bearer", "authorization",
    "cookie", "private_key", "privatekey", "telegram_token", "bot_token",
    "client_secret", "access_token", "refresh_token", "token", "secret",
    "credential", "connection_string", "connectionstring", "database_url", "dsn",
    "client_key", "signing_key", "encryption_key",
)

_DISPLAY_SECRET_NAME = (
    r"(?:api[-_]?key|apikey|password|passwd|client[-_]?secret|"
    r"access[-_]?token|refresh[-_]?token|telegram[-_]?bot[-_]?token|token|secret)"
)
_DISPLAY_CLI_SECRET_RE = re.compile(
    rf"(?P<prefix>(?:--{_DISPLAY_SECRET_NAME}(?:=|[ \t]+)|"
    rf"\b{_DISPLAY_SECRET_NAME}=))"
    r"(?:(?P<single>'[^']*')|(?P<double>\"[^\"]*\")|(?P<bare>[^\s'\"]+))",
    re.IGNORECASE,
)
_DISPLAY_AUTH_SCHEME_RE = re.compile(
    r"(?P<prefix>\b(?:Bearer|Basic)[ \t]+)"
    r"(?:(?P<single>'[^']*')|(?P<double>\"[^\"]*\")|(?P<bare>[^\s'\"]+))",
    re.IGNORECASE,
)


def _secret_key(key: str) -> bool:
    lowered = str(key).lower().replace("-", "_")
    return any(part in lowered for part in _SECRET_KEY_PARTS)


def _redact_text(text: str) -> str:
    """Redact display-only strings without touching the execution payload."""

    value = str(text)
    try:
        from agent.redact import redact_sensitive_text

        value = redact_sensitive_text(value, force=True)
    except Exception:
        # Never display a possibly sensitive value if the authoritative
        # redactor is unavailable.
        return "[REDACTED]"

    # The authoritative redactor masks credential values while preserving the
    # surrounding command.  Do not replace that useful, already-safe preview
    # with a bare [REDACTED]; if importing or running the redactor fails, the
    # exception path above still fails closed and hides the entire string.
    def _mask_display_match(match: re.Match[str]) -> str:
        quoted = match.group("single") or match.group("double") or ""
        quote = quoted[:1]
        return f"{match.group('prefix')}{quote}[REDACTED]{quote}"

    value = _DISPLAY_CLI_SECRET_RE.sub(_mask_display_match, value)
    value = _DISPLAY_AUTH_SCHEME_RE.sub(_mask_display_match, value)
    if "-----BEGIN " in value and "PRIVATE KEY-----" in value:
        return "[REDACTED PRIVATE KEY]"
    return value


def redact_for_display(value: Any, *, key: str = "") -> Any:
    """Return a recursively redacted copy for Telegram and audit records."""

    if _secret_key(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(k): redact_for_display(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_for_display(v, key=key) for v in value]
    if isinstance(value, tuple):
        return [redact_for_display(v, key=key) for v in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def redacted_args_json(args: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            redact_for_display(args),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
    except Exception:
        return "[REDACTED]"


def _strict_config() -> tuple[bool, float]:
    """Read strict settings; malformed security config fails closed."""

    try:
        from hermes_cli.config import load_config_readonly

        cfg = load_config_readonly()
        approvals = cfg.get("approvals") if isinstance(cfg, Mapping) else None
        if not isinstance(approvals, Mapping):
            raise StrictApprovalBlocked("approvals configuration is unavailable")
        mode = str(approvals.get("mode", "")).strip().lower()
        if mode not in {APPROVAL_MODE, OPS_GUARDED_MODE}:
            # Once this process has observed the secure default for a profile,
            # a tool must not be able to edit config.yaml to ``off`` (or a
            # legacy mode) and then continue issuing unapproved calls.  An
            # operator can still intentionally switch profiles/modes before
            # starting the process; weakening an already-live policy requires
            # a restart and therefore cannot be smuggled through an approved
            # shell/file call.
            profile_home = str(get_hermes_home())
            with _strict_latch_lock:
                if profile_home in _strict_latched_homes:
                    raise StrictApprovalBlocked(
                        "strict approval policy was weakened while the "
                        "process was running; restart is required"
                    )
            return False, 0.0
        timeout_raw = approvals.get("timeout_seconds", approvals.get("timeout", DEFAULT_TIMEOUT_SECONDS))
        timeout = float(timeout_raw)
        if timeout <= 0 or timeout != timeout or timeout == float("inf"):
            raise StrictApprovalBlocked("approvals.timeout_seconds is invalid")
        if approvals.get("allow_session_approval", False) is not False:
            raise StrictApprovalBlocked("session approvals are forbidden in strict approval modes")
        if approvals.get("allow_permanent_approval", False) is not False:
            raise StrictApprovalBlocked("permanent approvals are forbidden in strict approval modes")
        profile_home = str(get_hermes_home())
        with _strict_latch_lock:
            previous_mode = _strict_latched_modes.get(profile_home)
            if previous_mode == APPROVAL_MODE and mode == OPS_GUARDED_MODE:
                raise StrictApprovalBlocked(
                    "every_tool approval policy was weakened to ops_guarded while "
                    "the process was running; restart is required"
                )
            _strict_latched_homes.add(profile_home)
            _strict_latched_modes[profile_home] = mode
        return True, timeout
    except StrictApprovalError:
        raise
    except Exception as exc:
        raise StrictApprovalBlocked("approval configuration could not be loaded") from exc


def strict_mode_enabled() -> bool:
    enabled, _ = _strict_config()
    return enabled


def _ops_guarded_auto_tools(expected_mode: str) -> frozenset[str]:
    """Return the exact auto-authorization set for ``ops_guarded``.

    The configurable list may narrow the built-in set but can never widen it.
    Unknown names therefore cannot turn terminal, plugins, or MCP tools into
    unattended execution paths through a config edit.
    """

    try:
        from hermes_cli.config import load_config_readonly

        cfg = load_config_readonly()
        approvals = cfg.get("approvals") if isinstance(cfg, Mapping) else None
        if not isinstance(approvals, Mapping):
            raise StrictApprovalBlocked("approvals configuration is unavailable")
        current_mode = str(approvals.get("mode", "")).strip().lower()
        if expected_mode != OPS_GUARDED_MODE or current_mode != expected_mode:
            return frozenset()
        configured = approvals.get("auto_approve_tools")
        if configured is None:
            return OPS_GUARDED_AUTO_TOOLS
        if not isinstance(configured, (list, tuple, set, frozenset)):
            raise StrictApprovalBlocked("approvals.auto_approve_tools must be a list")
        names = frozenset(str(name).strip() for name in configured if str(name).strip())
        unsupported = names - OPS_GUARDED_AUTO_TOOLS
        if unsupported:
            raise StrictApprovalBlocked(
                "unsupported ops_guarded auto-approval tools: "
                + ", ".join(sorted(unsupported))
            )
        return names
    except StrictApprovalError:
        raise
    except Exception as exc:
        raise StrictApprovalBlocked("ops_guarded policy could not be loaded") from exc


def register_notifier(
    session_key: str,
    callback: Callable[[dict[str, Any]], Any],
    *,
    telegram_user_id: str,
    telegram_chat_id: str,
) -> None:
    """Register the live Telegram sender for one conversation."""

    if not session_key or not callable(callback):
        raise StrictApprovalBlocked("Telegram approval notifier is invalid")
    with _notifiers_lock:
        _notifiers[str(session_key)] = _Notifier(
            callback=callback,
            telegram_user_id=str(telegram_user_id),
            telegram_chat_id=str(telegram_chat_id),
        )


def unregister_notifier(session_key: str) -> None:
    with _notifiers_lock:
        _notifiers.pop(str(session_key), None)


def _notifier_for(session_key: str) -> _Notifier | None:
    with _notifiers_lock:
        return _notifiers.get(str(session_key))


def _db_path() -> Path:
    return get_hermes_home() / "strict-approvals.sqlite3"


def _mac_key_path() -> Path:
    return get_hermes_home() / "strict-approvals.key"


def _load_mac_key() -> bytes:
    path = _mac_key_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if os.name != "nt":
                mode = stat.S_IMODE(path.stat().st_mode)
                if mode & 0o077:
                    raise StrictApprovalBlocked("approval MAC key permissions are too broad")
            key = path.read_bytes()
            if len(key) != 32:
                raise StrictApprovalBlocked("approval MAC key is damaged")
            return key
        key = secrets.token_bytes(32)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            if os.write(fd, key) != len(key):
                raise StrictApprovalBlocked("approval MAC key could not be written completely")
            if os.name != "nt":
                os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        return key
    except FileExistsError:
        return _load_mac_key()
    except StrictApprovalError:
        raise
    except Exception as exc:
        raise StrictApprovalBlocked("approval MAC key is unavailable") from exc


def _payload_mac(key: bytes, pending: Mapping[str, Any]) -> str:
    material = "\x00".join(
        str(pending[name])
        for name in (
            "approval_id", "tool_call_id", "tool_name", "canonical_args", "args_hash",
            "session_id", "conversation_id", "telegram_user_id", "telegram_chat_id",
            "created_at", "expires_at",
        )
    ).encode("utf-8")
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def _decision_mac(key: bytes, pending: Mapping[str, Any], status: str) -> str:
    """Authenticate the mutable state transition without changing payload."""

    material = "\x00".join(
        str(pending[name])
        for name in ("approval_id", "payload_mac")
    ) + f"\x00{status}"
    return hmac.new(key, material.encode("utf-8"), hashlib.sha256).hexdigest()


def _verify_decision_mac(key: bytes, pending: Mapping[str, Any], status: str) -> None:
    expected = _decision_mac(key, pending, status)
    try:
        actual = pending["decision_mac"]
    except (KeyError, IndexError):
        actual = ""
    if not hmac.compare_digest(expected, str(actual)):
        raise StrictApprovalBlocked("approval state integrity check failed")


class ApprovalStore:
    """SQLite persistence with immutable payload columns and CAS decisions."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else _db_path()
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _initialize(self) -> None:
        try:
            database_already_existed = self.path.exists()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not database_already_existed:
                try:
                    fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    os.close(fd)
                except FileExistsError:
                    database_already_existed = True
            if os.name != "nt":
                mode = stat.S_IMODE(self.path.stat().st_mode)
                if mode & 0o077:
                    raise StrictApprovalBlocked("approval database permissions are too broad")
            with self._connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=FULL")
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS pending_approvals (
                        approval_id TEXT PRIMARY KEY,
                        tool_call_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        canonical_args TEXT NOT NULL,
                        args_hash TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        conversation_id TEXT NOT NULL,
                        telegram_user_id TEXT NOT NULL,
                        telegram_chat_id TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        payload_mac TEXT NOT NULL,
                        decision_mac TEXT NOT NULL,
                        status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired','blocked')),
                        resolved_at REAL,
                        resolved_by_user_id TEXT,
                        resolved_by_chat_id TEXT,
                        resolution_reason TEXT
                    );
                    CREATE INDEX IF NOT EXISTS pending_approvals_session_idx
                        ON pending_approvals(session_id, status);
                    CREATE TABLE IF NOT EXISTS approval_audit (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at REAL NOT NULL,
                        event TEXT NOT NULL,
                        approval_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        args_hash TEXT NOT NULL,
                        display_args TEXT NOT NULL,
                        detail TEXT NOT NULL
                    );
                    CREATE TRIGGER IF NOT EXISTS pending_approvals_immutable_payload
                    BEFORE UPDATE OF
                        approval_id, tool_call_id, tool_name, canonical_args,
                        args_hash, session_id, conversation_id,
                        telegram_user_id, telegram_chat_id, created_at,
                        expires_at, payload_mac
                    ON pending_approvals
                    BEGIN
                        SELECT RAISE(ABORT, 'immutable approval payload');
                    END;
                    CREATE TRIGGER IF NOT EXISTS pending_approvals_no_delete
                    BEFORE DELETE ON pending_approvals
                    BEGIN
                        SELECT RAISE(ABORT, 'approval rows are append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS approval_audit_immutable
                    BEFORE UPDATE ON approval_audit
                    BEGIN
                        SELECT RAISE(ABORT, 'approval audit is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS approval_audit_no_delete
                    BEFORE DELETE ON approval_audit
                    BEGIN
                        SELECT RAISE(ABORT, 'approval audit is append-only');
                    END;
                    """
                )
                columns = {
                    str(row[1])
                    for row in conn.execute("PRAGMA table_info(pending_approvals)")
                }
                if "decision_mac" not in columns:
                    # Existing installations predate state authentication. No
                    # old pending row is safe to resume; the restart recovery
                    # below blocks it before any callback can execute it.
                    conn.execute(
                        "ALTER TABLE pending_approvals ADD COLUMN decision_mac TEXT NOT NULL DEFAULT ''"
                    )
                check = conn.execute("PRAGMA integrity_check").fetchone()[0]
                if check != "ok":
                    raise StrictApprovalBlocked("approval database integrity check failed")
                if database_already_existed:
                    # A pending approval belongs to a live in-process waiter.
                    # After a process restart that waiter and its execution
                    # context no longer exist, so old Telegram callbacks must
                    # not revive the call.  Keep the row for auditability and
                    # transition it atomically to a terminal fail-closed state.
                    conn.execute("BEGIN IMMEDIATE")
                    stale_rows = conn.execute(
                        "SELECT * FROM pending_approvals WHERE status='pending'"
                    ).fetchall()
                    now = time.time()
                    for row in stale_rows:
                        decision_mac = _decision_mac(_load_mac_key(), row, "blocked")
                        conn.execute(
                            """UPDATE pending_approvals
                               SET status='blocked', resolved_at=?,
                                   resolution_reason=?, decision_mac=?
                               WHERE approval_id=? AND status='pending'""",
                            (now, "process_restart", decision_mac, row["approval_id"]),
                        )
                        self._audit(conn, "blocked", row, "process_restart")
                    conn.commit()
        except StrictApprovalError:
            raise
        except Exception as exc:
            raise StrictApprovalBlocked("approval database could not be initialized") from exc

    @staticmethod
    def _row_pending(row: sqlite3.Row) -> _Pending:
        return _Pending(**{key: row[key] for key in _Pending.__dataclass_fields__})

    def _audit(self, conn: sqlite3.Connection, event: str, pending: Mapping[str, Any], detail: str) -> None:
        conn.execute(
            "INSERT INTO approval_audit(created_at,event,approval_id,tool_name,args_hash,display_args,detail) VALUES(?,?,?,?,?,?,?)",
            (
                time.time(), event, pending["approval_id"], pending["tool_name"],
                pending["args_hash"], redacted_args_json(json.loads(pending["canonical_args"])),
                _redact_text(str(detail)),
            ),
        )

    def create(self, pending: Mapping[str, Any], *, display_args: str) -> None:
        required = tuple(_Pending.__dataclass_fields__)
        if any(name not in pending for name in required):
            raise StrictApprovalBlocked("approval payload is incomplete")
        try:
            with self._lock, self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """INSERT INTO pending_approvals(
                        approval_id,tool_call_id,tool_name,canonical_args,args_hash,
                        session_id,conversation_id,telegram_user_id,telegram_chat_id,
                        created_at,expires_at,payload_mac,decision_mac,status
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending')""",
                    tuple(pending[name] for name in required),
                )
                try:
                    safe_display_args = redacted_args_json(json.loads(pending["canonical_args"]))
                except Exception:
                    safe_display_args = "[REDACTED]"
                conn.execute(
                    "INSERT INTO approval_audit(created_at,event,approval_id,tool_name,args_hash,display_args,detail) VALUES(?,?,?,?,?,?,?)",
                    (time.time(), "created", pending["approval_id"], pending["tool_name"], pending["args_hash"], safe_display_args, "pending"),
                )
                conn.commit()
        except StrictApprovalError:
            raise
        except Exception as exc:
            raise StrictApprovalBlocked("approval state could not be persisted") from exc

    def create_auto_approved(self, pending: Mapping[str, Any]) -> None:
        """Persist an immutable, already-authorized ops_guarded invocation."""

        required = tuple(_Pending.__dataclass_fields__)
        if any(name not in pending for name in required):
            raise StrictApprovalBlocked("auto-approval payload is incomplete")
        try:
            with self._lock, self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """INSERT INTO pending_approvals(
                        approval_id,tool_call_id,tool_name,canonical_args,args_hash,
                        session_id,conversation_id,telegram_user_id,telegram_chat_id,
                        created_at,expires_at,payload_mac,decision_mac,status,
                        resolved_at,resolved_by_user_id,resolved_by_chat_id,resolution_reason
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'approved', ?, ?, ?, 'ops_guarded')""",
                    tuple(pending[name] for name in required)
                    + (
                        time.time(),
                        str(pending["telegram_user_id"]),
                        str(pending["telegram_chat_id"]),
                    ),
                )
                self._audit(conn, "auto_approved", pending, "ops_guarded")
                conn.commit()
        except StrictApprovalError:
            raise
        except Exception as exc:
            raise StrictApprovalBlocked("auto-approval state could not be persisted") from exc

    def block_auto_approved(self, approval_id: str, *, reason: str) -> None:
        """Invalidate an auto-approved row when its required notification fails."""

        try:
            with self._lock, self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM pending_approvals WHERE approval_id=?",
                    (str(approval_id),),
                ).fetchone()
                if row and row["status"] == "approved" and row["resolution_reason"] == "ops_guarded":
                    _verify_decision_mac(_load_mac_key(), row, "approved")
                    conn.execute(
                        """UPDATE pending_approvals
                           SET status='blocked', resolved_at=?, resolution_reason=?, decision_mac=?
                           WHERE approval_id=? AND status='approved'""",
                        (
                            time.time(),
                            _redact_text(str(reason)),
                            _decision_mac(_load_mac_key(), row, "blocked"),
                            str(approval_id),
                        ),
                    )
                    self._audit(conn, "blocked", row, reason)
                conn.commit()
        except Exception as exc:
            raise StrictApprovalBlocked("auto-approval state could not be blocked") from exc

    def get(self, approval_id: str) -> _Pending | None:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT approval_id,tool_call_id,tool_name,canonical_args,args_hash,session_id,conversation_id,telegram_user_id,telegram_chat_id,created_at,expires_at,payload_mac,decision_mac FROM pending_approvals WHERE approval_id=?",
                    (str(approval_id),),
                ).fetchone()
                return self._row_pending(row) if row else None
        except Exception as exc:
            raise StrictApprovalBlocked("approval state could not be read") from exc

    def status(self, approval_id: str) -> str:
        try:
            with self._connect() as conn:
                row = conn.execute("SELECT * FROM pending_approvals WHERE approval_id=?", (str(approval_id),)).fetchone()
                if not row:
                    raise StrictApprovalBlocked("approval state is missing")
                _verify_decision_mac(_load_mac_key(), row, str(row["status"]))
                return str(row["status"])
        except StrictApprovalError:
            raise
        except Exception as exc:
            raise StrictApprovalBlocked("approval state could not be read") from exc

    def resolve(self, approval_id: str, action: str, *, user_id: str, chat_id: str) -> bool:
        if action not in {"approve", "deny"}:
            return False
        now = time.time()
        new_status = "approved" if action == "approve" else "denied"
        try:
            with self._lock, self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM pending_approvals WHERE approval_id=?",
                    (str(approval_id),),
                ).fetchone()
                if not row:
                    conn.rollback()
                    return False
                _verify_decision_mac(_load_mac_key(), row, str(row["status"]))
                if row["status"] != "pending" or now >= float(row["expires_at"]):
                    if row["status"] == "pending" and now >= float(row["expires_at"]):
                        decision_mac = _decision_mac(_load_mac_key(), row, "expired")
                        conn.execute("UPDATE pending_approvals SET status='expired',resolved_at=?,resolution_reason=?,decision_mac=? WHERE approval_id=? AND status='pending'", (now, "timeout", decision_mac, str(approval_id)))
                    conn.commit()
                    return False
                if str(row["telegram_user_id"]) != str(user_id) or str(row["telegram_chat_id"]) != str(chat_id):
                    conn.rollback()
                    return False
                updated = conn.execute(
                    """UPDATE pending_approvals
                       SET status=?,resolved_at=?,resolved_by_user_id=?,resolved_by_chat_id=?,resolution_reason=?,decision_mac=?
                       WHERE approval_id=? AND status='pending' AND expires_at>?""",
                    (
                        new_status, now, str(user_id), str(chat_id), action,
                        _decision_mac(_load_mac_key(), row, new_status),
                        str(approval_id), now,
                    ),
                ).rowcount
                if updated != 1:
                    conn.rollback()
                    return False
                self._audit(conn, new_status, row, f"telegram:{user_id}:{chat_id}")
                conn.commit()
                return True
        except Exception as exc:
            raise StrictApprovalBlocked("approval resolution failed") from exc

    def expire(self, approval_id: str, *, reason: str = "timeout") -> None:
        try:
            with self._lock, self._connect() as conn:
                now = time.time()
                safe_reason = _redact_text(str(reason))
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM pending_approvals WHERE approval_id=?", (str(approval_id),)).fetchone()
                if row and row["status"] == "pending":
                    _verify_decision_mac(_load_mac_key(), row, "pending")
                    decision_mac = _decision_mac(_load_mac_key(), row, "expired")
                    conn.execute("UPDATE pending_approvals SET status='expired',resolved_at=?,resolution_reason=?,decision_mac=? WHERE approval_id=? AND status='pending'", (now, safe_reason, decision_mac, str(approval_id)))
                    self._audit(conn, "expired", row, safe_reason)
                conn.commit()
        except Exception as exc:
            raise StrictApprovalBlocked("approval expiration could not be persisted") from exc

    def list_pending(self) -> list[_Pending]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT approval_id,tool_call_id,tool_name,canonical_args,args_hash,session_id,conversation_id,telegram_user_id,telegram_chat_id,created_at,expires_at,payload_mac,decision_mac FROM pending_approvals WHERE status='pending' AND expires_at>?",
                    (time.time(),),
                ).fetchall()
                key = _load_mac_key()
                for row in rows:
                    _verify_decision_mac(key, row, "pending")
                return [self._row_pending(row) for row in rows]
        except Exception as exc:
            raise StrictApprovalBlocked("pending approval state could not be listed") from exc


_store_lock = threading.RLock()
_store: ApprovalStore | None = None


def _get_store() -> ApprovalStore:
    global _store
    with _store_lock:
        if _store is None:
            _store = ApprovalStore()
        return _store


def set_store_for_testing(store: ApprovalStore | None) -> None:
    global _store
    with _store_lock:
        _store = store


def recover_pending() -> list[_Pending]:
    """Validate state after restart; never resume execution automatically."""

    return _get_store().list_pending()


def resolve_approval(approval_id: str, action: str, *, telegram_user_id: str, telegram_chat_id: str) -> bool:
    """Resolve exactly once, only for the stored Telegram identity/chat."""

    resolved = _get_store().resolve(
        approval_id, action,
        user_id=str(telegram_user_id),
        chat_id=str(telegram_chat_id),
    )
    if resolved:
        with _waiters_lock:
            waiter = _waiters.get(str(approval_id))
        if waiter:
            waiter.set()
    return resolved


def _session_key() -> str:
    try:
        from tools.approval import get_current_session_key

        return str(get_current_session_key(default=""))
    except Exception:
        return ""


def require_tool_approval(
    tool_name: str,
    args: Mapping[str, Any],
    *,
    tool_call_id: str = "",
    session_id: str = "",
    conversation_id: str = "",
    telegram_user_id: str = "",
    telegram_chat_id: str = "",
) -> ApprovedInvocation | None:
    """Wait for a Telegram approval when strict mode is active.

    ``None`` means legacy mode is active.  In strict mode this function either
    returns the exact stored invocation or raises; it never silently allows.
    """

    enabled, timeout = _strict_config()
    if not enabled:
        return None

    session_key = _session_key()
    notifier = _notifier_for(session_key)
    if notifier is None:
        raise StrictApprovalBlocked("Telegram approval notifier is unavailable")
    user_id = str(telegram_user_id or notifier.telegram_user_id)
    chat_id = str(telegram_chat_id or notifier.telegram_chat_id)
    if not user_id or not chat_id:
        raise StrictApprovalBlocked("Telegram user/chat binding is unavailable")

    canonical_args_text = canonical_json(args)
    call_id = str(tool_call_id or uuid.uuid4().hex)
    call_hash = arguments_hash(str(tool_name), canonical_args_text)
    now = time.time()
    pending_data = {
        "approval_id": uuid.uuid4().hex,
        "tool_call_id": call_id,
        "tool_name": str(tool_name),
        "canonical_args": canonical_args_text,
        "args_hash": call_hash,
        "session_id": str(session_id),
        "conversation_id": str(conversation_id or session_key),
        "telegram_user_id": user_id,
        "telegram_chat_id": chat_id,
        "created_at": now,
        "expires_at": now + timeout,
    }
    mac_key = _load_mac_key()
    pending_data["payload_mac"] = _payload_mac(mac_key, pending_data)
    store = _get_store()
    display_args = redacted_args_json(args)
    profile_home = str(get_hermes_home())
    with _strict_latch_lock:
        active_mode = _strict_latched_modes.get(profile_home, "")
    auto_approved = str(tool_name) in _ops_guarded_auto_tools(active_mode)
    if (
        not auto_approved
        and active_mode == OPS_GUARDED_MODE
        and str(tool_name) in READONLY_SHELL_TOOLS
    ):
        # Provably read-only shell commands (no redirection other than
        # /dev/null, no substitution, allowlisted binaries, no sensitive
        # paths) get the same notified auto-approval as trusted read tools.
        # Anything the classifier cannot prove safe stays fully manual.
        command_args = args if isinstance(args, Mapping) else {}
        # PTYs can activate configured pagers (systemctl/journalctl/etc.),
        # which turns an observational command into arbitrary child-process
        # execution. Foreground/background pipe execution remains eligible.
        auto_approved = (
            not bool(command_args.get("pty"))
            and is_readonly_shell_command(command_args.get("command"))
        ) or (
            str(tool_name) == "terminal"
            and is_ops_guarded_codex_command(command_args, Path(profile_home))
        )
    decision_status = "approved" if auto_approved else "pending"
    pending_data["decision_mac"] = _decision_mac(mac_key, pending_data, decision_status)
    if auto_approved:
        store.create_auto_approved(pending_data)
    else:
        store.create(pending_data, display_args=display_args)

    try:
        display_args_value: Any = json.loads(display_args)
    except Exception:
        display_args_value = "[REDACTED]"

    payload = {
        "approval_id": pending_data["approval_id"],
        "tool_call_id": call_id,
        "tool_name": str(tool_name),
        "args_hash": call_hash,
        "args": display_args_value,
        "session_id": str(session_id),
        "conversation_id": str(conversation_id or session_key),
        "telegram_user_id": user_id,
        "telegram_chat_id": chat_id,
        "expires_at": pending_data["expires_at"],
        "auto_approved": auto_approved,
    }
    try:
        sent = notifier.callback(payload)
        # The notifier is deliberately a synchronous narrow waist.  Awaiting
        # an arbitrary coroutine here would require an event-loop policy and
        # could accidentally turn a failed send into an allowed execution.
        if inspect.isawaitable(sent):
            raise RuntimeError("Telegram approval notifier returned an awaitable")
        if sent is False:
            raise RuntimeError("Telegram approval message was not sent")
    except Exception as exc:
        if auto_approved:
            store.block_auto_approved(
                pending_data["approval_id"], reason="notifier_failure"
            )
        else:
            store.expire(pending_data["approval_id"], reason="notifier_failure")
        raise StrictApprovalBlocked("Telegram approval request could not be sent") from exc

    if auto_approved:
        return ApprovedInvocation(
            approval_id=pending_data["approval_id"],
            tool_call_id=call_id,
            tool_name=str(tool_name),
            canonical_args=canonical_args_text,
            args_hash=call_hash,
            args=json.loads(canonical_args_text),
        )

    approval_id = pending_data["approval_id"]
    waiter = threading.Event()
    with _waiters_lock:
        _waiters[approval_id] = waiter
    try:
        deadline = time.monotonic() + timeout
        while True:
            status = store.status(approval_id)
            if status == "approved":
                saved = store.get(approval_id)
                if saved is None:
                    raise StrictApprovalBlocked("approved payload disappeared")
                _verify_decision_mac(_load_mac_key(), saved.__dict__, "approved")
                if time.time() >= saved.expires_at:
                    raise StrictApprovalBlocked("approval expired before execution")
                expected_mac = _payload_mac(_load_mac_key(), saved.__dict__)
                if not hmac.compare_digest(expected_mac, saved.payload_mac):
                    raise StrictApprovalBlocked("approved payload integrity check failed")
                if saved.args_hash != arguments_hash(saved.tool_name, saved.canonical_args):
                    raise StrictApprovalBlocked("approved argument hash mismatch")
                try:
                    saved_args = json.loads(saved.canonical_args)
                except Exception as exc:
                    raise StrictApprovalBlocked("approved arguments are damaged") from exc
                if not isinstance(saved_args, dict):
                    raise StrictApprovalBlocked("approved arguments are not an object")
                return ApprovedInvocation(
                    approval_id=saved.approval_id,
                    tool_call_id=saved.tool_call_id,
                    tool_name=saved.tool_name,
                    canonical_args=saved.canonical_args,
                    args_hash=saved.args_hash,
                    args=saved_args,
                )
            if status in {"denied", "expired", "blocked"}:
                raise StrictApprovalError(f"Tool call denied ({status})")
            if status != "pending":
                raise StrictApprovalBlocked("unknown approval state")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                store.expire(approval_id)
                raise StrictApprovalError("Tool call denied (timeout)")
            waiter.wait(min(0.25, remaining))
            waiter.clear()
    finally:
        try:
            # Cancellation or teardown must not leave a live pending callback
            # that no waiter can consume. An already approved/denied row is
            # terminal, so this is a no-op for the normal return path.
            store.expire(approval_id, reason="waiter_closed")
        except Exception:
            logger.error("Failed to close pending strict approval %s", approval_id, exc_info=True)
        with _waiters_lock:
            _waiters.pop(approval_id, None)


def enter_authorized_call(invocation: ApprovedInvocation) -> contextvars.Token:
    return _authorized_call.set((invocation.tool_name, invocation.args_hash, invocation.tool_call_id))


def begin_authorized_execution(
    tool_name: str,
    args: Mapping[str, Any],
    *,
    tool_call_id: str = "",
) -> contextvars.Token:
    """Mark one exact call as being inside its approved handler execution."""

    canonical = canonical_json(args)
    return _authorized_execution.set(
        (str(tool_name), arguments_hash(str(tool_name), canonical), str(tool_call_id or ""))
    )


def is_authorized_execution(
    tool_name: str,
    args: Mapping[str, Any],
    *,
    tool_call_id: str = "",
) -> bool:
    """Return whether the exact call is inside the approved handler scope."""

    current = _authorized_execution.get()
    if current is None:
        return False
    current_name, current_hash, current_call_id = current
    try:
        canonical = canonical_json(args)
    except StrictApprovalError:
        return False
    if current_name != str(tool_name) or current_hash != arguments_hash(str(tool_name), canonical):
        return False
    if tool_call_id and current_call_id and str(tool_call_id) != current_call_id:
        return False
    return True


def reset_authorized_execution(token: contextvars.Token) -> None:
    _authorized_execution.reset(token)


def ensure_handler_approval(
    tool_name: str,
    args: Mapping[str, Any],
    *,
    tool_call_id: str = "",
    session_id: str = "",
    conversation_id: str = "",
) -> bool:
    """Defend a public handler called outside the registry dispatcher.

    The normal registry path has an execution marker.  A direct call must
    obtain its own one-shot approval instead of trusting the strict-mode flag.
    ``True`` means the exact handler call is approved; ``False`` means legacy
    approval mode is active.  Strict-mode failures raise and therefore fail
    closed at the caller.
    """

    if not strict_mode_enabled():
        return False
    # Direct agent-loop sinks execute while the outer one-use marker is still
    # installed; registry-backed sinks execute after that marker is consumed
    # and replaced by the handler-scope marker. Accept either exact scope, but
    # never the mode flag alone.
    if (
        is_authorized_execution(tool_name, args, tool_call_id=tool_call_id)
        or is_authorized_call(tool_name, args, tool_call_id=tool_call_id)
    ):
        return True
    # A caller may be nested under a different one-shot marker. It is not
    # proof for this call and must not survive long enough to approve a later
    # retry with the old name/arguments.
    clear_inherited_authorization_context()
    invocation = require_tool_approval(
        tool_name,
        args,
        tool_call_id=tool_call_id,
        session_id=session_id,
        conversation_id=conversation_id,
    )
    if invocation is None:
        raise StrictApprovalBlocked("strict handler approval was not obtained")
    return True


def consume_authorized_call(tool_name: str, args: Mapping[str, Any], tool_call_id: str = "") -> bool:
    current = _authorized_call.get()
    if current is None:
        return False
    current_name, current_hash, current_call_id = current
    canonical = canonical_json(args)
    if current_name != str(tool_name) or current_hash != arguments_hash(str(tool_name), canonical):
        return False
    if tool_call_id and current_call_id and str(tool_call_id) != current_call_id:
        return False
    _authorized_call.set(None)
    return True


def authorized_call_id() -> str:
    """Return the current one-use marker's call id before it is consumed."""

    current = _authorized_call.get()
    return str(current[2]) if current is not None else ""


def is_authorized_call(tool_name: str, args: Mapping[str, Any], tool_call_id: str = "") -> bool:
    """Peek at the one-use marker without consuming it."""

    current = _authorized_call.get()
    if current is None:
        return False
    current_name, current_hash, current_call_id = current
    try:
        canonical = canonical_json(args)
    except StrictApprovalError:
        return False
    if current_name != str(tool_name) or current_hash != arguments_hash(str(tool_name), canonical):
        return False
    if tool_call_id and current_call_id and str(tool_call_id) != current_call_id:
        return False
    return True


def reset_authorized_call(token: contextvars.Token) -> None:
    _authorized_call.reset(token)


def clear_inherited_authorization_context() -> None:
    """Remove parent one-shot markers from a child execution context.

    ``contextvars.copy_context()`` is useful for carrying the session and
    notifier identity into worker threads, but it also copies these
    execution-only markers.  A delegated agent, RPC worker, or scheduled
    child must never be able to consume the parent's approval.  Call this at
    the child boundary, inside the copied context, before any tool dispatch.
    """

    _authorized_call.set(None)
    _authorized_execution.set(None)


def format_telegram_expiration(expires_at: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(expires_at)))
