#!/usr/bin/env python3
"""
Remote Terminal Tool

Execute shell commands on a remote host over SSH. Authentication is
key-based only: ``BatchMode=yes`` disables password/passphrase prompts, and
when no explicit ``key_path`` is given, ssh's built-in key discovery applies
(``~/.ssh/config``, ssh-agent, default identity files).
"""

import json
import logging
import re
import shlex
import shutil
import subprocess

from tools.registry import registry, tool_error

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 600

# host: plain hostname/IP, optionally user@ prefix. No whitespace, no leading
# dash (which ssh would parse as an option).
_HOST_RE = re.compile(r"^([A-Za-z0-9_.-]+@)?[A-Za-z0-9_.:-]+$")


def _check_requirements() -> bool:
    if not shutil.which("ssh"):
        logger.error("remote_terminal requires the OpenSSH client (ssh) in PATH.")
        return False
    return True


def _validate_text_arg(value: str, label: str) -> str | None:
    """Reject values ssh would parse as options or that are malformed."""
    if not value or not value.strip():
        return f"{label} must not be empty"
    if value.startswith("-"):
        return f"{label} must not start with '-' (ssh option injection risk)"
    if any(ch.isspace() for ch in value):
        return f"{label} must not contain whitespace"
    return None


def remote_terminal_tool(
    command: str,
    host: str,
    port: int = 22,
    key_path: str = "",
    timeout: int | None = None,
    workdir: str = "",
    task_id: str = None,
    _approval_args: dict | None = None,
    _tool_call_id: str = "",
    _session_id: str = "",
) -> str:
    """Execute a shell command on a remote host over SSH."""
    approval_args = (
        dict(_approval_args)
        if isinstance(_approval_args, dict)
        else {
            "command": command,
            "host": host,
            "port": port,
            "key_path": key_path,
            "timeout": timeout,
            "workdir": workdir,
        }
    )
    try:
        from tools.strict_approval import ensure_handler_approval

        strict_handler_approved = ensure_handler_approval(
            "remote_terminal",
            approval_args,
            tool_call_id=str(_tool_call_id or ""),
            session_id=str(_session_id or task_id or ""),
            conversation_id=str(_session_id or task_id or ""),
        )
    except Exception as strict_error:
        logger.error("Remote terminal global approval blocked: %s", strict_error)
        return tool_error(
            "Global approval blocked: security subsystem unavailable or call not approved",
            success=False,
            tool="remote_terminal",
        )

    if not command or not str(command).strip():
        return tool_error("command must not be empty", success=False, tool="remote_terminal")
    command = str(command)

    host = str(host or "").strip()
    if err := _validate_text_arg(host, "host"):
        return tool_error(err, success=False, tool="remote_terminal")
    if not _HOST_RE.match(host):
        return tool_error(f"host {host!r} is not a valid [user@]host", success=False, tool="remote_terminal")

    try:
        port = int(port)
    except (TypeError, ValueError):
        return tool_error(f"port must be an integer, got {port!r}", success=False, tool="remote_terminal")
    if not (1 <= port <= 65535):
        return tool_error(f"port {port} is out of range", success=False, tool="remote_terminal")

    key_path = str(key_path or "").strip()
    if key_path:
        if err := _validate_text_arg(key_path, "key_path"):
            return tool_error(err, success=False, tool="remote_terminal")

    workdir = str(workdir or "").strip()

    if timeout is None:
        timeout = DEFAULT_TIMEOUT
    try:
        timeout = int(timeout)
    except (TypeError, ValueError):
        return tool_error(f"timeout must be an integer, got {timeout!r}", success=False, tool="remote_terminal")
    if timeout < 1:
        return tool_error("timeout must be >= 1", success=False, tool="remote_terminal")
    timeout = min(timeout, MAX_TIMEOUT)

    # Legacy (non-strict) path: run the same dangerous-command guards the
    # local terminal tool applies. In strict approval mode the registry
    # dispatch layer has already gated this exact call via Telegram.
    if not strict_handler_approved:
        try:
            from tools.approval import check_all_command_guards
            from tools.terminal_tool import _get_approval_callback

            guard = check_all_command_guards(
                command, "ssh", approval_callback=_get_approval_callback()
            )
            if not guard.get("approved"):
                return json.dumps({
                    "success": False,
                    "error": guard.get("message") or "Command was not approved",
                    "blocked": True,
                }, ensure_ascii=False)
        except ImportError:
            logger.debug("Command guard modules unavailable; skipping legacy guard")

    argv = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
    ]
    if port != 22:
        argv.extend(["-p", str(port)])
    if key_path:
        argv.extend(["-i", key_path])
    argv.extend(["--", host, "bash", "-s"])

    script = f"cd {shlex.quote(workdir)}\n{command}" if workdir else command

    logger.info("remote_terminal: executing on %s (port %d)", host, port)
    try:
        result = subprocess.run(
            argv,
            input=script,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return json.dumps({
            "success": False,
            "error": f"Command timed out after {timeout}s",
            "host": host,
            "timed_out": True,
        }, ensure_ascii=False)
    except FileNotFoundError:
        return tool_error(
            "ssh client not found in PATH. Install OpenSSH client.",
            success=False, tool="remote_terminal",
        )
    except Exception as exc:
        return tool_error(f"Failed to execute remote command: {exc}", success=False, tool="remote_terminal")

    return json.dumps({
        "success": result.returncode == 0,
        "host": host,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }, ensure_ascii=False)


REMOTE_TERMINAL_SCHEMA = {
    "name": "remote_terminal",
    "description": (
        "Execute a shell command on a remote host over SSH. Key-based auth "
        "only: when key_path is omitted, ssh's standard key discovery applies "
        "(ssh-agent, ~/.ssh/config, default identity files). Password auth is "
        "not supported. Requires the host to be reachable and pre-authorized."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The shell command to execute on the remote host (runs via bash).",
            },
            "host": {
                "type": "string",
                "description": "Target host: 'hostname', 'user@hostname', or an IP with optional user prefix.",
            },
            "port": {
                "type": "integer",
                "description": "SSH port (default: 22).",
                "default": 22,
            },
            "key_path": {
                "type": "string",
                "description": "Path to a private key file for ssh -i. Omit to use ssh's default key discovery.",
                "default": "",
            },
            "timeout": {
                "type": "integer",
                "description": f"Max seconds to wait (default: {DEFAULT_TIMEOUT}, max: {MAX_TIMEOUT}).",
                "minimum": 1,
            },
            "workdir": {
                "type": "string",
                "description": "Remote working directory for the command (cd'd to before execution).",
                "default": "",
            },
        },
        "required": ["command", "host"],
    },
}


def _handle_remote_terminal(args, **kw):
    return remote_terminal_tool(
        command=args.get("command"),
        host=args.get("host"),
        port=args.get("port", 22),
        key_path=args.get("key_path", ""),
        timeout=args.get("timeout"),
        workdir=args.get("workdir", ""),
        task_id=kw.get("task_id"),
        _approval_args=dict(args),
        _tool_call_id=kw.get("tool_call_id", ""),
        _session_id=kw.get("session_id", ""),
    )


registry.register(
    name="remote_terminal",
    toolset="remote_terminal",
    schema=REMOTE_TERMINAL_SCHEMA,
    handler=_handle_remote_terminal,
    check_fn=_check_requirements,
    emoji="🌐",
    max_result_size_chars=100_000,
)
