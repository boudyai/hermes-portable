"""Narrow ``ops_guarded`` allow-list for controlling the Codex CLI.

This is intentionally separate from the generic read-only classifier: account
selection, scratch repository creation, and Codex itself can mutate state.  We
only auto-authorize exact, reviewed command shapes and keep Codex inside its
own workspace sandbox.  Anything ambiguous falls back to the normal Telegram
approval.
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Mapping, Any


_ACCOUNT_RE = re.compile(r"~/.codex/auth\.account[A-Za-z0-9_.-]+\.json")
_CODEX_AUTH = "~/.codex/auth.json"
_LAB_CODEX_WORKSPACE = "/root/.codex-workspace"


def _has_unquoted_shell_syntax(command: str) -> bool:
    """Reject shell composition while allowing punctuation in quoted prompts."""
    quote = ""
    escaped = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote:
            if char == quote:
                quote = ""
            elif quote == '"' and char == "`":
                return True
            elif quote == '"' and char == "$" and command[index:index + 2] == "$(":
                return True
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char in ";&|<>`\n\r":
            return True
        if char == "$" and command[index:index + 2] == "$(":
            return True
        index += 1
    return bool(quote or escaped)


def _split_single_command(command: object) -> list[str] | None:
    if not isinstance(command, str) or not command.strip():
        return None
    if _has_unquoted_shell_syntax(command):
        return None
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return None


def _safe_codex_workdir(value: object, hermes_home: Path) -> bool:
    """Require an existing workspace that cannot contain Hermes private state."""
    if not isinstance(value, str) or not value.strip():
        return False
    workdir = Path(os.path.abspath(os.path.expanduser(value)))
    if not workdir.is_dir():
        return False
    private_home = Path(os.path.abspath(os.path.expanduser(str(hermes_home))))
    user_home = Path.home().resolve()
    try:
        resolved = workdir.resolve()
        private = private_home.resolve()
    except OSError:
        return False
    # A workspace at the OS home (or above it) would put ~/.hermes and
    # ~/.codex inside Codex's project boundary. A workspace inside ~/.hermes
    # is equally invalid.
    if resolved == user_home or resolved in user_home.parents:
        return False
    if private == resolved or private in resolved.parents or resolved in private.parents:
        return False
    return True


def _is_safe_codex_exec(
    argv: list[str], workdir: object, hermes_home: Path, *, scratch: bool = False
) -> bool:
    if len(argv) < 4 or argv[0] != "codex" or argv.count("exec") != 1:
        return False
    if not scratch and not _safe_codex_workdir(workdir, hermes_home):
        return False

    sandbox_ok = False
    model_ok = False
    effort_ok = False
    prompts: list[str] = []
    index = 1
    saw_exec = False
    while index < len(argv):
        arg = argv[index]
        if arg == "exec":
            saw_exec = True
            index += 1
            continue
        if arg in {"--sandbox", "-s"}:
            if index + 1 >= len(argv) or argv[index + 1] != "workspace-write":
                return False
            sandbox_ok = True
            index += 2
            continue
        if arg in {"--model", "-m"}:
            if index + 1 >= len(argv) or argv[index + 1] != "gpt-5.6-sol":
                return False
            model_ok = True
            index += 2
            continue
        if arg in {"--config", "-c"}:
            if index + 1 >= len(argv) or argv[index + 1] not in {
                "model_reasoning_effort=medium",
                "model_reasoning_effort=high",
            }:
                return False
            effort_ok = True
            index += 2
            continue
        if arg == "--sandbox=workspace-write":
            sandbox_ok = True
        elif arg == "--model=gpt-5.6-sol":
            model_ok = True
        elif arg in {
            "--config=model_reasoning_effort=medium",
            "--config=model_reasoning_effort=high",
        }:
            effort_ok = True
        elif arg in {"--ephemeral", "--ignore-user-config", "--ignore-rules"}:
            pass
        elif arg.startswith("-"):
            # In particular: no --add-dir, -c, output files, images, profiles,
            # full-access bypasses, or alternate providers.
            return False
        else:
            if not saw_exec:
                return False
            prompts.append(arg)
        index += 1

    return (
        sandbox_ok
        and model_ok
        and effort_ok
        and saw_exec
        and len(prompts) == 1
        and bool(prompts[0].strip())
    )


def is_ops_guarded_codex_command(args: Mapping[str, Any], hermes_home: Path) -> bool:
    """Return whether a terminal call matches the reviewed Codex control policy."""
    command = args.get("command")

    # lab-hermes uses one dedicated consultant workspace. Accept this exact
    # shell wrapper (including the harmless stderr merge emitted by some
    # callers), but no other ``cd`` target or shell composition. Resolve the
    # directory before approval so replacing it with a symlink to /root or
    # ~/.hermes fails the same workspace-boundary check as workdir=.
    lab_prefix = f"cd {_LAB_CODEX_WORKSPACE} && "
    if isinstance(command, str) and command.startswith(lab_prefix):
        suffix = command[len(lab_prefix):]
        if suffix.endswith(" 2>&1"):
            suffix = suffix[:-5]
        argv = _split_single_command(suffix)
        return (
            bool(argv)
            and _safe_codex_workdir(_LAB_CODEX_WORKSPACE, hermes_home)
            and _is_safe_codex_exec(argv, _LAB_CODEX_WORKSPACE, hermes_home)
        )

    scratch_prefix = "cd $(mktemp -d) && git init && "
    if isinstance(command, str) and command.startswith(scratch_prefix):
        suffix = command[len(scratch_prefix):]
        argv = _split_single_command(suffix)
        return bool(argv) and _is_safe_codex_exec(
            argv, None, hermes_home, scratch=True
        )

    argv = _split_single_command(command)
    if not argv:
        return False

    if argv == ["codex", "--version"]:
        return True
    if argv in (["codex", "login", "--device-auth"], ["codex", "login", "status"]):
        return True
    if argv == ["mktemp", "-d"]:
        return True
    if argv == ["git", "init"]:
        workdir = args.get("workdir")
        if not isinstance(workdir, str):
            return False
        resolved = Path(os.path.abspath(os.path.expanduser(workdir)))
        return resolved.is_dir() and resolved.is_relative_to(Path("/tmp"))
    if (
        len(argv) == 4
        and argv[:2] == ["ln", "-sf"]
        and _ACCOUNT_RE.fullmatch(argv[2])
        and argv[3] == _CODEX_AUTH
    ):
        return True
    return _is_safe_codex_exec(argv, args.get("workdir"), hermes_home)
