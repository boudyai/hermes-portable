"""Read-only shell command classification for ops_guarded auto-approval.

Used by tools/strict_approval.py to decide whether a ``terminal`` /
``remote_terminal`` ``command`` argument is provably read-only and may be
auto-authorized (with notification) in ``ops_guarded`` mode.

Design rule: when in doubt, return False — the call falls back to the normal
manual human-in-the-loop approval. An extra approval prompt is always
preferable to a destructive command slipping through.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Tools whose ``command`` argument this classifier may vouch for.
READONLY_SHELL_TOOLS = frozenset({"terminal", "remote_terminal"})


class _Unsafe(Exception):
    """Internal: the command is not provably read-only."""


# Commands that are read-only regardless of arguments (arguments are still
# scanned for sensitive paths). Anything executing another program (xargs,
# env, nice, timeout, sudo, shells, interpreters, ssh, eval, ...) is absent
# on purpose.
_SIMPLE_READONLY = frozenset({
    "ls", "cat", "grep", "egrep", "fgrep", "head", "tail", "wc", "echo",
    "printf", "pwd", "df", "du", "free", "uname", "ps", "uptime",
    "whoami", "id", "stat", "file", "readlink", "realpath",
    "basename", "dirname", "uniq", "cut", "tr", "true", "false", "test", "[",
    "lsblk", "netstat", "vmstat", "iostat", "lscpu", "lsmem",
    "lsof", "nproc", "arch", "tty", "logname", "groups", "tree", "which",
    "type",
})

# Commands with read-only capability that have specific writing flags.
_FIND_REJECT_ARGS = frozenset({
    "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf", "-fls",
})
_JOURNALCTL_REJECT_PREFIXES = (
    "--vacuum", "--rotate", "--flush", "--sync",
    "--relinquish-var", "--smart-relinquish-var",
)
_DOCKER_READONLY_SUBCOMMANDS = frozenset({
    "ps", "logs", "inspect", "images", "version", "info", "port", "stats",
    "top", "df",
})
_SYSTEMCTL_READONLY_SUBCOMMANDS = frozenset({
    "status", "list-units", "list-timers", "list-unit-files", "is-active",
    "is-enabled", "is-failed", "show", "cat",
})

_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _has_short_flag_letter(args: list[str], letter: str) -> bool:
    """True when any single-dash flag bundle contains *letter* (-o, -ro, ...)."""
    return any(re.match(rf"^-[^-]*{re.escape(letter)}", arg) for arg in args)


# sort -o writes output to a file.
def _check_sort(args: list[str]) -> None:
    if _has_short_flag_letter(args, "o") or any(a.startswith("--output") for a in args):
        raise _Unsafe("sort with output file")


# date -s / date MMDDhhmm set the system clock; only +FORMAT / display flags
# are read-only.
def _check_date(args: list[str]) -> None:
    for arg in args:
        if arg == "-s" or arg.startswith("--set"):
            raise _Unsafe("date setting the system clock")
        if not arg.startswith(("-", "+")):
            raise _Unsafe("date with a bare operand may set the system clock")


# hostname with a bare name or -F sets the host name; only explicit display
# flags are read-only.
_HOSTNAME_SAFE_FLAGS = frozenset({
    "-a", "--alias", "-A", "--all-fqdns", "-d", "--domain", "-f", "--fqdn",
    "-h", "--help", "-i", "--ip-address", "-I", "--all-ip-addresses",
    "-s", "--short", "-v", "--version", "-y", "--yp", "--nis",
})


def _check_hostname(args: list[str]) -> None:
    if any(arg not in _HOSTNAME_SAFE_FLAGS for arg in args):
        raise _Unsafe("hostname may set the host name")


# ss -K / --kill forcibly closes sockets.
def _check_ss(args: list[str]) -> None:
    if _has_short_flag_letter(args, "K") or "--kill" in args:
        raise _Unsafe("ss killing sockets")

# Paths the agent must not read without a human looking at the call first.
_SENSITIVE_RE = re.compile(
    r"\.env($|\.)"                                   # .env, .env.local, foo.env
    r"|(^|/)\.secrets?($|/|\.)"                      # .secret, .secrets
    r"|(^|/)\.ssh/"                                  # ~/.ssh/...
    r"|(^|/)\.aws/"
    r"|(^|/)\.gnupg(/|$)"
    r"|(^|/)\.netrc$"
    r"|(^|/)\.pgpass$"
    r"|(^|/)\.my\.cnf$"
    r"|(^|/)\.kube/config$"
    r"|(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.|$)"
    r"|\.(pem|key|p12|pfx|keystore|jks)$"
    r"|(^|/)credentials?($|/|\.)"
    r"|/etc/(shadow|gshadow|sudoers)($|\.)"
    r"|authorized_keys"
    r"|strict-approvals",                            # approval DB / MAC key
    re.IGNORECASE,
)

# Operators accepted by the tokenizer. Anything else containing shell
# operator characters is unsafe.
_SEPARATORS = frozenset({";", "&&", "||", "|"})

_DEV_NULL = "/dev/null"


def _tokenize(command: str) -> list[tuple[str, str]]:
    """Split *command* into ("word", text) and ("op", text) tokens.

    Single/double quotes and backslash escapes are resolved into word token
    text, so quoted operator characters (e.g. grep 'a | b') stay part of a
    word and are never mistaken for real operators. Raises _Unsafe on
    unbalanced quotes or any form of command / process substitution.
    """
    tokens: list[tuple[str, str]] = []
    cur: list[str] = []
    i, n = 0, len(command)

    def flush() -> None:
        if cur:
            tokens.append(("word", "".join(cur)))
            cur.clear()

    while i < n:
        ch = command[i]
        if ch in " \t\r":
            flush()
            i += 1
            continue
        if ch == "\n":
            flush()
            tokens.append(("op", ";"))
            i += 1
            continue
        if ch == "#" and not cur:
            # Comment: only when it starts a word (shell semantics).
            nl = command.find("\n", i)
            i = n if nl == -1 else nl
            continue
        if ch == "\\":
            if i + 1 >= n:
                raise _Unsafe("trailing backslash")
            nxt = command[i + 1]
            if nxt == "\n":
                i += 2  # line continuation
                continue
            cur.append(nxt)
            i += 2
            continue
        if ch == "'":
            j = command.find("'", i + 1)
            if j == -1:
                raise _Unsafe("unbalanced single quote")
            cur.append(command[i + 1:j])
            i = j + 1
            continue
        if ch == '"':
            i += 1
            closed = False
            while i < n:
                c = command[i]
                if c == '"':
                    closed = True
                    i += 1
                    break
                if c == "`":
                    raise _Unsafe("backtick substitution")
                if c == "$" and i + 1 < n and command[i + 1] == "(":
                    raise _Unsafe("command substitution")
                if c == "\\" and i + 1 < n and command[i + 1] in {'"', "\\", "$"}:
                    cur.append(command[i + 1])
                    i += 2
                    continue
                cur.append(c)
                i += 1
            if not closed:
                raise _Unsafe("unbalanced double quote")
            continue
        if ch == "`":
            raise _Unsafe("backtick substitution")
        if ch == "$" and i + 1 < n and command[i + 1] == "(":
            raise _Unsafe("command substitution")
        if ch in ";|&><":
            flush()
            j = i
            while j < n and command[j] in ";|&><":
                j += 1
            tokens.append(("op", command[i:j]))
            i = j
            continue
        cur.append(ch)
        i += 1
    flush()
    return tokens


def _first_non_flag(args: list[str]) -> str | None:
    for arg in args:
        if not arg.startswith("-"):
            return arg
    return None


def _check_simple_command(argv: list[str]) -> None:
    """Raise _Unsafe unless *argv* is a provably read-only invocation."""
    while argv and _ENV_ASSIGNMENT_RE.match(argv[0]):
        argv = argv[1:]
    if not argv:
        raise _Unsafe("empty command")

    for token in argv:
        if _SENSITIVE_RE.search(token):
            raise _Unsafe(f"sensitive path reference: {token!r}")

    name = argv[0].rsplit("/", 1)[-1]
    rest = argv[1:]

    if name in _SIMPLE_READONLY:
        return
    if name == "find":
        if any(arg in _FIND_REJECT_ARGS for arg in rest):
            raise _Unsafe("find with writing action")
        return
    if name == "sort":
        _check_sort(rest)
        return
    if name == "date":
        _check_date(rest)
        return
    if name == "hostname":
        _check_hostname(rest)
        return
    if name == "ss":
        _check_ss(rest)
        return
    if name == "journalctl":
        if any(arg.startswith(_JOURNALCTL_REJECT_PREFIXES) for arg in rest):
            raise _Unsafe("journalctl with log-mutating flag")
        return
    if name == "docker":
        if _first_non_flag(rest) not in _DOCKER_READONLY_SUBCOMMANDS:
            raise _Unsafe("docker subcommand is not read-only")
        return
    if name == "systemctl":
        if _first_non_flag(rest) not in _SYSTEMCTL_READONLY_SUBCOMMANDS:
            raise _Unsafe("systemctl subcommand is not read-only")
        return
    raise _Unsafe(f"command not in read-only allowlist: {name!r}")


def is_readonly_shell_command(command: object) -> bool:
    """Return True when *command* is provably read-only.

    Guarantees when True: no command substitution, no heredocs, no input
    redirection, no output redirection except to /dev/null or fd duplication,
    no backgrounding, no sensitive path references, and every simple command
    (across ``;``/``&&``/``||``/newlines and pipe stages) is in the read-only
    allowlist.
    """
    if not isinstance(command, str) or not command.strip():
        return False
    try:
        tokens = _tokenize(command)
        current: list[str] = []
        saw_command = False

        def finalize() -> None:
            nonlocal current, saw_command
            if current:
                saw_command = True
                _check_simple_command(current)
                current = []

        i = 0
        while i < len(tokens):
            kind, tok = tokens[i]
            if kind == "word":
                current.append(tok)
                i += 1
                continue
            if tok in _SEPARATORS:
                if tok != ";" and not current:
                    raise _Unsafe(f"dangling operator: {tok!r}")
                finalize()
                i += 1
                continue
            if tok in (">", ">>", "&>"):
                # Output redirect: only /dev/null is allowed. A bare digit
                # word immediately before the operator is the fd number.
                if current and current[-1].isdigit():
                    current.pop()
                if i + 1 >= len(tokens) or tokens[i + 1] != ("word", _DEV_NULL):
                    raise _Unsafe("output redirect target is not /dev/null")
                i += 2
                continue
            if tok == ">&":
                # fd duplication (e.g. 2>&1) writes nowhere new.
                if current and current[-1].isdigit():
                    current.pop()
                if (
                    i + 1 >= len(tokens)
                    or tokens[i + 1][0] != "word"
                    or not tokens[i + 1][1].isdigit()
                ):
                    raise _Unsafe("fd duplication target is not numeric")
                i += 2
                continue
            raise _Unsafe(f"unsupported operator: {tok!r}")
        finalize()
        return saw_command
    except _Unsafe as exc:
        logger.debug("read-only classification rejected: %s", exc)
        return False
