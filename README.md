<p align="center">
  <img src="assets/banner.png" alt="Hermes Agent" width="100%">
</p>

# Hermes Agent — Strict Global HITL fork

Security-focused fork of [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) for operating production infrastructure through Telegram.

The fork puts every enabled tool call behind one global Telegram gate. In `every_tool`, every call needs a fresh one-time approval. The production-oriented `ops_guarded` mode auto-authorizes only the seven explicitly listed read/interaction tools plus provably read-only `terminal`/`remote_terminal` shell commands, always after successfully sending an immediate Telegram notice; everything else still waits for 🥦 or 🦀.

## Security model

- One immutable pending approval per tool call.
- Canonical JSON arguments and a SHA-256 payload hash.
- Binding to approval, tool-call, session, conversation, Telegram user and chat IDs.
- Manual prompts expose only 🥦 and 🦀; no session or permanent approval.
- Auto-authorized calls are shown as `😵‍💫 Разрешено автоматически`; manual cards remain in chat with their final status.
- Retry or changed arguments require a new approval.
- Timeout, restart, invalid callback, damaged state or unavailable approval subsystem fail closed.
- Secrets are redacted in Telegram and audit logs without modifying the execution payload.
- Scheduled jobs require approval both when managed and before every actual run.
- Wiki is enabled in the default ops profile and is protected by the same gate.

Approval is granted to the complete tool call, not to individual shell fragments. For example, this is one terminal tool call and therefore one approval:

```bash
systemctl stop nginx && rm /tmp/file && curl https://example.com
```

## Install from source

Requirements: Git and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/boudyai/hermes-agent.git
cd hermes-agent
uv sync --locked --extra messaging --extra mcp --extra cli
uv run hermes setup
```

Add the web-search extra you use, for example:

```bash
uv sync --locked --extra messaging --extra mcp --extra cli --extra parallel-web
```

## Minimal ops configuration

`~/.hermes/config.yaml`:

```yaml
toolsets:
  - ops

approvals:
  mode: ops_guarded
  timeout_seconds: 900
  allow_session_approval: false
  allow_permanent_approval: false
  auto_approve_tools:
    - read_file
    - search_files
    - skills_list
    - skill_view
    - session_search
    - wiki_read
    - clarify

wiki:
  enabled: true
  root: ~/.hermes/wiki
```

The list may narrow the built-in seven-tool allow-list but cannot widen it. Use `mode: every_tool` when reads and clarification must also wait for manual approval.

Independently of `auto_approve_tools`, `ops_guarded` also auto-authorizes `terminal` and `remote_terminal` calls whose `command` is provably read-only: every simple command across pipes/`&&`/`;`/newlines must be in a fixed allow-list (`ls`, `cat`, `grep`, `find`, `docker ps|logs|inspect`, `systemctl status|show`, ...), with no command substitution, no heredocs, no output redirection except to `/dev/null`, and no references to sensitive paths (`.env`, `~/.ssh`, private keys, `/etc/shadow`, the approval store itself, ...). Anything the classifier cannot prove safe — including ambiguous cases — falls back to the manual 🥦/🦀 prompt. The boundary is hardcoded and cannot be widened from config.

`ops_guarded` also recognizes a narrow set of local Codex CLI control calls:
version/login status, device login, exact account-symlink switching, scratch
`mktemp -d`/`git init`, process inspection, and `codex exec`. Auto-approved
`codex exec` requires an explicit non-Hermes workdir plus
`--sandbox workspace-write -m gpt-5.6-sol` and the sole config override
`-c model_reasoning_effort=medium|high` (the server skill may add `--ephemeral`,
`--ignore-user-config`, and `--ignore-rules` for further isolation). The exact
`cd $(mktemp -d) && git init && codex exec --sandbox workspace-write ...`
scratch form is also recognized. Full-access/bypass flags, extra writable
directories, arbitrary shell composition, remote execution, and reading
`~/.codex/auth*.json` stay manually gated.

Configure the Telegram token and restrict access to trusted user IDs. The production-oriented personality is available at [`deploy/strict-ops/SOUL.md`](deploy/strict-ops/SOUL.md); install it as `~/.hermes/SOUL.md`.

## Run

```bash
uv run hermes gateway setup
uv run hermes gateway run
```

For production, run the gateway under a service manager and keep configuration, secrets and approval state outside the Git checkout. Restart explicitly after a reviewed update.

## Verify

```bash
uv sync --locked --extra dev --extra messaging --extra mcp --extra cli
uv run pytest -q tests/tools/test_strict_global_approval.py \
  tests/tools/test_approval_mode_parity.py \
  tests/gateway/test_telegram_approval_buttons.py \
  tests/test_toolsets.py
```

Upstream documentation remains available at [hermes-agent.nousresearch.com/docs](https://hermes-agent.nousresearch.com/docs/). See [LICENSE](LICENSE) for licensing information.
