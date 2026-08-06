<p align="center">
  <img src="assets/banner.png" alt="Hermes Agent" width="100%">
</p>

# Hermes Agent — Strict Global HITL fork

Security-focused fork of [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) for operating production infrastructure through Telegram.

Every enabled tool call must receive a fresh, one-time approval from the bound Telegram user and chat **before execution**. This applies to terminal commands, files, code, browser and HTTP access, MCP, memory, wiki, skills, cron and other tools.

## Security model

- One immutable pending approval per tool call.
- Canonical JSON arguments and a SHA-256 payload hash.
- Binding to approval, tool-call, session, conversation, Telegram user and chat IDs.
- Only **Allow once** and **Deny** actions; no session or permanent approval.
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

## Minimal strict configuration

`~/.hermes/config.yaml`:

```yaml
toolsets:
  - ops

approvals:
  mode: every_tool
  timeout_seconds: 900
  allow_session_approval: false
  allow_permanent_approval: false

wiki:
  enabled: true
  root: ~/.hermes/wiki
```

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
