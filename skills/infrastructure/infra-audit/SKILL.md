---
name: infra-audit
description: Audit live servers against wiki, find drift and risks.
platforms: [linux]
---

# Infra audit — compare live state vs wiki

Run a read-only audit across all (or a subset of) homelab servers and compare
live state against the operator wiki. Reports drift, new risks, and stale wiki
facts. No changes are made — this is pure inspection.

## When to use

- User asks to "audit", "check all servers", "find problems".
- Periodic health check of the infrastructure.
- After bulk wiki updates, to verify nothing was missed.
- Before a planned change, to establish a baseline.

## Prerequisites

1. Load `homelab-operations` skill (wiki-first rule, SSH access, fish pitfall).
2. Read `ops/prod-access.md` for the SSH key and per-host user/shell table.
3. Read `ops/network.md` for the full host inventory.

## Audit procedure

### 1. Build the target list

From `ops/network.md` → "Где стоит что" table. Each row gives hostname, IP, location.

### 2. For each host, run a lightweight read-only probe

Use the `host-recon` script for a full survey, or a targeted probe for specific
checks:

```bash
ssh -o ConnectTimeout=15 <user>@<ip> 'bash -s' <<'EOF'
echo "=== DISK ==="
df -h / | tail -1
echo "=== FAILED ==="
systemctl --failed 2>/dev/null | grep -v "^  UNIT\|^0 loaded\|^$\|Legend\|LOAD\|ACTIVE\|SUB"
echo "=== DOCKER ==="
docker ps -a --format '{{.Names}} {{.Status}}' 2>/dev/null | grep -iE 'exited|unhealthy|failed' || echo "(all healthy)"
echo "=== SSH ==="
sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication)'
echo "=== UPTIME ==="
uptime
EOF
```

### 3. Compare each finding against the wiki page

For each host, read `ops/<hostname>.md` and check:

| Check | What to compare |
|---|---|
| IP | `ip -br a` vs wiki "IP" field |
| Hostname | `hostname` vs wiki title and "Кратко" |
| CTID | `mount \| grep pve` vs wiki "PVE CTID" |
| OS version | `/etc/os-release` vs wiki "ОС" |
| Disk usage | `df -h /` — flag if >80%, check wiki "Замечания" mentions it |
| Failed units | `systemctl --failed` — any non-trivial? |
| Containers | `docker/podman ps -a` — any exited/unhealthy? New containers not in wiki? |
| SSH config | `sshd -T` — `PasswordAuthentication yes`? `PermitRootLogin yes`? |
| Listening ports | `ss -tlnp` — any ports not documented in wiki? |
| NixOS git | Uncommitted changes? Unpushed commits? (check wiki "Git-статус") |

### 4. Compile the audit report

Structure the report as:

```
## Infra audit — YYYY-MM-DD

### Critical
- <host>: <issue> (e.g. disk 100%, service down, SSH open)

### Warnings
- <host>: <issue> (e.g. disk >80%, stale wiki, uncommitted config)

### Drift (live ≠ wiki)
- <host>: <what changed> — wiki says X, live says Y

### OK
- <host>: all checks pass
```

### 5. Present to user

Report findings. Offer to update wiki for drift items. Do NOT make changes
without explicit confirmation.

## What to flag

### Critical (action needed soon)
- `/` disk usage ≥ 95%
- Failed systemd units (non-trivial)
- Containers in `exited`/`unhealthy`/`failed` state
- SSH `PasswordAuthentication yes` + `PermitRootLogin yes` (brute-force risk)
- No firewall + exposed services

### Warnings (should address)
- `/` disk usage 80–94%
- `PasswordAuthentication yes` (even without root login)
- Uncommitted NixOS config changes
- Unpushed git commits
- Secrets in git-tracked config files
- Hostname mismatch (live ≠ configured)
- Stale wiki page (live state differs from documented)

### Info
- New containers not yet in wiki
- Ports not documented
- `motd-news.service` failed (trivial, ignore)

## Batch execution

For auditing all hosts at once, use `execute_code` with parallel SSH:

```python
from hermes_tools import terminal
import concurrent.futures

hosts = [
    ("root", "192.168.2.89"),
    ("root", "192.168.2.53"),
    # ... from network.md
]

probe = """
echo "=== DISK ==="
df -h / | tail -1
echo "=== FAILED ==="
systemctl --failed 2>/dev/null | grep -v "^  UNIT\|^0 loaded\|^$\|Legend\|LOAD\|ACTIVE\|SUB"
echo "=== DOCKER ==="
docker ps -a --format '{{.Names}} {{.Status}}' 2>/dev/null | grep -iE 'exited|unhealthy|failed' || echo "(all healthy)"
echo "=== SSH ==="
sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication)'
"""

def probe_host(user_ip):
    user, ip = user_ip
    cmd = f"ssh -o ConnectTimeout=10 {user}@{ip} 'bash -s' <<'EOF'\n{probe}\nEOF"
    result = terminal(cmd, timeout=20)
    return ip, result

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
    results = list(ex.map(probe_host, hosts))

for ip, result in results:
    print(f"--- {ip} ---")
    print(result.get("output", result.get("error", "ERROR")))
```

## Pitfalls

- **Don't modify anything** — this is read-only. If you find a problem, report it.
- **Fish shell** — always use `bash -s` heredoc for remote commands.
- **sudo** — some hosts require sudo for podman/systemctl. Note if checks are limited.
- **Timeouts** — use `-o ConnectTimeout=15` to avoid hanging on unreachable hosts.
- **Known_hosts** — first connection to a host needs `ssh-keyscan` + user confirmation.
- **SMART interpretation** — before interpreting non-standard SMART attributes (e.g. attr 188
  Command_Timeout on HGST), read `references/smart-interpretation.md` in the wiki. Do not
  transfer vendor-specific semantics between vendors without checking drivedb.h. Always
  check `journalctl -k` for ATA errors alongside smartctl — phy-level errors don't appear
  in SMART error log. Map `ataN → device` via kernel log.
