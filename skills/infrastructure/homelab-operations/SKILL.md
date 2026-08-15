---
name: homelab-operations
description: Consult the operator wiki first for infra work.
platforms: [linux]
---

# Homelab operations

The user's homelab infrastructure is documented in a **git-versioned operator wiki** at `/root/wiki`. Structure:

- `local/` — this installation (command host `lab-hermes`): `host.md`, `shell.md`, `vless.md`, `hermes-agent.md`.
- `ops/` — managed infrastructure: `network.md` (map), `prod-access.md` (SSH key), one page per server.
- `index.md` — root navigation.

**The wiki is the single source of truth for all infrastructure facts** — server inventory, IPs, SSH users, shells, services, firewall state, credentials. The skill does not duplicate any of this. When you need a fact, read the wiki.

## Standard server page format

New/rewritten server pages follow a fixed structure approved by the user (2026-08-06: "Гораздо лучше, чем другая модель"). The template lives in [references/server-page-template.md](references/server-page-template.md). Key sections: Кратко (summary table) → Доступ → Железо → NixOS-конфиг/OS-config → Сервисы → Backup → Сеть → Firewall → Замечания/риски → Быстрые ссылки. Always sync `index.md` and `ops/network.md` when adding or rewriting a host.

## Inspecting a server (read-only SSH survey)

When documenting or rewriting a server page, run a **read-only SSH survey** before writing:

1. Read the wiki page first (wiki-first rule) — get the expected IP, user, known role.
2. Connect with the right user from the table above. If `Permission denied`, try the other user before concluding the key is missing.
3. Wrap remote commands in `bash -s` heredoc (fish hosts will break on POSIX one-liners).
4. Collect in batches — one SSH call per logical group (host basics, config files, containers/services). Independent reads can be batched in parallel.
5. Key facts to collect: hostname (live vs configured — they can differ after a rebuild without `switch`), OS/virt type, CPU/RAM, disks & mount points, network (IP, routes, DNS), SSH config (`sshd -T`), listening ports (`ss -tlnp`), failed systemd units, running services, containers (`docker ps`/`podman ps`), GPU (`nvidia-smi`), uptime, git status of config repo.
6. For NixOS hosts: read `/etc/nixos/flake.nix`, `configuration.nix`, `apps.nix`, etc. Check `git status` for uncommitted changes and `git remote -v` for backup status.
7. For LXC containers: determine the **CTID from the mount path** — `mount | grep pve` shows `/mnt/pve/<storage>/images/<CTID>/vm-<CTID>-disk-0.raw`. This is the Proxmox container ID. Also check `systemd-detect-virt` returns `lxc`.
8. Never modify the server during a survey — read-only only. Note risks/discrepancies as observations, not fixes.

## Core rule: wiki-first, not system-first

Before doing any infra work — diagnosing, planning a change, or poking at the system — **read the operator wiki first** (`wiki_read index.md` + the relevant page), not `uname`/`ip`/`systemctl` guesses.

The user has corrected this twice: diagnosing with system commands while an up-to-date wiki exists is **wrong**. The wiki is authoritative and fresher than transient system state.

- Load the relevant page before acting (e.g. `ops/codeserver.md` before touching the GPU box).
- The wiki holds info the live system won't show (why a service is stopped, firewall hazards, reachability constraints, sudo requirements).

**Pitfall: "list what's running" / "show me everything" feels like a simple local command but is infra work.** For the command host (`lab-hermes`), local `systemctl`/`ss` is fine. But the user often means the *entire homelab*. Jumping straight to `systemctl`/`ss`/`docker ps` on the local host and presenting that as "everything running" misses the point. Read `index.md` first to get the full server inventory, then inspect each relevant host via SSH (with wiki-provided credentials/ports/users). The wiki gives the inventory; the live system gives the current state. You need both.

## Where facts live: wiki, not memory

- Infrastructure facts belong in the **wiki**, not in agent memory. The user explicitly wants only the meta-rule ("check the wiki") in memory, not duplicated infra detail.
- If asked to "remember" an infra fact, update the wiki instead of memory.

## SSH access

- All SSH access details (key path, per-host users, connection status) live in `ops/prod-access.md`. Read it before connecting to any server.
- The login shell differs per host. Check the server's wiki page — if it's fish, see the pitfall below.

## Pitfall: remote shell may be fish

Some hosts use **fish** as the login shell. Running a quoted multi-command string over `ssh host 'cmd'` executes under fish, which errors on shell constructs like `(cmd)` in command position. Never pass complex one-liners assuming POSIX sh.

**Always wrap non-trivial remote commands in a bash heredoc:**

```
ssh user@host 'bash -s' <<'EOF'
  command1
  command2
EOF
```

This is safe regardless of the remote shell.

## Editing the wiki

- Git repo at `/root/wiki`, branch `master`.
- Git identity: `user.name "Prod Paladin"`, `user.email "prod-paladin@cornspace.su"` (check `git config` or follow user preference).
- After edits: `cd /root/wiki && git add -A && git commit -m "..."`.
- **Sync related pages**: a single fact often appears in multiple pages. When you change a fact, search the whole wiki for other occurrences so you don't leave a stale reference.
- Use `wiki_read` to view content — `read_file` may flag `.md` files as "Binary" (UTF-8).

## Pitfall: stale facts

The wiki gets stale. When the user says a wiki fact is wrong, verify live state read-only, then update the wiki and any related pages, and commit. Don't leave contradictory info across pages.

When adding a server or rewriting a page, **inspect the live system read-only first** — don't trust the old page blindly.

## Destructive changes on prod: backup + confirmation (mandatory)

**Rule (enforced after 2026-08-07 incident):** Before ANY destructive or modifying action on prod — editing configs, `rm`, restarting services, `docker compose down`, changing data — you MUST:

1. **Make a backup** of what you're about to change: `cp file file.bak` (or equivalent). No exceptions, even if the change seems trivial.
2. **Get explicit user confirmation** before executing. Describe what you'll do, what could go wrong, and how to revert.
3. **Verify the result** read-only after the change.

### Pitfall: never use `sed` with range patterns on prod configs

`sed -i '/addr1/,/addr2/d'` is dangerous on config files. If `addr2` doesn't match (different indentation, whitespace, encoding), **sed deletes from addr1 to EOF** — silently destroying everything below the match point.

** incident:** `sed -i '/^    healthcheck:/,/^    retries: 5$/d'` on a compose.yaml — the `retries: 5` line had 6 spaces, not 4, so addr2 never matched. Sed deleted from `healthcheck:` to end of file, removing 3 of 5 service definitions. User caught it: "Ты что удалил бота из compose файла 😳"

**Safe alternatives:**
- Use the `patch` tool (fuzzy matching, refuses ambiguous matches).
- Use `write_file` to rewrite the entire file after verifying content.
- If sed is unavoidable, test with `sed -n` (dry-run, no `-i`) first and review the output.

## Podman in LXC: known quirks

Podman running inside Proxmox LXC containers has specific quirks. See [references/podman-lxc-quirks.md](references/podman-lxc-quirks.md) for details: healthcheck failures, NOPASSWD sudoers tied to nix store paths, and rootful podman access patterns.

## Proxmox host (pve) — STRICT READ-ONLY RULES

**Правила работы с Proxmox гипервизором (pve, 192.168.2.71):**

1. **НИКАКИХ WRITE-действий на хосте pve.** Вообще. Только read-only команды: `cat`, `ls`, `ss`, `ip`, `zpool status`, `smartctl -A/-i`, `systemctl status`, `qm list`, `pct list`, `pvesm status`. Никаких `rm`, `cp`, `sed -i`, `reboot`, `qm stop`, `pct stop`, `apt`, `zpool scrub`, ничего пишущего.
2. **Подключаться ТОЛЬКО когда пользователь специально запросил** работу с pve. Не «просто проверить», не «заодно посмотреть», не «на всякий случай».
3. **Перед каждой SSH-командой на pve** писать в ответе КАПСОМ: **ВЫПОЛНЯЕТСЯ НА: pve (192.168.2.71)** — чтобы пользователь точно видел, где выполняется команда.
4. **Blast radius = все VM/LXC на хосте.** Ошибка на pve может положить весь homelab.
5. Если для задачи нужен write на pve — остановиться, объяснить что нужно и почему, и ждать явного подтверждения пользователя.

## Network-change caution

`lab-hermes` is a Proxmox LXC with networkd-managed config. There can be **two overlapping `.network` files on one interface** — the lexical-first one wins. Before touching IP/gateway: identify which file governs, check how your own access arrives, confirm the new gateway has internet egress, and get explicit user confirmation. Full details live in the wiki.
