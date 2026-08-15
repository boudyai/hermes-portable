---
name: wiki-host-page
description: Write a wiki host page from SSH survey data per template.
platforms: [linux]
---

# Wiki host page — writing from survey data

Write or rewrite an `ops/<hostname>.md` page in the operator wiki using the
standard template. Source data comes from a read-only SSH survey (see `host-recon`
skill) — never from the old page or guesses.

## When to use

- After running `host-recon` on a server.
- User asks to "add a server to the wiki" or "rewrite a host page".
- Live state diverges from the wiki page.

## Prerequisites

1. **Survey completed** — read-only SSH survey results available (from `host-recon`).
2. **Wiki loaded** — `wiki_read index.md` + relevant pages (`network.md`, `prod-access.md`).
3. **Template loaded** — the template lives in the `homelab-operations` skill at
   `references/server-page-template.md`. Load it with `skill_view(name='homelab-operations', file_path='references/server-page-template.md')`.

## Writing the page

### Structure (from template)

```
# `<hostname>` — <role/short description>
## Кратко (summary table)
## Доступ (SSH details)
## Железо (CPU, RAM, GPU, disks)
## OS-config / NixOS-конфиг (if applicable)
## Сервисы (systemd + Docker/Podman tables)
## Сеть (interfaces, container networks)
## Firewall
## Замечания / риски (numbered list)
## Быстрые ссылки (index, network, prod-access)
```

### Rules

- Write from **observed live facts**, not the old page.
- Include survey date: "Осмотр YYYY-MM-DD (read-only, по SSH)."
- Distinguish observed vs configured (e.g. live hostname vs NixOS config hostname).
- Flag risks but don't fix them — this is documentation, not a change session.
- Keep tables compact. Long compose configs go in a summary, not a full dump.
- **No secrets** in the wiki: no passwords, API keys, private keys, `.env` contents.
  Note their presence ("secrets in `.env`") but never include values.

### File path

Pages live at `/root/wiki/ops/<hostname>.md`. Use `write_file` to create/overwrite.

### Key facts table — fill from survey

| Field | Source |
|---|---|
| IP | `ip -br a` → primary interface |
| CTID | `mount \| grep pve` → `/mnt/pve/<stg>/images/<CTID>/vm-<CTID>-disk-...` |
| OS | `/etc/os-release` |
| Kernel | `uname -r` |
| Virt | `systemd-detect-virt` (lxc / kvm / none) |
| RAM | `free -h` |
| User | `grep /etc/passwd` for uid 1000+ |
| Uptime | `uptime` |
| SSH config | `sshd -T` |
| Ports | `ss -tlnp` |
| Containers | `docker ps -a` / `podman ps -a` |
| Failed units | `systemctl --failed` |
| Disk usage | `df -h /` |

## After writing the page

### 1. Sync `index.md`

Add a line in the `ops/` section:
```
- [ops/<hostname>.md](ops/<hostname>.md) — `<hostname>` (<ip>, <virt> <CTID>): <short role>.
```

### 2. Sync `ops/network.md`

Add a row to the "Где стоит что" table:
```
| `<hostname>` | <ip> | <location> | <role>, <CTID> | [<hostname>.md](<hostname>.md) |
```

### 3. Sync `ops/prod-access.md`

- Mark the host as "Проверено подключение" in the status checklist.
- Add a row to the server table with user, shell, SSH access type.

### 4. Git commit

```bash
cd /root/wiki && git add -A && git commit -m "add <hostname> (<ip>, <CTID>) — <short role>"
```

## Common patterns

### LXC container
- Virt = `lxc`, kernel = `7.0.2-7-pve` (host kernel).
- CTID from `mount | grep pve`.
- `lsblk` shows ALL host disks — only the rootfs loop device matters.
- RAM is limited by the container config, not physical host RAM.

### KVM VM
- Virt = `kvm`, own kernel (e.g. `6.8.0-71-generic`).
- No CTID. CPU count is vCPU, not host cores.
- Has its own disk partition layout.

### Bare metal
- Virt = `none`, own kernel.
- Full disk visibility, real hardware sensors.
- No PVE mount paths.

### NixOS host
- Config in `/etc/nixos/` (symlink to git repo).
- Read `flake.nix`, `configuration.nix`, `apps.nix`, module files.
- Check `git remote -v` (backup status) and `git status` (uncommitted changes).
- Shell is typically fish — note for SSH access.

## Pitfalls

- **Don't trust old wiki page** — always verify live. Old pages may have wrong IPs,
  stale service lists, outdated SSH config.
- **Hostname mismatch** — live `hostname` may differ from NixOS `networking.hostName`
  if `nixos-rebuild switch` wasn't run. Flag as a risk.
- **Duplicate disk entries** — `lsblk` in LXC shows host disks. Don't list them all;
  only the rootfs (loop device) and any mounted storage.
- **Secrets in config** — NixOS configs may contain API keys (e.g. Frigate `PLUS_API_KEY`).
  Flag as risk, don't reproduce the value.
