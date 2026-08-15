# Server page template

Approved format for `ops/<hostname>.md` pages in the operator wiki.
User approved this structure 2026-08-06 ("Гораздо лучше, чем другая модель")
and asked all server pages be rewritten to it.

## Structure

```
# `<hostname>` — <role/short description>

<1-2 sentence summary: what it is, where, why it matters.>

## Кратко

| Параметр | Значение |
|---|---|
| IP | `<ip>/<mask>` (location, subnet) |
| PVE CTID | **<CTID>** (disk `<disk-name>` on `<storage>`) |
| ОС | <OS name + version/codename> |
| Ядро | `<kernel-version>` |
| Привилегии | <privileged LXC? / bare metal? / VM?> |
| Пользователь | `<user>` (uid, shell, groups) |
| Uptime | <uptime at time of survey> |
| Роль | <bullet list of key services> |

## Доступ

- SSH: `ssh <user>@<ip>`, port <port>.
- <PermitRootLogin / PasswordAuthentication status>.
- Key `prod_paladin`/`id_ed25519` — **works/doesn't work**.
- sudo: <requires password / NOPASSWD / n/a>.

## Железо (visible from LXC)

- **CPU**: <model, cores/threads>.
- **RAM**: <total, used>, swap <on/off>.
- **GPU**: <model(s), VRAM, driver version, CUDA version>.
- **Диски** (passed through from PVE host):

| Mount | Device | FS | Size | Used | Purpose |
|---|---|---|---|---|---|
| `/` | ... | ... | ... | ... | rootfs |
| `/mnt/...` | ... | ... | ... | ... | ... |

- Note unmounted disks (visible in lsblk but not mount).

## <NixOS-конфиг / OS-config>

(For NixOS hosts)
- **Git repo**: `/etc/nixos` (local / remote URL).
- **flake.nix**: inputs, outputs, hostname entry.
- **Modules**: list of .nix files and what they contain.
- **Rebuild**: exact command / alias.
- **GC**: schedule, keep generations.
- **stateVersion**.

### Секреты
- Where secrets live, what's in git (flag plaintext secrets).

### Git-статус
- Uncommitted changes, missing remote, etc.

## Сервисы

### NixOS-native (systemd)
Table of service → description.

### Podman/Docker (compose stacks)
Table of unit → stack dir → purpose → ports.
Note dockerCompat, dockerSocket, networks.

## Backup

(If applicable)
BorgBackup / other. Table of job → source → schedule.
Encryption, prune policy, notifications.

## Сеть

- Interface: IP, gateway, DNS.
- Container networks (podman/docker subnets).
- Network manager (networkd / NetworkManager).

## Firewall

- `networking.firewall.enable` / `ufw status` / nftables.
- Open TCP/UDP ports (list).
- Any hazards or notes.

## Замечания / риски

Numbered list of observations:
- hostname mismatch (live vs configured)
- uncommitted config changes
- missing git remote
- secrets in git
- disk usage warnings
- ghost VRAM
- sudo availability
- failed systemd units
- anything else worth flagging

## Быстрые ссылки

- [../index.md](../index.md)
- [network.md](network.md)
- [prod-access.md](prod-access.md)
```

## Rules

- Write from **observed live facts**, not the old page.
- Include a survey date ("Осмотр YYYY-MM-DD").
- Distinguish what's observed vs what's configured (e.g. live hostname vs configured hostname).
- Flag risks but don't fix them — this is documentation, not a change session.
- Sync `index.md` and `ops/network.md` after adding/rewriting.
- Keep tables compact. Long compose configs go in a summary, not a full dump.
