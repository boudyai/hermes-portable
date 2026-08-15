---
name: host-recon
description: Read-only SSH survey of a server before wiki page update.
platforms: [linux]
---

# Host recon — read-only SSH survey

Perform a **read-only** SSH survey of a server before writing or updating its
wiki page. Collects all facts needed for the standard server page template in
one SSH call. No writes, no config changes, no service restarts.

## When to use

- Adding a new server to the wiki.
- Re-inspecting a server before rewriting its wiki page.
- Verifying live state matches wiki (audit).

## Prerequisites

1. Read `ops/prod-access.md` in the wiki for the SSH key path and per-host user/shell.
2. If connecting for the first time, collect the host key fingerprint with `ssh-keyscan`
   and present it to the user for confirmation before adding to `~/.ssh/known_hosts`.
3. Wrap commands in `bash -s` heredoc — some hosts use fish as the login shell.

## Running the survey

The survey script lives at [scripts/host-recon.sh](scripts/host-recon.sh).
Pipe it over SSH in one call:

```bash
ssh -o ConnectTimeout=15 <user>@<ip> 'bash -s' < scripts/host-recon.sh
```

For NixOS hosts that need deeper config inspection, append extra reads:

```bash
ssh -o ConnectTimeout=15 <user>@<ip> 'bash -s' <<'EOF'
cat /etc/nixos/configuration.nix
cat /etc/nixos/apps.nix
cat /etc/nixos/apps/*.nix
ls -la /opt/
EOF
```

## What it collects

| Category | Commands |
|---|---|
| Hostname | `hostname`, `/etc/hostname` |
| OS | `/etc/os-release`, `uname -r`, `nixos-version` |
| Virt type | `systemd-detect-virt` (lxc / kvm / none) |
| CPU | `lscpu` (model, cores, threads) |
| Memory | `free -h` |
| Disks | `lsblk`, `df -h /` |
| Network | `ip -br a`, `ip route`, `/etc/resolv.conf` |
| SSH config | `sshd -T` (port, root login, password auth, pubkey) |
| Ports | `ss -tlnp` |
| Failed units | `systemctl --failed` |
| Running services | `systemctl list-units --type=service --state=running` |
| Docker | `docker ps -a`, `docker network ls` |
| Podman | `podman ps -a` (root + user) |
| NixOS config | `/etc/nixos/flake.nix`, git status |
| GPU | `nvidia-smi` |
| LXC CTID | `mount | grep pve` (extract from disk path) |
| Uptime | `uptime` |
| Users | `grep /etc/passwd` |

## Key facts to extract for the wiki page

1. **CTID** — from `mount | grep pve`: `/mnt/pve/<storage>/images/<CTID>/vm-<CTID>-disk-0.raw`.
2. **Virt type** — `systemd-detect-virt` returns `lxc`, `kvm`, or `none` (bare metal).
3. **Live vs configured hostname** — `hostname` may differ from the NixOS config
   if `nixos-rebuild switch` wasn't run after changing `networking.hostName`.
4. **SSH posture** — `PermitRootLogin` + `PasswordAuthentication` combination.
5. **Disk usage** — flag any `/` over 80% as a risk.
6. **Failed units** — list any non-trivial failed systemd units.
7. **Docker/Podman containers** — names, images, status (running/exited/failed/unhealthy).
8. **Listening ports** — map ports to services, note any unexpected ones.

## Pitfalls

- **fish shell**: `ssh user@host 'cmd1; cmd2'` breaks on fish. Always use `bash -s` heredoc.
- **sudo on NixOS hosts**: `sudo -n` may require a password. Root podman may not be visible
  without sudo. Note this as a limitation in the wiki page.
- **LXC disk visibility**: `lsblk` shows all PVE host disks, not just the container's.
  Use `mount | grep pve` to find the actual rootfs and CTID.
- **First connection**: `ssh-keyscan` + present fingerprint to user before trusting.
- **No secrets**: never read or log `.env` files, private keys, or password hashes.
  Note their presence but don't include contents.
- **SMART interpretation**: before interpreting non-standard SMART attributes (e.g. attribute 188
  Command_Timeout), read `references/smart-interpretation.md` in the wiki. Do not transfer
  vendor-specific semantics (e.g. Seagate raw16 subfields) to other vendors (HGST, WD) without
  confirmation in smartmontools drivedb.h. Always check kernel log (`journalctl -k`) for ATA
  errors — phy-level errors (PHYRdyChg, CommWake, DevExch) do not appear in SMART error log
  or CRC counters. Map `ataN → device` via kernel log, do not guess.

## After the survey

1. Extract key facts into the server page template (see `homelab-operations` skill,
   `references/server-page-template.md`).
2. Sync `index.md`, `ops/network.md`, and `ops/prod-access.md` with the new host.
3. Git commit: `cd /root/wiki && git add -A && git commit -m "..."`.
4. Flag any risks found (full disks, password auth, failed units, secrets in git).
