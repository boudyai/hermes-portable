#!/usr/bin/env bash
# host-recon.sh — read-only SSH survey script for homelab servers.
# Usage: ssh <user>@<ip> 'bash -s' < host-recon.sh
# Safe for fish and bash remote shells. Read-only: no writes, no config changes.
set -u

echo "===== HOSTNAME ====="
hostname 2>/dev/null
cat /etc/hostname 2>/dev/null

echo "===== OS ====="
cat /etc/os-release 2>/dev/null | grep -E '^(NAME|VERSION|PRETTY|BUILD_ID)'
uname -r
nixos-version 2>/dev/null || true

echo "===== VIRT ====="
systemd-detect-virt 2>/dev/null || echo '(none)'

echo "===== CPU ====="
lscpu 2>/dev/null | grep -E '^(Model name|CPU\(s\)|Thread|Core|Socket|Architecture)'

echo "===== MEMORY ====="
free -h 2>/dev/null

echo "===== DISKS ====="
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null
echo "--- df ---"
df -h / 2>/dev/null

echo "===== NETWORK ====="
ip -br a 2>/dev/null
echo "--- routes ---"
ip route 2>/dev/null
echo "--- dns ---"
cat /etc/resolv.conf 2>/dev/null | head -5

echo "===== SSHD ====="
sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication)'

echo "===== LISTENING PORTS ====="
ss -tlnp 2>/dev/null

echo "===== SYSTEMD FAILED ====="
systemctl --failed 2>/dev/null || true

echo "===== SERVICES RUNNING ====="
systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -40

echo "===== DOCKER ====="
docker ps -a --format '{{.Names}} | {{.Image}} | {{.Status}} | {{.Ports}}' 2>/dev/null || echo '(no docker)'

echo "===== DOCKER NETWORKS ====="
docker network ls 2>/dev/null || true

echo "===== PODMAN (root) ====="
sudo -n podman ps -a --format '{{.Names}} | {{.Image}} | {{.Status}} | {{.Ports}}' 2>/dev/null || echo '(no sudo podman)'

echo "===== PODMAN (user) ====="
podman ps -a --format '{{.Names}} | {{.Image}} | {{.Status}} | {{.Ports}}' 2>/dev/null || echo '(no podman)'

echo "===== NIXOS CONFIG ====="
ls -la /etc/nixos 2>/dev/null || true
cat /etc/nixos/flake.nix 2>/dev/null || echo '(no flake)'

echo "===== GIT STATUS (nixos) ====="
cd /etc/nixos 2>/dev/null && git remote -v 2>/dev/null; git log --oneline -3 2>/dev/null; git status --short 2>/dev/null

echo "===== UPTIME ====="
uptime 2>/dev/null

echo "===== USERS ====="
grep -E ':[0-9]{4}:' /etc/passwd 2>/dev/null || true

echo "===== NVIDIA ====="
nvidia-smi 2>/dev/null || echo '(no nvidia-smi)'

echo "===== CTID (LXC) ====="
mount 2>/dev/null | grep pve | head -3 || true
