---
name: service-health-audit
description: Use when checking which homelab services are up or down.
platforms: [linux]
---

# Service health audit

Массовая проверка TCP-доступности сервисов по списку домен→бэкенд. Применяется к reverse proxy (Caddy, nginx) или к любому набору host:port.

**Не заменяет `host-recon`** (survey одного хоста) и **не заменяет `infra-audit`** (drift wiki vs live). Этот skill — для быстрой проверки "что живо, что мертво" по списку сервисов.

## Procedure

### 1. Get the service list

Источник — конфиг reverse proxy (Caddyfile, nginx.conf) или wiki-таблица доменов. Извлечь пары:

```
domain → host:port[:protocol]
```

Если конфиг на удалённом хосте — читать через SSH:

```bash
ssh root@<proxy-ip> 'cat /path/to/config'
```

### 2. TCP connectivity check

С caddy-сервера (или с любого хоста в LAN):

```bash
ssh root@<audit-host> 'bash -s' <<'EOF'
for entry in \
  "192.168.2.69:8008:matrix" \
  "192.168.2.69:3000:gitea" \
  "10.20.30.95:8123:homeassistant"; do
  host=$(echo "$entry" | cut -d: -f1)
  port=$(echo "$entry" | cut -d: -f2)
  name=$(echo "$entry" | cut -d: -f3)
  timeout 2 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null && echo "  UP   $name  $host:$port" || echo "  DOWN $name  $host:$port"
done
EOF
```

Для HTTPS-бэкендов (self-signed): TCP connect достаточно. Полная HTTP-проверка — `curl -sk --connect-timeout 3 https://host:port/`.

### 3. DNS check

Для каждого домена — убедиться что DNS резолвится:

```bash
dig +short <domain> A
```

Пустой ответ = NXDOMAIN = домен не работает, Caddy будет спамить ACME-ошибками.

### 4. TLS certificate check (if reverse proxy is Caddy)

```bash
ssh root@<caddy-ip> 'bash -s' <<'EOF'
for d in /root/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/*/; do
  domain=$(basename "$d")
  cert="$d${domain}.crt"
  [ -f "$cert" ] && echo "  $domain → $(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)"
done
EOF
```

### 5. Error log analysis

```bash
ssh root@<proxy-ip> 'bash -s' <<'EOF'
# Errors by host (7d)
journalctl -u <service> --since "7d ago" --no-pager 2>/dev/null | grep -oP '"host":"[^"]*"' | sort | uniq -c | sort -rn

# ACME errors by domain
journalctl -u <service> --since "7d ago" --no-pager 2>/dev/null | grep -oP '"identifier":"[^"]*"' | sort | uniq -c | sort -rn
EOF
```

### 6. Classify results

| Status | Meaning | Action |
|---|---|---|
| UP + cert valid + no errors | Working | None |
| UP + cert expiring soon | Warning | Renewal check |
| UP + errors in log | Degraded | Investigate |
| DOWN + DNS OK | Backend dead | Check backend service |
| DOWN + NXDOMAIN | DNS missing | Add DNS record or remove domain |
| DOWN + no route to host | Host offline | Check VM/LXC status |

## Output format

Таблица: домен, бэкенд, TCP status, cert status, трафик (записей в логе), итоговый статус.

## Pitfalls

### Write raw output to file, don't rely on stdout

When auditing 10+ hosts in parallel, the combined output easily exceeds stdout caps (e.g. execute_code truncates at ~48KB). **Write raw output to a file inside the script** (`with open('/tmp/audit-raw.txt', 'w') as f: f.write(...)`), then read or summarise from the file. Do not rely on tool stdout for large multi-host audits — it will be truncated and you'll lose data, requiring a second pass.

### NixOS podman: sudoers path breaks after rebuild

On NixOS hosts with rootful podman, the NOPASSWD sudoers rule is tied to a specific nix store path (e.g. `/nix/store/gz8a9...-podman-5.8.2/bin/podman`). After `nixos-rebuild switch`, the hash changes and `sudo -n podman` fails with "a password is required". The old path may still exist in the store until `nix-collect-garbage`, so it can work by accident temporarily.

**Correct approach:** run `sudo -l` first to find the exact allowed path, then use that exact path: `sudo -n /nix/store/<hash>-podman-<ver>/bin/podman ps`. Do not assume `sudo -n podman` will work — it won't if the system path isn't in the sudoers rule.

### No access log = no traffic data

Caddy без `log` directive не пишет access log. Journal содержит только errors/warnings. "Нет записей" ≠ "нет трафика" — значит "нет ошибок". Для полной картины нужен access log или внешний monitor (Uptime Kuma).

### Hairpin NAT

Домены могут резолвиться во внешний IP. Тестирование с proxy-сервера через `curl https://domain` — timeout. Использовать `curl --resolve domain:443:127.0.0.1` или `curl --resolve domain:443:<lan-ip>`.

### `no route to host` vs `connection refused`

- `no route to host` — хост выключен или сеть недоступна. Проверять VM/LXC статус.
- `connection refused` — хост жив, порт не слушает. Сервис остановлен.

### Fish shell on remote hosts

Некоторые хосты используют fish. Оборачивать команды в `bash -s` heredoc. См. `homelab-operations` skill.

## Scope

Этот skill — read-only. Не изменяет конфиги, не перезапускает сервисы. Для изменений — `caddy-management` (если Caddy) или ручная работа.