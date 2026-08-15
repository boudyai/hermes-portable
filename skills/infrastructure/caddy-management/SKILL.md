---
name: caddy-management
description: Use when auditing or editing Caddy reverse proxy.
platforms: [linux]
---

# Caddy management

Caddy reverse proxy живёт на отдельном LXC-контейнере. Факты (IP, пути, SSH-доступ) — **только в wiki** `ops/caddy.md`. Читать wiki перед работой.

## Topology (from wiki)

- Caddy-сервер: `ssh root@<caddy-ip>` (см. wiki `ops/caddy.md` для IP)
- Caddyfile: `/root/homelab-stacks/caddy/Caddyfile` (git-репо)
- `/etc/caddy/Caddyfile` → symlink на Caddyfile в homelab-stacks
- Caddy запущен как systemd service (не Docker)
- Cert storage: `/root/.local/share/caddy/certificates/`
- Static files: `/srv/` (robots.txt, llms.txt, .well-known)
- homelab-stacks клонирован на 3 ноды (см. skill `homelab-git-sync`)

## Audit procedure

### 1. Read current state

```bash
ssh root@<caddy-ip> 'bash -s' <<'EOF'
cat /root/homelab-stacks/caddy/Caddyfile
caddy version
systemctl status caddy --no-pager -l | head -20
EOF
```

### 2. Extract domains and backends

Parse Caddyfile for `domain {` blocks and `reverse_proxy` lines. Each block = one domain → one backend.

### 3. Check backend TCP connectivity (from caddy server, 2s timeout per check)

```bash
ssh root@<caddy-ip> 'bash -s' <<'EOF'
for entry in "HOST:PORT:NAME" ...; do
  host=$(echo "$entry" | cut -d: -f1)
  port=$(echo "$entry" | cut -d: -f2)
  name=$(echo "$entry" | cut -d: -f3)
  timeout 2 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null && echo "  UP   $name  $host:$port" || echo "  DOWN $name  $host:$port"
done
EOF
```

### 4. Check TLS certificates

```bash
ssh root@<caddy-ip> 'bash -s' <<'EOF'
# Production certs
for d in /root/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/*/; do
  domain=$(basename "$d")
  cert="$d${domain}.crt"
  [ -f "$cert" ] && openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2 | xargs -I{} echo "  $domain → expires {}"
done

# Staging certs (indicates ACME failures)
ls /root/.local/share/caddy/certificates/acme-staging-v02.api.letsencrypt.org-directory/ 2>/dev/null

# ACME errors by domain (last 7d)
journalctl -u caddy --since "7d ago" --no-pager 2>/dev/null | grep -oP '"identifier":"[^"]*"' | sort | uniq -c | sort -rn
EOF
```

### 5. Traffic analysis from journal (errors/warnings only — no access log by default)

**Important:** Caddy does NOT have an access log unless `log` directive is added. Journal contains only errors and warnings. "No entries in journal" ≠ "no traffic" — it means "no errors".

```bash
ssh root@<caddy-ip> 'bash -s' <<'EOF'
# Count requests by host (last 7d, errors+warnings only)
journalctl -u caddy --since "7d ago" --no-pager 2>/dev/null | grep -oP '"host":"[^"]*"' | sort | uniq -c | sort -rn
EOF
```

## Edit procedure

### 1. Backup

```bash
cp /root/homelab-stacks/caddy/Caddyfile /root/homelab-stacks/caddy/Caddyfile.bak
```

### 2. Edit

Write new Caddyfile. Use snippets for repeated patterns. Sort domains by zone then alphabetically. One style: tabs for indentation, consistent `tls { issuer acme }` blocks.

### 3. Validate

```bash
caddy validate --config /root/homelab-stacks/caddy/Caddyfile
```

**Must pass:** `Valid configuration`. If validation fails, do NOT reload. Rollback from `.bak`.

### 4. Format

```bash
caddy fmt --overwrite /root/homelab-stacks/caddy/Caddyfile
```

Re-validate after formatting.

### 5. Reload

```bash
systemctl reload caddy
systemctl is-active caddy
ss -tlnp | grep -E ':80|:443'
```

### 6. Verify

- Check deleted domains return HTTP 000 (connection closed)
- Check remaining domains respond (TCP connect or curl)
- Check journal for new errors: `journalctl -u caddy --since "30s ago"`
- For external domain testing, use `curl --resolve domain:443:127.0.0.1` (see Hairpin NAT pitfall)

### 7. Commit + sync

Use `homelab-git-sync` skill. Caddyfile is in `homelab-stacks` repo which lives on 3 nodes.

## Snippets

### robots_disallow

```
(robots_disallow) {
	@robots path /robots.txt
	respond @robots 200 {
		body `User-agent: *
Disallow: /`
	}
}
```

Import in domain blocks: `import robots_disallow` (before `reverse_proxy`).

### www redirect

```
www.example.com {
	redir https://example.com{uri} permanent
}
```

**Requires DNS A/CNAME record for www subdomain** → same IP as apex. Without DNS, Caddy can't get TLS cert and will spam ACME errors.

### Static file serving with 451 fallback

```
example.com {
	root * /srv
	file_server

	@allOtherPages {
		not path /.well-known/matrix/*
		not path /
		not path /robots.txt
		not path /llms.txt
	}
	respond @allOtherPages "451 Unavailable for Legal Reasons" 451
}
```

## Pitfalls

### Hairpin NAT

Caddy resolves domains to external IP (e.g. `188.32.232.148`). Testing from caddy server itself via `curl https://domain` will **timeout** — packets go out to external IP and don't come back (no hairpin NAT). Use `curl --resolve domain:443:127.0.0.1` or `curl --resolve domain:443:<caddy-lan-ip>`.

### ACME staging vs production

Caddy tries staging first, then production. Staging certs in `acme-staging-v02.api.letsencrypt.org-directory/` indicate failed issuance. Production certs in `acme-v02.api.letsencrypt.org-directory/`. If a domain has only staging cert → ACME is failing (usually DNS NXDOMAIN).

### ACME spam from dead domains

If a domain block exists in Caddyfile but DNS doesn't resolve (NXDOMAIN), Caddy retries ACME every ~6 hours, generating hundreds of error lines. Remove the block or add DNS record.

### No access log

Without `log` directive in Caddyfile, there's no access log. Journal only has errors/warnings. To add access logging:

```
example.com {
	log {
		output file /var/log/caddy/example.com.log
	}
	reverse_proxy ...
}
```

Consider disk space and log rotation if enabling.

### compose.yaml confusion

`compose.yaml` exists in `/root/homelab-stacks/caddy/` but Caddy runs as systemd service, not Docker. Don't confuse the two. The compose file is unused.

## Verification commands (read-only)

All safe, no side effects:
- `cat Caddyfile` — read config
- `caddy validate --config ...` — validate without applying
- `caddy fmt` (without --overwrite) — check formatting without writing
- `systemctl status caddy` — service status
- `ss -tlnp | grep -E ':80|:443'` — port listening
- `journalctl -u caddy --since "7d ago"` — error logs
- `openssl x509 -in cert.crt -noout -enddate` — cert expiry
- `timeout 2 bash -c "echo >/dev/tcp/host/port"` — TCP connect check
- `curl -sk --resolve domain:443:127.0.0.1 https://domain/path` — local test bypassing hairpin NAT