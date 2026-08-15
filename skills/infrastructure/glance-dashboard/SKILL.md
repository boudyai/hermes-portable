---
name: glance-dashboard
description: Use when configuring or debugging Glance dashboard widgets.
platforms: [linux]
---

# Glance dashboard configuration

Configure, update, and debug [Glance](https://github.com/glanceapp/glance) dashboards.
Covers widget-specific gotchas, connectivity verification, secrets handling, and
known limitations when running in LXC containers.

## Prerequisites

1. Read the operator wiki (`/root/wiki/index.md`) for server inventory, IPs, domains, and services.
2. Read `ops/caddy.md` for the domain→backend mapping (which domains point to which internal IP:port).
3. Identify the Glance host (wiki lists it, e.g. `glance` at 192.168.2.131).

## Deployment patterns

Glance can run as:
- **Binary + systemd** — `/opt/glance/glance`, config at `/opt/glance_data/glance.yml`, systemd unit `glance.service`.
- **Docker compose** — `glanceapp/glance` image, mount `./config:/app/config`.

Check actual deployment before making changes:

```bash
ssh root@<glance-ip> 'bash -s' <<'EOF'
  systemctl is-active glance 2>/dev/null || echo "no systemd"
  docker ps 2>/dev/null | grep glance || echo "no docker"
  ss -tlnp | grep -E '8080'
  /opt/glance/glance --version 2>&1 || echo "binary not found"
EOF
```

## Config structure

- Main config: `glance.yml` (or `config/glance.yml` for Docker).
- Auto-reload: Glance watches config files. Changes take effect on save — no restart needed.
- **Exception**: environment variable changes require `systemctl restart glance` (env vars are read at process start only).
- Validate config before relying on auto-reload:
  ```bash
  /opt/glance/glance --config /opt/glance_data/glance.yml config:print >/dev/null 2>&1 && echo "OK" || echo "INVALID"
  ```

## Secrets in config

Never put passwords/tokens directly in `glance.yml`. Use environment variables:

1. Create `/opt/glance_data/.env` (chmod 600):
   ```
   ADGUARD_PASSWORD=secretpassword
   ```
2. Add `EnvironmentFile` to systemd unit:
   ```ini
   [Service]
   EnvironmentFile=/opt/glance_data/.env
   ExecStart=/opt/glance/glance --config /opt/glance_data/glance.yml
   ```
3. Reference in config: `password: ${ADGUARD_PASSWORD}`
4. Restart: `systemctl daemon-reload && systemctl restart glance` (env changes need restart, not just reload).

## Before writing config: connectivity survey

Test all service URLs from the Glance host before adding them to monitor widgets:

```bash
ssh root@<glance-ip> 'bash -s' <<'SURVEYEOF'
# Test HTTP connectivity to all internal services
services=(
  "192.168.2.69:80|http"
  "192.168.2.69:3000|http"
  "192.168.2.71:8006|https"
  # ... add all services from wiki
)
for entry in "${services[@]}"; do
  addr=$(echo "$entry" | cut -d'|' -f1)
  scheme=$(echo "$entry" | cut -d'|' -f2)
  code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 3 --max-time 5 "${scheme}://${addr}" 2>/dev/null)
  echo "${scheme}://${addr} -> $code"
done

# Test RSS feed URLs
for url in "https://feeds.arstechnica.com/arstechnica/index/" "https://selfh.st/rss/"; do
  ct=$(curl -sI --connect-timeout 5 --max-time 10 "$url" -H "User-Agent: Mozilla/5.0" 2>/dev/null | grep -i content-type | head -1)
  code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$url" 2>/dev/null)
  echo "$url -> $code | $ct"
done

# Test Yahoo Finance symbols for markets widget
for sym in BTC-USD ETH-USD SOL-USD GRAM-USD; do
  result=$(curl -s --connect-timeout 5 --max-time 10 "https://query1.finance.yahoo.com/v8/finance/chart/$sym?interval=1d&range=1d" -H "User-Agent: Mozilla/5.0" 2>/dev/null)
  price=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); m=d['chart']['result'][0]['meta']; print(f'{m[\"regularMarketPrice\"]} ({m.get(\"longName\",\"?\")}')" 2>/dev/null)
  echo "  $sym -> $price"
done

# Test AdGuard API auth
curl -sk -o /dev/null -w "%{http_code}" -u 'user:pass' "http://<adguard-ip>/control/stats"
SURVEYEOF
```

## Monitor widget — gotchas

### Redirects to self-signed HTTPS

Problem: Service returns 302/307/308 redirect to HTTPS with self-signed cert. Glance follows the redirect,
hits TLS error, shows service as failing. `alt-status-codes` does NOT help — Glance follows the redirect
and checks the final response, not the initial redirect code.

Solutions:
- **`check-url`** — separate URL for status check that returns 200 directly (no redirect):
  ```yaml
  - title: Nextcloud
    url: http://192.168.2.69          # user-facing link
    check-url: http://192.168.2.69/status.php  # actual health check (200, no redirect)
    icon: si:nextcloud
  ```
- **`allow-insecure: true`** — skip cert verification. Helps when the check-url is HTTPS with self-signed cert.
  Does NOT help when the server sends `tls: internal error` (no cert for the IP at all).

Example: Caddy reverse proxy on IP 192.168.2.100 — HTTPS on IP gives `tls: internal error` (Caddy has no
cert for IP, only for domains). Use `check-url` with a domain that resolves to that IP:
```yaml
- title: Caddy
  url: http://192.168.2.100
  check-url: https://git.cornspace.su   # domain resolves to 192.168.2.100, valid cert
  allow-insecure: true
  icon: si:caddy
```

### alt-status-codes

For services that legitimately return non-200 on the check URL itself (no redirect):
```yaml
alt-status-codes: [401]   # Plex requires auth, returns 401 when up
alt-status-codes: [404]   # Pomodoro returns 404 on root path but is running
```

### show-failing-only

Duplicate all monitor sites in a separate widget with `show-failing-only: true` to get a
compact list of only down services. This is a separate widget — Glance doesn't support
filtering within the same widget.

## Server Stats widget — broken in LXC

**Known issue**: `server-stats` widget shows 100% CPU perpetually when Glance runs inside a
Proxmox LXC container. The container sees host-level load average via `/proc/loadavg`
(host value, e.g. 302.67) but `nproc` returns 1 (cgroup limit). Glance caps at 100%.
RAM and disk stats are correct, but CPU is useless.

**Recommendation**: Skip `server-stats` in LXC deployments. Use Netdata or similar
for actual system metrics. The widget adds visual noise without value.

## Reddit widget — blocked on VPS IPs

Reddit blocks VPS/datacenter IP ranges at the network level. The Reddit widget
(and direct RSS feed access) return 403 with "whoa there, pardner!" from VPS IPs.

What doesn't work:
- `reddit` widget (uses `www.reddit.com/r/<sub>/hot.json`) — 403
- Direct RSS: `https://www.reddit.com/r/<sub>/.rss` — 403
- `old.reddit.com` — 403
- Redlib/libreddit instances — mostly dead, JS-challenged, or blocked

Workarounds (if needed):
- `proxy` property in the Reddit widget config (HTTP/HTTPS proxy on a residential IP)
- `request-url-template` to route through a proxy service
- Self-host a VPN/residential proxy and route Glance traffic through it

## Markets widget — crypto symbol gotchas

Yahoo Finance symbol names can be misleading:

| Symbol | Actually is | Price | Correct? |
|--------|-------------|-------|----------|
| `BTC-USD` | Bitcoin | ~$65K | ✅ |
| `ETH-USD` | Ethereum | ~$1.9K | ✅ |
| `SOL-USD` | Solana | ~$74 | ✅ |
| `TON-USD` | **Old Telegram Open Network token** (abandoned) | ~$0.005 | ❌ |
| `GRAM-USD` | **Toncoin** (The Open Network) | ~$1.33 | ✅ |

Always verify symbols with the Yahoo Finance API before adding:
```bash
curl -s "https://query1.finance.yahoo.com/v8/finance/chart/<SYMBOL>?interval=1d&range=1d" \
  -H "User-Agent: Mozilla/5.0" | python3 -m json.tool | grep -E "regularMarketPrice|longName"
```

For coins not on Yahoo Finance, use a `custom-api` widget with CoinGecko:
```yaml
- type: custom-api
  title: Crypto
  cache: 5m
  url: https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,solana,the-open-network&vs_currencies=usd&include_24hr_change=true
  template: |
    <ul class="list list-gap-10">
    {{ range $key, $val := .JSON.Map "" }}
      <li>
        <span class="color-highlight">{{ $key }}</span>:
        ${{ printf "%.2f" ($val.Float "usd") }}
        <span class="color-{{ if ge ($val.Float "usd_24h_change") 0.0 }}positive{{ else }}negative{{ end }}">
          {{ printf "%.1f" ($val.Float "usd_24h_change") }}%
        </span>
      </li>
    {{ end }}
    </ul>
```

## RSS feeds — blocked sources

These RSS feeds return 403 or HTML (Cloudflare/bot protection) from VPS IPs:

| Source | Status | Alternative |
|--------|--------|-------------|
| `bleepingcomputer.com/feed/` | 403 | — |
| `darkreading.com/rss.xml` | 403 | — |
| `securityweek.com/feed/` | 403 | — |
| `theregister.com/.../rss/` | 200 but HTML, not RSS | Schneier, Threatpost |

Working RSS feeds (verified 2026-08-07 from VPS):
- `feeds.arstechnica.com/arstechnica/index/` ✅
- `selfh.st/rss/` ✅
- `nixos.org/blog/announcements-rss.xml` ✅
- `blog.cloudflare.com/rss/` ✅
- `krebsonsecurity.com/feed/` ✅
- `www.schneier.com/feed/` ✅
- `threatpost.com/feed/` ✅
- `www.wired.com/feed/rss` ✅
- `www.theverge.com/rss/index.xml` ✅
- `www.phoronix.com/rss.php` ✅
- `hackaday.com/blog/feed/` ✅
- `www.servethehome.com/feed/` ✅
- `lobste.rs/rss` ✅
- `hnrss.org/frontpage` ✅

Always test RSS feeds with `curl -sI` checking `content-type` is `application/rss+xml`,
`application/xml`, or `text/xml` — not `text/html` (which means bot challenge page).

## DNS Stats widget (AdGuard Home)

Requires `username` and `password` (basic auth). AdGuard API endpoint: `/control/stats`.

```yaml
- type: dns-stats
  title: AdGuard Home
  service: adguard
  url: http://<adguard-ip>
  username: <user>
  password: ${ADGUARD_PASSWORD}
  hour-format: 24h
```

Store password in `.env` file (see Secrets section above). Verify auth works:
```bash
curl -sk -o /dev/null -w "%{http_code}" -u '<user>:<pass>' "http://<adguard-ip>/control/stats"
# Should return 200
```

## Icons

Use Simple Icons (`si:<name>`) for most services: `si:nextcloud`, `si:gitea`, `si:immich`,
`si:vaultwarden`, `si:plex`, `si:jellyfin`, `si:proxmox`, `si:adguardhome`, etc.

For services without Simple Icons, use Material Design Icons: `mdi:note-edit`, `mdi:file-upload`, `mdi:timer`.

Icon reference: https://simpleicons.org/ (si: prefix), https://pictogrammers.com/library/mdi/ (mdi: prefix).

## Verification after config changes

1. Check logs for errors:
   ```bash
   journalctl -u glance --no-pager -n 10
   ```
2. Test HTTP response:
   ```bash
   curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/<page-slug>
   ```
3. Use browser screenshot to visually verify all widgets render with data and no errors.

## Config backup rule

Before modifying an existing working config:
```bash
cp /opt/glance_data/glance.yml /opt/glance_data/glance.yml.bak
```
Clean up backups after confirming the new config works (don't leave stale .bak files).