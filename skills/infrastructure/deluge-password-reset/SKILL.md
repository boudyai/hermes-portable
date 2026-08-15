---
name: deluge-password-reset
description: Use when resetting Deluge Web UI admin password.
platforms: [linux]
---

# Deluge Web UI password reset

Reset the admin password for Deluge's Web UI (port 8112).

## Host

Deluge runs on `dacha` (10.20.30.96), NixOS, user `soaska`, shell **fish** — wrap all remote commands in `bash -s` heredoc. See wiki `ops/dacha.md`.

## Config file

- Path: `/storage/media/deluge/.config/deluge/web.conf`
- Owner: `soaska:deluge`, mode `600`
- **Non-standard format**: two JSON objects concatenated — header `{"file": 2, "format": 1}` immediately followed by the main config object. `json.load()` fails with "Extra data". Must split at second `{` and parse separately.

## Password hash format

Deluge stores `pwd_salt` (40-char hex) and `pwd_sha1` (40-char hex) in `web.conf`.

Hash is **`sha1(salt + password)`** — salt first, then password. Not the other way around.

Generate new hash:

```python
import hashlib, secrets

password = "NEW_PASSWORD"
salt = secrets.token_hex(20)  # 40-char hex
pwd_sha1 = hashlib.sha1((salt + password).encode()).hexdigest()
```

## CRITICAL: stop service before editing

`delugeweb` writes `web.conf` from memory on graceful shutdown. If you edit the file while the service is running and then `restart`, **your changes are overwritten** by the old in-memory values.

Correct sequence:

1. **Backup**: `cp web.conf web.conf.bak`
2. **Stop** service: `sudo systemctl stop delugeweb.service`
3. **Edit** file while service is stopped
4. **Verify** values on disk
5. **Start** service: `sudo systemctl start delugeweb.service`
6. **Verify** service active + port listening + values still correct on disk

`deluged` (daemon) is not affected — torrents keep running.

## Full procedure

```bash
ssh soaska@10.20.30.96 'bash -s' <<'EOF'
# 1. Backup
cp /storage/media/deluge/.config/deluge/web.conf /storage/media/deluge/.config/deluge/web.conf.bak

# 2. Stop service
sudo systemctl stop delugeweb.service

# 3. Edit file
python3 -c "
import json

path = '/storage/media/deluge/.config/deluge/web.conf'
with open(path) as f:
    raw = f.read()

split_idx = raw.index('{', 1)
header = raw[:split_idx]
main = raw[split_idx:]

data = json.loads(main)
data['pwd_salt'] = 'NEW_SALT'
data['pwd_sha1'] = 'NEW_SHA1'

with open(path, 'w') as f:
    f.write(header)
    json.dump(data, f, indent=4)
"

# 4. Verify on disk
grep pwd_salt /storage/media/deluge/.config/deluge/web.conf
grep pwd_sha1 /storage/media/deluge/.config/deluge/web.conf

# 5. Start service
sudo systemctl start delugeweb.service
sleep 2
systemctl is-active delugeweb.service
ss -tlnp | grep 8112

# 6. Verify values survived restart
grep pwd_salt /storage/media/deluge/.config/deluge/web.conf
grep pwd_sha1 /storage/media/deluge/.config/deluge/web.conf
EOF
```

## Login

- URL: `http://10.20.30.96:8112`
- Login: `admin`
- Password: the new password

## Pitfalls

1. **`sha1(salt + password)`, not `sha1(password + salt)`** — first attempt used wrong order, login failed.
2. **Stop before edit** — `restart` overwrites file from memory. Must `stop` → edit → `start`.
3. **Split JSON** — `web.conf` is two concatenated JSON objects. `json.load()` fails; split at second `{`.
4. **fish shell** — wrap remote commands in `bash -s` heredoc.