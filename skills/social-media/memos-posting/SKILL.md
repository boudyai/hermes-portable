---
name: memos-posting
description: "Use when posting to Memos. Create and manage memos via API."
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [memos, api, posting, social]
    related_skills: []
---

# Memos Posting

## Overview

Post updates to a self-hosted Memos instance via the v1 REST API. Supports visibility levels (PRIVATE, PROTECTED, PUBLIC) and Markdown content.

## When to Use

- User asks to post an update/announcement to Memos
- User asks to create, list, or delete memos
- Don't use for: general note-taking (use obsidian skill), email (use himalaya skill)

## Configuration

- **Memos URL**: `http://192.168.2.69:5230` (from wiki: `ops/unreasonable-corvus.md`)
- **API key**: stored in `/root/wiki/secrets/memos.txt`
- **API key file is git-ignored** — never commit secrets to the repo

Read the API key at the start of each session:

```bash
MEMOS_TOKEN=$(cat /root/wiki/secrets/memos.txt)
```

## API Reference

Base URL: `http://192.168.2.69:5230/api/v1`

All requests require header: `Authorization: Bearer <token>`

### Visibility Levels

| Value | Meaning |
|---|---|
| `PRIVATE` | Only the author (default) |
| `PROTECTED` | Registered users only |
| `PUBLIC` | Everyone, including anonymous |

### Create Memo

```bash
curl -s -X POST http://192.168.2.69:5230/api/v1/memos \
  -H "Authorization: Bearer $MEMOS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content":"Hello world!","visibility":"PROTECTED"}'
```

Response includes `name` field (memo ID, format `memos/<uid>`).

### List Memos

```bash
curl -s http://192.168.2.69:5230/api/v1/memos \
  -H "Authorization: Bearer $MEMOS_TOKEN" | python3 -m json.tool
```

### Delete Memo

```bash
curl -s -X DELETE http://192.168.2.69:5230/api/v1/memos/<memo_uid> \
  -H "Authorization: Bearer $MEMOS_TOKEN"
```

## Workflow

1. Read API key: `MEMOS_TOKEN=$(cat /root/wiki/secrets/memos.txt)`
2. Verify Memos is reachable: `curl -s -o /dev/null -w "%{http_code}" http://192.168.2.69:5230/` — expect `200`
3. Compose content in Markdown
4. POST to `/api/v1/memos` with desired visibility
5. Verify response contains `name` field (memo ID) and correct `visibility`
6. Report memo ID and URL to user

## Content Guidelines

- Markdown supported in `content` field
- Keep posts concise — Memos is a microblog, not a wiki
- For infrastructure updates: what changed, when, impact
- Avoid posting secrets, API keys, passwords in memo content

## Common Pitfalls

1. **`/api/v1/users/me` returns "user not found"** — PAT auth doesn't populate this endpoint. Don't use it for auth verification; use the create endpoint or a list call instead.

2. **Wrong visibility value** — must be uppercase string: `PRIVATE`, `PROTECTED`, `PUBLIC`. Lowercase or numeric values will be rejected or default to PRIVATE.

3. **Committing secrets to git** — `secrets/` is in `.gitignore`. Never add `secrets/memos.txt` to a git commit. The API key is for local use only.

4. **Memo IDs in URL paths** — response `name` is `memos/<uid>`. Use only `<uid>` in URL paths after `/api/v1/memos/`.

## Verification Checklist

- [ ] API key read from `/root/wiki/secrets/memos.txt`
- [ ] Memos instance reachable (HTTP 200 on `/`)
- [ ] POST request sent with correct visibility
- [ ] Response contains `name` field (memo ID)
- [ ] Response `visibility` matches requested value
- [ ] Memo URL reported to user: `http://192.168.2.69:5230/memos/<uid>`