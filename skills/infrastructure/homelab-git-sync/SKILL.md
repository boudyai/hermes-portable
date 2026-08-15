---
name: homelab-git-sync
description: Use when committing to repos cloned across multiple nodes.
platforms: [linux]
---

# Homelab git sync

В homelab конфигурационные репозитории клонированы на несколько нод. Изменение, сделанное на одной ноде, нужно закоммитить, запушить и синхронизировать на остальные.

## Репозитории и их клоны

### `homelab-stacks` (Obsidian vault + сервисные стеки)

Origin: `git.cornspace.su/soaska/homelab-stacks` (Gitea, self-hosted).

| Нода | IP | Путь | SSH-доступ | Пользователь |
|---|---|---|---|---|
| caddy | 192.168.2.100 | `/root/homelab-stacks` | `ssh root@192.168.2.100` | root |
| unreasonable-corvus | 192.168.2.69 | `/mnt/tier1-apps/homelab-stacks` | `ssh soaska@192.168.2.69` | soaska |
| lab-hermes | 192.168.2.130 | `/root/homelab-stacks` | local | root |

**Где что редактируется:**
- Caddyfile — на caddy (192.168.2.100), т.к. там живой Caddy service
- Compose-файлы сервисов — на unreasonable-corvus (192.168.2.69), т.к. там запущены контейнеры
- lab-hermes клон — для reference/синхронизации, не для прямой редакции

### `wiki` (операторский wiki)

Origin: `git.cornspace.su/soaska/lab-hermes-wiki.git` (Gitea, self-hosted).

| Нода | Путь | SSH-доступ |
|---|---|---|
| lab-hermes | `/root/wiki` | local |

Wiki живёт только на lab-hermes. Не клонируется на другие ноды.

### `rc-stacks` (дача, отдельный репозиторий)

Origin: `git.cornspace.su/soaska/rc-stacks.git`. На даче (10.20.30.96, `reasonable-corvus`). Не путать с `homelab-stacks`.

## Sync procedure

### Сценарий A: изменение на удалённой ноде (caddy / unreasonable-corvus)

1. **Commit на ноде изменения:**

```bash
ssh root@<node-ip> 'bash -s' <<'EOF'
cd <repo-path>
git add -A
git commit -m "<message>"
git push origin <branch>
EOF
```

2. **Pull на lab-hermes:**

```bash
cd /root/homelab-stacks
git pull origin main
```

3. **Если репо есть на третьей ноде — pull и там:**

```bash
ssh soaska@192.168.2.69 'bash -s' <<'EOF'
cd /mnt/tier1-apps/homelab-stacks
git pull origin main
EOF
```

### Сценарий B: изменение на lab-hermes (wiki, локальные репо)

```bash
cd /root/wiki
git add -A
git commit -m "<message>"
git push origin master
```

### Сценарий C: проверка синхронизации всех клонов

```bash
# На каждой ноде:
ssh root@<node-ip> 'git -C <repo-path> log --oneline -1'
# Сравнить хеши. Если расходятся — pull на отстающей ноде.
```

## Ветка по умолчанию

- `homelab-stacks`: `main`
- `wiki`: `master`

Проверять через `git branch` если unsure.

## Pitfalls

### Staged but not committed

`git add -A` стейджит, но `git commit` может не сработать (пустой diff, pre-commit hook). Всегда проверять `git status` после commit и `git log --oneline -1` чтобы убедиться что коммит создан.

### Different remote URLs

Клоны одного репо могут иметь slight differences в remote URL (с `.git` и без). Это cosmetic, git treat'ит их одинаково. Не "исправлять" если не просят.

### unreasonable-corvus SSH user — soaska, не root

На unreasonable-corvus (192.168.2.69) SSH под `soaska`, не `root`. `PermitRootLogin no`. См. wiki `ops/unreasonable-corvus.md`.

### Backup files в репо

После редактирования конфигов (Caddyfile, compose.yaml) могут остаться `.bak` файлы. `git add -A` подхватит их. Удалять перед commit:

```bash
rm /path/to/file.bak
# или
git add -- specific/file.only
```

### Fish shell

На unreasonable-corvus shell — fish. Оборачивать команды в `bash -s` heredoc. См. `homelab-operations` skill.

### Gitea self-hosted — доступность

Origin — `git.cornspace.su` (Gitea на unreasonable-corvus:3000). Если Gitea недоступен — push не сработает. Проверять `curl -sk https://git.cornspace.su/ -o /dev/null -w '%{http_code}'`.

## Git identity

- Wiki: `user.name "Prod Paladin"`, `user.email "prod-paladin@cornspace.su"` (на lab-hermes).
- homelab-stacks: проверить `git config user.name` на каждой ноде.