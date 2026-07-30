# destructive-command-guard

A [Pi](https://github.com/badlogic/pi-mono) extension that prompts for
confirmation before running destructive shell commands — designed as a
companion to permission-system "yolo mode", which auto-allows everything.
This guard is an independent `tool_call` gate, so genuinely dangerous
commands still require interactive approval while routine work stays
prompt-free.

## What prompts

- **Filesystem**: `rm` / `rmdir` / `unlink` / `shred` / `truncate`,
  `find -delete`, `dd`, `mkfs`, `diskutil erase`, `sudo`, `chmod`, `chown`
- **Git (worktree-destroying only)**: `git reset --hard|--merge|--keep`,
  `git clean`, `git restore <file>` (worktree), `git checkout --`,
  `git branch -D`, `git tag -d`, `git stash drop|clear`, force pushes
- **Runtime**: `kill` / `killall` / `pkill`, `docker rm|rmi|down|prune`,
  `kubectl delete|drain`, `pm2 delete|stop|restart|reload|kill`
- **Databases**: migration tools (`prisma`, `drizzle-kit`, `knex`,
  `sequelize`, `alembic`, `flyway`, `liquibase`), `mysqladmin`, `dropdb`,
  `pg_restore`, and query clients (`psql`, `mysql`, `sqlite3`, `redis-cli`,
  `mongosh`, …) **only when the command contains write statements or opaque
  script input** (`-f file.sql`, `< dump.sql`, `.read`)

## What is deliberately allowed (leniency)

- Read-only database client use: `SELECT` / `SHOW` / `EXPLAIN` /
  `redis-cli GET` / `mongosh find()` etc., locally and over SSH
- Non-recursive `rm [-f]` of explicit files (no globs, variables,
  `~`, `.`/`..`, or bare roots)
- Recursive `rm -rf` strictly under temp dirs (`/tmp`, `/private/tmp`,
  `/var/folders/*/*/T`)
- Heredoc bodies (`cat > file << 'EOF' … EOF`) are treated as file
  content, not commands — unless piped into a shell/ssh interpreter
- Index-only git: plain/`--soft`/`--mixed` `git reset`,
  `git restore --staged`, `git branch -d` (refuses unmerged)
- `kill -0` liveness probes

## Approval flow

Prompts show a one-line trimmed snippet (with **Show full command** for
long commands) and offer:

1. **Allow once**
2. **Allow for this session** — persists in memory for the Pi session
3. **Always allow** — saved to `~/.pi/agent/destructive-command-guard.json`
   (glob patterns; `ssh <host> …` commands are scoped to `ssh <host> *`)
4. **Deny** — blocks the tool call

In headless (no-UI) sessions the guard fails closed and blocks.

Use the `/destructive-allowlist` command to inspect saved and session
allow patterns.

## Install

```sh
git clone https://github.com/mfirdausazizi/destructive-command-guard \
  ~/.pi/agent/extensions/destructive-command-guard
```

Then `/reload` in Pi.

## Test

```sh
node --experimental-strip-types --test index.test.ts
```
