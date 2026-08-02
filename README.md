# destructive-command-guard

A [Pi](https://github.com/badlogic/pi-mono) extension that prompts for
confirmation before running destructive shell commands — designed as a
companion to permission-system "yolo mode", which auto-allows everything.
This guard is an independent `tool_call` gate, so genuinely dangerous
commands still require interactive approval while routine work stays
prompt-free.

## What prompts

- **Filesystem**: `rm` / `rmdir` / `unlink` / `shred` / `truncate`,
  `find -delete`, `dd`, `mkfs`, `diskutil erase` — in command position only
- **Permissions**: world-writable `chmod` (`777`/`666`/`o+w`/`a+w`),
  recursive `chown` or `chown root`, chmod/chown of sensitive files
  (`.env`, keys, secrets)
- **Services**: `systemctl`/`service` `start|stop|restart|reload|mask|enable|disable`
- **Git (worktree-destroying only)**: `git reset --hard|--merge|--keep`,
  `git clean`, `git restore <file>` (worktree), `git checkout --`,
  `git branch -D`, `git tag -d`, `git stash drop|clear`, force pushes
- **Runtime**: `kill` / `killall` / `pkill`, `docker rm|rmi|down|prune`,
  `kubectl delete|drain`, `pm2 delete|kill` (always) and
  `pm2 stop|restart|reload` over ssh only
- **Databases**: migration tools (`prisma`, `drizzle-kit`, `knex`,
  `sequelize`, `alembic`, `flyway`, `liquibase`), `mysqladmin`, `dropdb`,
  `pg_restore`, and query clients (`psql`, `mysql`, `sqlite3`, `redis-cli`,
  `mongosh`, …) **only when the command contains write statements or opaque
  script input** (`-f file.sql`, `< dump.sql`, `.read`)

## What is deliberately allowed (leniency)

- Read-only database client use: `SELECT` / `SHOW` / `EXPLAIN` /
  `redis-cli GET` / `mongosh find()` etc., locally and over SSH
- Destructive tokens in **data position**: quoted strings, `echo`/`printf`
  arguments, `grep`/`rg`/`sed`/`awk` needles, `man`/`which` targets,
  `git commit -m` messages, env values (`FOO=rm`)
- `sudo` wrapping a benign command (`sudo head file`); the wrapped command
  is still matched, so `sudo rm -rf /` prompts
- Inline `node -e` / `python -c` scripts unless they use process/file
  mutation APIs (`child_process`, `os.unlink`, `shutil`, `fs.rm`, …)
- `rm|rmdir|unlink --help|--version`
- Non-recursive `rm`/`rmdir`/`unlink` of explicit files (no globs,
  variables, `~`, `.`/`..`, or bare roots)
- Local `pm2 stop|restart|reload`
- Recursive `rm -rf` strictly under temp dirs (`/tmp`, `/private/tmp`,
  `/var/folders/*/*/T`)
- Heredoc bodies (`cat > file << 'EOF' … EOF`) are treated as file
  content, not commands — unless the receiver is a shell (`bash <<EOF`,
  `ssh host 'bash -s' <<EOF`). Bodies fed to data interpreters
  (`python3 -`, `node`), locally or over ssh, are data
- Index-only git: plain/`--soft`/`--mixed` `git reset`,
  `git restore --staged`, `git branch -d` (refuses unmerged)
- `kill -0` liveness probes

## Approval flow

Every prompt starts with `[destructive-command-guard]` and deterministic `What`, `Why`, and approval-scope facts.
The optional `pi-security-hints` service adds at most two short AI risk sentences; missing models, timeouts, or service failures never hide or change the approval decision.
Long commands use a trimmed preview with **Show full command** before approval.

1. **Allow once** — permits this invocation only.
2. **Remember exact command for this session** — stores the exact normalized command in memory until the Pi session ends.
3. **Always allow exact command in all sessions** — requires confirmation, then writes the exact command to `~/.pi/agent/destructive-command-guard.json`.
4. **Deny** — blocks the tool call.

All approvals are exact-command scoped, including SSH commands, and wildcard characters in existing entries are treated literally rather than as broader patterns.
In headless sessions the guard fails closed with a tagged What/Why denial.
The extension publishes a session-scoped `destructive-command-guard` status (`Ready` or `Approval pending`) for compatible hosts such as PI WEB.

Use `/destructive-allowlist` to inspect the in-memory session rules and the all-sessions file used for revocation.

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
