import assert from "node:assert/strict";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import registerGuard, {
	isDestructiveCommand,
	loadAllowPatterns,
	matchesAllowPattern,
	suggestAllowPattern,
	trimSnippet,
} from "./index.ts";

const WORKTREE =
	"/Users/firdausazizi/GithubProjects/wabot-v4-master/wabot-v4/.worktrees/wab-308";

const SAFE = [
	"git status",
	"git diff --stat",
	"npm test",
	"rg TODO src",
	"docker ps",
	"kubectl get pods",
	"ls -la",
	"cat package.json",
	"git log --oneline -5",
	"docker compose ps",
	"ssh wabot-v3-new 'pm2 status'",
	"ssh wabot-v3-new \"mysql -e 'START TRANSACTION READ ONLY; SELECT 1; ROLLBACK'\"",
	"rm -rf /var/folders/54/qflmp4cd5bn0nd509f8wgnqw0000gn/T/pi-clipboard-659f7a41-6cc9-43e7-8ebd-ecdfcf663bf2.png",
	'/bin/rm -fr "/var/folders/54/qflmp4cd5bn0nd509f8wgnqw0000gn/T/pi-clipboard-659f7a41-6cc9-43e7-8ebd-ecdfcf663bf2.png"',
	"/usr/bin/rm -rf '/var/folders/54/qflmp4cd5bn0nd509f8wgnqw0000gn/T/pi-clipboard-659f7a41-6cc9-43e7-8ebd-ecdfcf663bf2.png'",
	`rm -rf ${WORKTREE}/.tmp-review-home`,
	`rm -fr ${WORKTREE}/.npm-cache ${WORKTREE}/mcp/wabot-admin/.npm-cache`,
	`/bin/rm -rf ${WORKTREE}/.npm-cache-worker-remote ${WORKTREE}/.pi-subagents`,
	`rm -rf ${WORKTREE}/.tmp-review-home && cd ${WORKTREE} && git status --short`,
	// Non-recursive rm of explicit files
	"rm -f verify-db-wab291.js",
	"rm file.txt",
	"/bin/rm file",
	"rm -f mcp/wabot-admin/node_modules",
	"npm run typecheck 2>&1 | grep 'error TS'; rm -f jsdom-ls-probe.test.ts",
	`rm -f ${WORKTREE}/probe.js && git status`,
	// Recursive rm strictly under temp dirs
	"rm -rf /tmp/wab291-backend-validate",
	"rm -rf /tmp/wabot-app-prod-inspect; echo cleaned",
	"rm -rf /private/tmp/scratch-dir",
	"rm -rf /var/folders/54/qflmp4cd5bn0nd509f8wgnqw0000gn/T/pi-scratch",
	"rm -rf /tmp/.npm-cache",
	"cd /tmp && rm -rf wabot-app-prod-inspect && git clone --depth 1 https://github.com/x/y.git wabot-app-prod-inspect",
	// Remote temp cleanup over ssh
	"ssh wabot-v3-new 'node /tmp/verify.js; rm -f /tmp/verify.js'",
	// Heredoc bodies are data, not commands
	"cat > /tmp/check.js << 'EOF'\nconst mysql = require('mysql2/promise');\nEOF",
	"cat > verify-db.js << 'EOF'\n/* psql DROP TABLE rm -rf all mentioned in content */\nEOF\nnode verify-db.js",
	// Index-only / merged-branch git operations
	"git reset",
	"git reset HEAD~1",
	"git reset --soft HEAD~1",
	"git reset --mixed origin/main",
	"git restore --staged file.txt",
	"git branch -d merged-branch",
	"git branch --delete merged-branch",
	// Liveness probe
	"kill -0 1234",
	// Help/version output only
	"rm --help",
	"rm --help >/dev/null",
	// rmdir/unlink of explicit non-glob targets (same power as allowed `rm file`)
	"rmdir tmp/rev 2>&1; echo done",
	"unlink probe.txt",
	// Destructive tokens in data/search position are not commands
	"grep -rn 'rm -rf' src | head -5",
	'rg -n "rm |force|drop " index.ts',
	"echo 'do not rm -rf /'",
	"printf 'chmod 777 secrets'",
	"man sudo",
	"which rm",
	"git log --grep='git reset --hard'",
	"git commit -m 'remove kill switch and rm helper'",
	"FOO=rm ls",
	"grep -n 'trap .*EXIT\\|KILL' monitor.sh",
	"for s in TERM KILL; do echo $s; done",
	"node -e 'console.log(\"rm -rf build\")'",
	"python3 -c 'print(\"chmod 777\")'",
	// sudo wrapping a read-only command
	"sudo head -n 100 /var/log/app.log",
	"ssh wabot-v3-sql 'sudo head -n 100 /var/lib/rehearsal/logs/restore-result.json'",
	"ssh wabot-v3-new 'sudo ls -l /etc/nginx/sites-enabled'",
	// chmod/chown routine forms on own files
	"chmod +x /tmp/lc-probe.sh",
	"chmod 644 file.txt",
	"chmod u+w build/out.js",
	// Local pm2 process control (only ssh pm2 soft verbs prompt)
	"pm2 restart api",
	"pm2 stop api",
	"pm2 reload api",
	"pm2 status",
	// ssh-quoted temp cleanup
	"ssh wabot-v3-new 'rm -f /tmp/verify.js'",
	// Heredoc into a data interpreter over ssh is data, not shell
	"ssh host 'python3 -' <<'PY'\nprint('rm -rf /')\nPY",
	// Identifier collisions
	"node -e 'console.log(1)' # truncateToWidth mention",
	// Words containing pattern names must not match
	"pi --no-kill-switch describe",
];

const DESTRUCTIVE = [
	"rm -rf build",
	"sudo systemctl restart app",
	"git reset --hard HEAD~1",
	"git clean -fd",
	"git push --force-with-lease origin main",
	"git push -f origin main",
	"git checkout -- package-lock.json",
	"docker-compose down -v",
	"docker compose down -v",
	"kubectl delete deployment api",
	"chmod 777 secrets.env",
	"chown root:root file",
	"chmod o+w /srv/app",
	"chown -R deploy:deploy /srv/app",
	"sudo rm -rf /var/lib/app",
	"sudo systemctl stop nginx",
	"pm2 delete api",
	"pm2 kill",
	"ssh wabot-v3-new 'pm2 restart api'",
	"ssh wabot-v3-new 'pm2 stop api'",
	"ssh host 'rm -rf /var/www/html'",
	"truncate -s 0 notes.md",
	"python3 -c \"import os; os.unlink('/Users/firdausazizi/real.md')\"",
	"echo 'DROP TABLE users' | mysql db",
	"kill -9 1234",
	"docker system prune -af",
	"ssh wabot-v3-new \"mysql -e 'DROP TABLE users'\"",
	// rm with targets split across lines is not recognized as a safe invocation
	"rm -rf\n/var/folders/54/qflmp4cd5bn0nd509f8wgnqw0000gn/T/pi-clipboard-659f7a41-6cc9-43e7-8ebd-ecdfcf663bf2.png",
	// recursive rm outside temp dirs mixed with temp target still flags
	"rm -rf /var/folders/54/qflmp4cd5bn0nd509f8wgnqw0000gn/T/pi-scratch /Users/firdausazizi/real",
	`rm -rf ${WORKTREE}/node_modules`,
	`rm -rf ${WORKTREE}/.tmp-review-home/child`,
	`rm -rf ${WORKTREE}/../other/.tmp-review-home`,
	`rm -rf ${WORKTREE}/.tmp-review-home && echo unsafe`,
	`rm -rf ${WORKTREE}/.npm-cache ${WORKTREE}/unrelated`,
	`find ${WORKTREE}/.npm-cache -type f -delete`,
	`find ${WORKTREE}/.npm-cache \\\n		-type f -delete`,
	`rm -rf ${WORKTREE}/.npm-cache*`,
	// Leniency must not extend to risky rm forms
	"rm -rf build",
	"rm -rf src/*",
	"rm -f $HOME/file",
	"rm -f *.js",
	"rm -rf /tmp",
	"rm -rf /tmp/..",
	"rm -rf ~/anything",
	"rm -rf /tmp/x /Users/firdausazizi/real-dir",
	"rm --no-preserve-root -rf /",
	// Heredocs fed to an interpreter still count
	"ssh host 'bash -s' <<'REMOTE'\ngit reset --hard\nREMOTE",
	"bash <<'EOF'\nrm -rf build\nEOF",
	// Other destructive parts alongside a safe rm still flag
	"rm -f probe.js && git reset --hard HEAD~1",
	// Worktree-touching git operations still flag
	"git reset --hard",
	"git reset --merge",
	"git reset --keep HEAD~2",
	"git restore file.txt",
	"git restore --staged --worktree file.txt",
	"git restore --staged -W file.txt",
	"git branch -D feature",
	"git branch -df feature",
	"git branch --delete --force feature",
	"kill -9 1234",
	"kill 1234",
];

const DATABASE_READ = [
	"psql -c 'SELECT 1'",
	"mysql --execute 'SELECT 1'",
	"mysql -e 'SHOW TABLES'",
	"mysql -e 'SELECT COUNT(*) AS total FROM sp_options'",
	"mysql -e 'SELECT name, COUNT(*) AS cnt FROM sp_options GROUP BY name HAVING COUNT(*) > 1'",
	"psql -c 'EXPLAIN SELECT * FROM users WHERE id = 1'",
	"redis-cli GET key",
	"redis-cli PING",
	"redis-cli --scan --pattern 'session:*'",
	"redis-cli TTL some:key",
	"mongosh --eval 'db.stats()'",
	"mongosh --eval 'db.users.find({}).limit(5)'",
	"mongosh --eval 'db.users.countDocuments()'",
	"mongo --eval 'db.version()'",
	"pgcli postgres://localhost/db",
	"mariadb -e 'DESCRIBE sp_options'",
	"sqlite3 app.db '.tables'",
	"sqlite3 app.db 'SELECT * FROM sqlite_master'",
	"valkey-cli PING",
	"psql --version",
	"mysql -e 'SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_NAME = \"sp_options\"'",
];

const DATABASE_WRITE_CMDS = [
	"docker exec db psql -c 'DROP TABLE users'",
	"ssh host 'redis-cli FLUSHALL'",
	"mysql -e 'INSERT INTO sp_options (name) VALUES (\"x\")'",
	"mysql -e 'UPDATE sp_options SET value = 1'",
	"mysql -e 'DELETE FROM sp_options WHERE id = 1'",
	"mysql -e 'CREATE TABLE t (id INT)'",
	"mysql -e 'ALTER TABLE sp_options ADD UNIQUE (name)'",
	"mysql -e 'TRUNCATE sp_options'",
	"mysql db < dump.sql",
	"psql -f migrate.sql",
	"psql --file migrate.sql",
	"sqlite3 app.db '.read setup.sql'",
	"redis-cli SET key value",
	"redis-cli DEL key",
	"redis-cli FLUSHDB",
	"redis-cli EXPIRE key 60",
	"mongosh --eval 'db.users.insertOne({})'",
	"mongosh --eval 'db.users.drop()'",
	"mongosh --eval 'db.users.updateMany({}, {$set: {a: 1}})'",
	"mysqladmin flush-tables",
	"dropdb mydb",
	"pg_restore -d mydb backup.dump",
	"npx prisma migrate deploy",
	"drizzle-kit push",
	"knex migrate:latest",
	"alembic upgrade head",
];

test("safe commands are not destructive", () => {
	for (const command of SAFE) {
		assert.equal(isDestructiveCommand(command), false, command);
	}
});

test("destructive shell commands are flagged", () => {
	for (const command of DESTRUCTIVE) {
		assert.equal(isDestructiveCommand(command), true, command);
	}
});

test("read-only database client use is allowed", () => {
	for (const command of DATABASE_READ) {
		assert.equal(isDestructiveCommand(command), false, command);
	}
});

test("database writes and opaque script input are flagged", () => {
	for (const command of DATABASE_WRITE_CMDS) {
		assert.equal(isDestructiveCommand(command), true, command);
	}
});

test("allow pattern matching and suggestions", () => {
	assert.equal(suggestAllowPattern("rm -rf build"), "rm -rf build");
	assert.equal(
		suggestAllowPattern("ssh wabot-dev-oc 'pm2 status'"),
		"ssh wabot-dev-oc 'pm2 status'",
	);
	assert.equal(
		suggestAllowPattern(
			"ssh wabot-dev-oc 'bash -s' <<'REMOTE'\ngit reset --hard\nREMOTE",
		),
		"ssh wabot-dev-oc 'bash -s' <<'REMOTE'\ngit reset --hard\nREMOTE",
	);
	assert.equal(
		suggestAllowPattern("/usr/bin/ssh user@wabot-dev-oc uptime"),
		"/usr/bin/ssh user@wabot-dev-oc uptime",
	);

	assert.ok(
		!matchesAllowPattern(
			"ssh wabot-dev-oc 'pm2 restart api'",
			"ssh wabot-dev-oc *",
		),
	);
	assert.ok(
		matchesAllowPattern(
			"ssh wabot-dev-oc 'pm2 restart api'",
			"ssh wabot-dev-oc 'pm2 restart api'",
		),
	);
	assert.ok(
		!matchesAllowPattern(
			"ssh wabot-dev-oc 'pm2 restart worker'",
			"ssh wabot-dev-oc 'pm2 restart api'",
		),
	);
	assert.ok(matchesAllowPattern("rm -rf build", "rm -rf build"));
	assert.ok(!matchesAllowPattern("rm -rf build2", "rm -rf build"));
});

test("tool handler prompts, emits approval events, blocks rejection, and fails closed headlessly", async () => {
	let handler: ((event: any, ctx: any) => Promise<any>) | undefined;
	const emitted: string[] = [];
	const payloads: unknown[] = [];
	registerGuard({
		on(event: string, callback: typeof handler) {
			if (event === "tool_call") handler = callback;
		},
		registerCommand() {},
		events: {
			emit(event: string, payload?: unknown) {
				emitted.push(event);
				payloads.push(payload);
			},
		},
	} as any);
	assert.ok(handler);

	let prompts = 0;
	let answer = "Deny";
	const ui = {
		select: async (_title: string, options: string[]) => {
			prompts += 1;
			return options.find((option) => option.startsWith(answer));
		},
	};

	assert.equal(
		await handler(
			{ toolName: "bash", input: { command: "git status" } },
			{ hasUI: true, ui },
		),
		undefined,
	);
	assert.equal(prompts, 0);
	assert.deepEqual(emitted, []);

	assert.equal(
		await handler(
			{ toolName: "bash", input: { command: SAFE.at(-1) } },
			{ hasUI: false },
		),
		undefined,
	);
	assert.equal(prompts, 0);

	assert.deepEqual(
		await handler(
			{ toolName: "bash", input: { command: "git reset --hard" } },
			{ hasUI: false },
		),
		{
			block: true,
			reason: "Destructive command requires interactive approval",
		},
	);
	assert.deepEqual(emitted, []);

	assert.deepEqual(
		await handler(
			{ toolName: "ctx_shell", input: { command: "psql -f migrate.sql" } },
			{ hasUI: true, ui },
		),
		{ block: true, reason: "Destructive command blocked by user" },
	);
	assert.equal(prompts, 1);
	assert.deepEqual(emitted, ["warp-pi-notify:approval-required"]);
	assert.deepEqual(payloads[0], {
		toolName: "ctx_shell",
		command: "psql -f migrate.sql",
	});

	answer = "Allow once";
	assert.equal(
		await handler(
			{ toolName: "shell", input: { command: "redis-cli DEL key" } },
			{ hasUI: true, ui },
		),
		undefined,
	);
	assert.equal(prompts, 2);

	// Allow once does not persist: same command prompts again
	answer = "Deny";
	assert.deepEqual(
		await handler(
			{ toolName: "shell", input: { command: "redis-cli DEL key" } },
			{ hasUI: true, ui },
		),
		{ block: true, reason: "Destructive command blocked by user" },
	);
	assert.equal(prompts, 3);

	// Session SSH approvals persist only for the exact command.
	answer = "Allow for this session";
	const sessionSsh = "ssh test-guard-host 'pm2 restart api'";
	assert.equal(
		await handler(
			{ toolName: "bash", input: { command: sessionSsh } },
			{ hasUI: true, ui },
		),
		undefined,
	);
	assert.equal(prompts, 4);
	assert.equal(
		await handler(
			{ toolName: "bash", input: { command: sessionSsh } },
			{ hasUI: true, ui },
		),
		undefined,
	);
	assert.equal(prompts, 4);

	answer = "Deny";
	assert.deepEqual(
		await handler(
			{
				toolName: "bash",
				input: {
					command: "ssh test-guard-host 'git reset --hard origin/main'",
				},
			},
			{ hasUI: true, ui },
		),
		{ block: true, reason: "Destructive command blocked by user" },
	);
	assert.equal(prompts, 5);

	assert.deepEqual(emitted.length, 5);

	// Long commands show a trimmed snippet with a "Show full command" option;
	// choosing it re-prompts with the full text and without that option.
	const longCommand = `git reset --hard ${"x".repeat(300)}`;
	const seen: { title: string; options: string[] }[] = [];
	const expandingUi = {
		select: async (title: string, options: string[]) => {
			seen.push({ title, options });
			return seen.length === 1
				? "Show full command"
				: options.find((option) => option === "Deny");
		},
	};
	assert.deepEqual(
		await handler(
			{ toolName: "bash", input: { command: longCommand } },
			{ hasUI: true, ui: expandingUi },
		),
		{ block: true, reason: "Destructive command blocked by user" },
	);
	assert.equal(seen.length, 2);
	assert.ok(seen[0].options.includes("Show full command"));
	assert.ok(seen[0].title.includes("\u2026"));
	assert.ok(!seen[1].options.includes("Show full command"));
	assert.ok(seen[1].title.includes(longCommand));
});

test("persistent approvals require confirmation and status is restored", async () => {
	const allowlistPath = join(
		mkdtempSync(join(tmpdir(), "destructive-guard-")),
		"allowlist.json",
	);
	const handlers = new Map<
		string,
		(event: any, ctx: any) => Promise<any> | any
	>();
	registerGuard(
		{
			on(
				event: string,
				callback: (event: any, ctx: any) => Promise<any> | any,
			) {
				handlers.set(event, callback);
			},
			registerCommand() {},
			events: { emit() {} },
		} as any,
		allowlistPath,
	);

	const statuses: string[] = [];
	let confirmed = false;
	const ctx = {
		hasUI: true,
		ui: {
			select: async (_title: string, options: string[]) =>
				options.find((option) => option.startsWith("Always allow")),
			confirm: async () => confirmed,
			setStatus: (_key: string, text: string) => statuses.push(text),
		},
	};

	await handlers.get("session_start")?.({}, ctx);
	assert.match(statuses.at(-1) ?? "", /^Ready/);

	const event = { toolName: "bash", input: { command: "rm -rf build" } };
	assert.deepEqual(await handlers.get("tool_call")?.(event, ctx), {
		block: true,
		reason: "Destructive command blocked by user",
	});
	assert.equal(existsSync(allowlistPath), false);
	assert.deepEqual(statuses.slice(-2), ["Approval pending", "Ready"]);

	confirmed = true;
	assert.equal(await handlers.get("tool_call")?.(event, ctx), undefined);
	assert.deepEqual(loadAllowPatterns(allowlistPath), ["rm -rf build"]);
	assert.deepEqual(statuses.slice(-2), [
		"Approval pending",
		"Ready · 1 saved rule",
	]);
});

test("approval notification failures block instead of escaping the guard", async () => {
	let handler: ((event: any, ctx: any) => Promise<any>) | undefined;
	registerGuard({
		on(event: string, callback: typeof handler) {
			if (event === "tool_call") handler = callback;
		},
		registerCommand() {},
		events: {
			emit() {
				throw new Error("listener failed");
			},
		},
	} as any);
	assert.ok(handler);

	assert.deepEqual(
		await handler(
			{ toolName: "bash", input: { command: "rm -rf notification-test" } },
			{ hasUI: true, ui: {} },
		),
		{ block: true, reason: "Destructive command approval notification failed" },
	);
});

test("cancelled and failed dialogs restore Ready status and block", async () => {
	let handler: ((event: any, ctx: any) => Promise<any>) | undefined;
	const allowlistPath = join(
		mkdtempSync(join(tmpdir(), "destructive-guard-")),
		"allowlist.json",
	);
	registerGuard(
		{
			on(event: string, callback: typeof handler) {
				if (event === "tool_call") handler = callback;
			},
			registerCommand() {},
			events: { emit() {} },
		} as any,
		allowlistPath,
	);
	assert.ok(handler);

	for (const select of [
		async () => undefined,
		async () => {
			throw new Error("dialog failed");
		},
	]) {
		const statuses: string[] = [];
		const result = await handler(
			{ toolName: "bash", input: { command: "rm -rf dialog-test" } },
			{
				hasUI: true,
				ui: {
					select,
					setStatus: (_key: string, text: string) => statuses.push(text),
				},
			},
		);
		assert.equal(result?.block, true);
		assert.deepEqual(statuses, ["Approval pending", "Ready"]);
	}
});

test("trimSnippet collapses whitespace and bounds length", () => {
	assert.equal(trimSnippet("  git\n  status  "), "git status");
	const long = trimSnippet("a".repeat(300), 80);
	assert.equal(long.length, 80);
	assert.ok(long.endsWith("\u2026"));
});
