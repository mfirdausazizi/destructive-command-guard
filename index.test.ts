import assert from "node:assert/strict";
import test from "node:test";
import registerGuard, {
	isDestructiveCommand,
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
	"pm2 restart api",
	"chmod 777 secrets.env",
	"chown root:root file",
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
		"ssh wabot-dev-oc *",
	);
	assert.equal(
		suggestAllowPattern(
			"ssh wabot-dev-oc 'bash -s' <<'REMOTE'\ngit reset --hard\nREMOTE",
		),
		"ssh wabot-dev-oc *",
	);
	assert.equal(
		suggestAllowPattern("/usr/bin/ssh user@wabot-dev-oc uptime"),
		"/usr/bin/ssh user@wabot-dev-oc *",
	);

	assert.ok(
		matchesAllowPattern(
			"ssh wabot-dev-oc 'pm2 restart api'",
			"ssh wabot-dev-oc *",
		),
	);
	assert.ok(
		matchesAllowPattern(
			"ssh wabot-dev-oc 'bash -s' <<'REMOTE'\ngit reset --hard\nREMOTE",
			"ssh wabot-dev-oc *",
		),
	);
	assert.ok(
		!matchesAllowPattern(
			"ssh other-host 'pm2 restart api'",
			"ssh wabot-dev-oc *",
		),
	);
	assert.ok(matchesAllowPattern("rm -rf build", "rm -rf build"));
	assert.ok(!matchesAllowPattern("rm -rf build2", "rm -rf build"));
});

test("tool handler prompts, emits approval events, blocks rejection, and fails closed headlessly", async () => {
	let handler: ((event: any, ctx: any) => Promise<any>) | undefined;
	const emitted: string[] = [];
	registerGuard({
		on(event: string, callback: typeof handler) {
			assert.equal(event, "tool_call");
			handler = callback;
		},
		registerCommand() {},
		events: {
			emit(event: string) {
				emitted.push(event);
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
			{ toolName: "bash", input: { command: "rm --help" } },
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

	// Session allow persists for the session (ssh commands scope to host)
	answer = "Allow for this session";
	assert.equal(
		await handler(
			{
				toolName: "bash",
				input: { command: "ssh test-guard-host 'pm2 restart api'" },
			},
			{ hasUI: true, ui },
		),
		undefined,
	);
	assert.equal(prompts, 4);
	assert.equal(
		await handler(
			{
				toolName: "bash",
				input: {
					command: "ssh test-guard-host 'git reset --hard origin/main'",
				},
			},
			{ hasUI: true, ui },
		),
		undefined,
	);
	assert.equal(prompts, 4);

	assert.deepEqual(emitted.length, 4);

	// Long commands show a trimmed snippet with a "Show full command" option;
	// choosing it re-prompts with the full text and without that option.
	const longCommand = `rm --help ${"x".repeat(300)}`;
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

test("trimSnippet collapses whitespace and bounds length", () => {
	assert.equal(trimSnippet("  git\n  status  "), "git status");
	const long = trimSnippet("a".repeat(300), 80);
	assert.equal(long.length, 80);
	assert.ok(long.endsWith("\u2026"));
});
