/**
 * Prompt for destructive shell commands and direct database-client use.
 * Companion to @gotgenes/pi-permission-system yolo mode: yolo auto-allows
 * ask rules, so this independent tool_call gate still requires confirmation.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const COMMAND_TOOLS = new Set(["bash", "shell", "ctx_shell", "exec_command"]);

const ALLOWLIST_PATH = join(
	homedir(),
	".pi",
	"agent",
	"destructive-command-guard.json",
);

/** Absolute path or bare executable token, not part of a --flag. */
const EXE = String.raw`(?<![\w-])(?:(?:\/(?:usr\/)?(?:local\/)?(?:s?bin\/)?)?|[A-Za-z]:\\(?:[^\\\s]+\\)*)?`;

function re(body: string, flags = "i"): RegExp {
	return new RegExp(body, flags);
}

const CLIPBOARD_TEMP_PATH = String.raw`\/var\/folders\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/T\/pi-clipboard-[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\.png`;
const SAFE_CLIPBOARD_RM = re(
	String.raw`^(?:\/(?:usr\/)?bin\/)?rm[ \t]+-(?:rf|fr)[ \t]+(?:${CLIPBOARD_TEMP_PATH}|"${CLIPBOARD_TEMP_PATH}"|'${CLIPBOARD_TEMP_PATH}')$`,
	"",
);

const PATH_COMPONENT = String.raw`[A-Za-z0-9][A-Za-z0-9._-]*`;
const WORKTREE_ROOT = String.raw`\/Users\/firdausazizi\/GithubProjects\/(?:${PATH_COMPONENT}\/)+\.worktrees\/${PATH_COMPONENT}`;
const WORKTREE_TEMP_DIR = String.raw`${WORKTREE_ROOT}(?:\/${PATH_COMPONENT})*\/(?:\.npm-cache(?:-${PATH_COMPONENT})?|\.pi-subagents|\.tmp-review-home)`;
const SAFE_WORKTREE_RM = re(
	String.raw`^(?:\/(?:usr\/)?bin\/)?rm[ \t]+-(?:rf|fr)[ \t]+${WORKTREE_TEMP_DIR}(?:[ \t]+${WORKTREE_TEMP_DIR})*(?:[ \t]+&&[ \t]+cd[ \t]+${WORKTREE_ROOT}[ \t]+&&[ \t]+git[ \t]+status[ \t]+--short)?$`,
	"",
);

// Command position: start of string/segment (incl. inside quotes for ssh/bash -c
// payloads), optionally preceded by env assignments and benign wrappers. Bare
// destructive tokens in argument/data position no longer match.
const CMD_POS = String.raw`(?:^|[\n;&|'"\`(])[ \t]*(?:(?:command|builtin|nohup|time|nice|env|exec|timeout[ \t]+\S+|[A-Za-z_][A-Za-z0-9_]*=[^\s'"]*)[ \t]+)*(?:\/(?:usr\/)?(?:local\/)?(?:s?bin\/)?)?`;

// Filesystem / system
const FILESYSTEM = [
	re(String.raw`${CMD_POS}(?:rm|rmdir|unlink|shred|truncate)\b`),
	re(String.raw`${CMD_POS}find\b[\s\S]*\s-delete\b`),
	re(String.raw`${CMD_POS}dd[ \t]+\S`, ""),
	re(String.raw`${CMD_POS}mkfs(?:\.\w+)?\b`),
	re(
		String.raw`\b${EXE}diskutil\b.*\b(?:erase|partition|reformat|unmountForce|apfs\s+delete)\b`,
	),
	// chmod/chown: only clearly risky forms (world-writable, recursive chown,
	// chown to root, sensitive filenames). chmod +x / 644 on own files is allowed.
	re(
		String.raw`${CMD_POS}chmod\b[^\n;|&]*(?:\b[0-7]?777\b|\b[0-7]?666\b|\b[augo]*[oa][+=][rwxst]*w)`,
	),
	re(
		String.raw`${CMD_POS}chown\b[^\n;|&]*[ \t](?:-R\b|--recursive\b|root\b|0:0)`,
	),
	re(
		String.raw`${CMD_POS}(?:chmod|chown)\b[^\n;|&]*(?:\.env\b|id_rsa|id_ed25519|\.pem\b|credentials|secrets?\b)`,
	),
	// Service state changes (sudo prefixes are stripped before matching).
	re(
		String.raw`${CMD_POS}(?:systemctl|service)\b[^\n;|&]*\b(?:start|stop|restart|reload|mask|unmask|enable|disable)\b`,
	),
];

// Git. Index-only operations are allowed: `git reset` without
// --hard/--merge/--keep, `git restore --staged` without --worktree/-W,
// and `git branch -d` (refuses unmerged; -D still asks).
const GIT = [
	re(String.raw`\bgit\s+reset\b[^\n;|&]*(?:--hard|--merge|--keep)\b`),
	re(String.raw`\bgit\s+clean\b`),
	re(String.raw`\bgit\s+restore\b(?![^\n;|&]*--staged\b)`),
	re(
		String.raw`\bgit\s+restore\b[^\n;|&]*(?:--worktree\b|\s-W\b|\s-SW\b|\s-WS\b)`,
	),
	re(String.raw`\bgit\s+checkout\s+--(?:\s|$)`),
	re(String.raw`\bgit\s+branch\s+-D\b`, ""),
	re(
		String.raw`\bgit\s+branch\s+(?:--delete\s+--force|--force\s+--delete|-[a-z]*f[a-z]*d|-[a-z]*d[a-z]*f)\b`,
	),
	re(String.raw`\bgit\s+tag\s+(?:-d|--delete)\b`),
	re(String.raw`\bgit\s+stash\s+(?:drop|clear)\b`),
	re(String.raw`\bgit\s+push\b[^\n]*\s(?:--force(?:-with-lease)?|-f)\b`),
	re(String.raw`\bgit\s+push\b[^\n]*\s-f\b`),
];

// Process / containers / process managers. `kill -0` is a liveness probe.
// `kill` is case-sensitive so signal names (KILL) and SQL (KILL QUERY) don't match.
const RUNTIME = [
	re(String.raw`${CMD_POS}kill\b(?![ \t]+-0\b)`, ""),
	re(String.raw`${CMD_POS}(?:killall|pkill)\b`),
	re(
		String.raw`\bdocker(?:-compose|\s+compose)?\s+(?:rm|rmi|down|prune|volume\s+(?:rm|prune)|system\s+prune)\b`,
	),
	re(String.raw`\bkubectl\s+(?:delete|drain)\b`),
	re(String.raw`\bkubectl\s+replace\b[^\n]*--force\b`),
	re(String.raw`\bpm2\s+(?:delete|kill)\b`),
];

// pm2 stop/restart/reload only prompt over ssh (remote/prod); local dev pm2 is free.
const PM2_SOFT = re(String.raw`\bpm2\s+(?:stop|restart|reload)\b`);

// Inherently mutating database tooling always asks.
const DATABASE_ALWAYS = [
	re(
		String.raw`\b${EXE}(?:mysqladmin|createdb|dropdb|createuser|dropuser|pg_restore)\b`,
	),
	re(
		String.raw`\b(?:npx\s+)?(?:prisma|drizzle-kit|knex|sequelize(?:-cli)?|alembic|flyway|liquibase)\b`,
	),
];

// Query clients are allowed for read-only use; prompt only on write indicators
// or opaque script input (-f/--file/redirected stdin) the matcher cannot inspect.
const SQL_CLIENT = re(
	String.raw`\b${EXE}(?:psql|pgcli|mysql|mariadb|sqlite3|sqlcmd)\b`,
);
const SQL_WRITE = re(
	String.raw`\b(?:insert|update|delete|create|alter|drop|truncate|replace|grant|revoke|rename|load\s+data|into\s+outfile|attach)\b`,
);
const SQL_SCRIPT_INPUT = re(
	String.raw`\b${EXE}(?:psql|pgcli|mysql|mariadb|sqlite3|sqlcmd)\b[^\n;|&]*(?:<|\s-f\b|\s--file\b|\bsource\b|\.read\b|\.restore\b|\.import\b)`,
);
const REDIS_CLIENT = re(String.raw`\b${EXE}(?:redis-cli|valkey-cli)\b`);
const REDIS_WRITE = re(
	String.raw`\b(?:set|del|unlink|expire|persist|rename|move|migrate|restore|eval|evalsha|xadd|xdel|sadd|srem|hset|hdel|zadd|zrem|lpush|rpush|lpop|rpop|flushall|flushdb|config\s+set|script|copy|getset|getdel|incr|decr|append)\b`,
);
const MONGO_CLIENT = re(String.raw`\b${EXE}(?:mongosh|mongo)\b`);
const MONGO_WRITE = re(
	String.raw`\b(?:insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|replaceOne|bulkWrite|createIndex|dropIndex|dropDatabase|createCollection|renameCollection|findOneAndUpdate|findOneAndDelete|findOneAndReplace|findAndModify|save|drop|remove|insert|update)\s*\(`,
);

function isDatabaseDestructive(text: string): boolean {
	if (DATABASE_ALWAYS.some((pattern) => pattern.test(text))) return true;
	if (
		SQL_CLIENT.test(text) &&
		(SQL_WRITE.test(text) || SQL_SCRIPT_INPUT.test(text))
	)
		return true;
	if (REDIS_CLIENT.test(text) && REDIS_WRITE.test(text)) return true;
	if (MONGO_CLIENT.test(text) && MONGO_WRITE.test(text)) return true;
	return false;
}

// Over SSH, remote scripts can wrap DB access without a recognized client, so
// also catch SQL-statement-shaped text and standalone cache-wipe commands.
// Bare keywords like `set`/`update`/`create` alone are too noisy to flag.
const SSH_DATABASE_WRITE = [
	re(
		String.raw`\b(?:insert\s+into|delete\s+from|update\s+\S+\s+set|alter\s+table|drop\s+(?:table|database|index|schema|view)|truncate\s+table?|create\s+(?:table|database|index|schema|view)|grant\s+|revoke\s+|load\s+data|into\s+outfile)\b`,
	),
	re(String.raw`\b(?:flushall|flushdb|dropDatabase)\b`),
	re(
		String.raw`\b(?:insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|replaceOne|bulkWrite|createIndex|dropIndex|createCollection|renameCollection|findOneAndUpdate|findOneAndDelete|findOneAndReplace|findAndModify)\s*\(`,
	),
];

const PATTERNS = [...FILESYSTEM, ...GIT, ...RUNTIME];
const SSH_PATTERNS = [...FILESYSTEM, ...GIT, ...RUNTIME, ...SSH_DATABASE_WRITE];

// Heredoc bodies are data (file content), not executed commands — unless the
// receiver is a shell that will execute them. A data interpreter (python/node)
// receiving stdin — locally or over ssh — treats the body as data, not shell.
const HEREDOC_SHELL = /\b(?:bash|sh|zsh|ksh|dash|eval|source)\b/i;
const HEREDOC_DATA_INTERPRETER =
	/\b(?:python[\d.]*|node|deno|bun|ruby|perl|php)\b/i;
const HEREDOC_OPEN = /<<-?[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/;

function heredocBodyExecutes(openLine: string): boolean {
	if (HEREDOC_SHELL.test(openLine)) return true;
	if (HEREDOC_DATA_INTERPRETER.test(openLine)) return false;
	return /\bssh\b/i.test(openLine);
}

function stripHeredocBodies(text: string): string {
	const lines = text.split("\n");
	const out: string[] = [];
	let i = 0;
	while (i < lines.length) {
		const line = lines[i];
		out.push(line);
		const open = line.match(HEREDOC_OPEN);
		i += 1;
		if (!open || heredocBodyExecutes(line)) continue;
		const delimiter = open[2];
		while (i < lines.length && lines[i].trim() !== delimiter) i += 1;
		if (i < lines.length) {
			out.push(lines[i]);
			i += 1;
		}
	}
	return out.join("\n");
}

// Safe rm invocations: non-recursive removal of explicit files (no globs, no
// variables, not roots), or recursive removal strictly under temp dirs.
const RM_TOKEN = String.raw`(?:'[^'\n]*'|"[^"\n]*"|[^\s;|&<>()'"]+)`;
const RM_INVOCATION = re(
	String.raw`(^|[\n;&|'"][ \t]*)((?:\/(?:usr\/)?bin\/)?(?:rm|rmdir|unlink)(?:[ \t]+${RM_TOKEN})+)`,
	"gi",
);
const RM_SAFE_FLAG = /^(?:-[fv]+|--force)$/;
const RM_RECURSIVE_FLAG = /^(?:-[A-Za-z]*[rR][A-Za-z]*|--recursive)$/;
const RM_UNSAFE_TARGET = /[*?[\]$`\\]|^-|^[/~.]+$|^~|(?:^|\/)\.\.?(?:\/|$)/;
const TMP_DIR_TARGET = re(
	String.raw`^(?:\/private)?(?:\/tmp|\/var\/folders\/[^\/]+\/[^\/]+\/T)\/[A-Za-z0-9._-][A-Za-z0-9._\/-]*$`,
	"",
);
const SAFE_CD_TMP_RM = re(
	String.raw`^cd[ \t]+(?:\/private)?\/tmp(?:\/[A-Za-z0-9._-]+)*[ \t]*&&[ \t]*(?:\/(?:usr\/)?bin\/)?rm[ \t]+-(?:rf|fr)[ \t]+[A-Za-z0-9._-]+(?=[ \t]*(?:&&|$))`,
	"",
);

function stripSafeRmInvocations(text: string): string {
	return text.replace(
		RM_INVOCATION,
		(match, prefix: string, invocation: string) => {
			const tokens = invocation
				.replace(/^(?:\/(?:usr\/)?bin\/)?(?:rm|rmdir|unlink)/i, "")
				.trim()
				.split(/[ \t]+/)
				.filter(Boolean);
			if (tokens.some((t) => t === "--help" || t === "--version"))
				return `${prefix}true`;
			let recursive = false;
			const targets: string[] = [];
			for (const raw of tokens) {
				if (raw === "--") continue;
				if (/^-/.test(raw)) {
					if (RM_RECURSIVE_FLAG.test(raw)) {
						recursive = true;
						if (!/^-(?:rf|fr|[rR])$/.test(raw) && !/^--recursive$/.test(raw))
							return match;
					} else if (!RM_SAFE_FLAG.test(raw)) {
						return match;
					}
					continue;
				}
				const target = raw.replace(/^['"]|['"]$/g, "");
				if (!target || RM_UNSAFE_TARGET.test(target)) return match;
				targets.push(target);
			}
			if (targets.length === 0) return match;
			if (recursive && !targets.every((t) => TMP_DIR_TARGET.test(t)))
				return match;
			return `${prefix}true`;
		},
	);
}

// Data-only commands: their arguments are text/needles, never executed. Skipped
// entirely when the pipeline could feed that text into an executor or DB client.
const DATA_ARG_COMMANDS = re(
	String.raw`(^|[\n;&|'"][ \t]*|&&[ \t]*|\|\|[ \t]*)(?:\/usr\/bin\/)?(?:echo|printf|grep|egrep|fgrep|rg|ag|ack|man|whatis|apropos|type|which|sed|awk|jq|git[ \t]+(?:commit|log|grep|show|diff|blame))\b[^\n;|&]*`,
	"gi",
);
const PIPE_TO_EXECUTOR =
	/\|[ \t]*(?:sudo[ \t]+)?(?:bash|sh|zsh|ksh|dash|eval|xargs|ssh)\b/i;

function stripDataCommandArgs(text: string): string {
	if (
		PIPE_TO_EXECUTOR.test(text) ||
		SQL_CLIENT.test(text) ||
		REDIS_CLIENT.test(text) ||
		MONGO_CLIENT.test(text)
	)
		return text;
	return text.replace(DATA_ARG_COMMANDS, "$1true");
}

// Inline interpreter scripts (node -e / python -c) are data unless they reach
// for process/filesystem mutation APIs.
const INLINE_SCRIPT = re(
	String.raw`\b(?:node|deno|bun|python[\d.]*|ruby|perl)\b[^\n;|&]*?[ \t](?:-e|-c|--eval)[ \t]+('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")`,
	"gi",
);
const SCRIPT_EXEC_API =
	/child_process|execSync|spawn|\bexec\s*\(|os\.system|os\.remove|os\.unlink|os\.rmdir|shutil|subprocess|popen|fs\.(?:rm|unlink|rmdir)|rimraf|system\s*\(/i;

function stripInlineScripts(text: string): string {
	return text.replace(INLINE_SCRIPT, (match, literal: string) =>
		SCRIPT_EXEC_API.test(literal) ? match : match.replace(literal, "''"),
	);
}

// sudo itself is not destructive; strip the prefix and match what it wraps.
// `sudo rm -rf /` still flags via rm; `sudo head file` passes.
const SUDO_PREFIX = re(
	String.raw`(^|[\n;&|'"\`(]|&&|\|\|)([ \t]*)(?:\/(?:usr\/)?(?:local\/)?bin\/)?sudo\b(?:[ \t]+(?:-u[ \t]+\S+|-g[ \t]+\S+|--[\w-]+(?:=\S*)?|-[A-Za-z]+))*[ \t]+(?=\S)`,
	"gi",
);

function stripSudoPrefix(text: string): string {
	return text.replace(SUDO_PREFIX, "$1$2");
}

function sanitizeCommand(text: string): string {
	let result = stripHeredocBodies(text);
	result = stripDataCommandArgs(result);
	result = stripInlineScripts(result);
	result = stripSudoPrefix(result);
	result = result.replace(SAFE_CD_TMP_RM, "cd /tmp && true");
	return stripSafeRmInvocations(result);
}

/** Pure matcher used by tests and the tool_call handler. */
export function isDestructiveCommand(command: string): boolean {
	const original = command.trim();
	if (!original) return false;
	if (SAFE_CLIPBOARD_RM.test(original)) return false;
	if (SAFE_WORKTREE_RM.test(original)) return false;
	const text = sanitizeCommand(original);
	if (isDatabaseDestructive(text)) return true;
	// Inline scripts that survived stripping reference mutation APIs.
	for (const m of text.matchAll(INLINE_SCRIPT)) {
		if (SCRIPT_EXEC_API.test(m[1])) return true;
	}
	const isSsh = /^ssh\b/i.test(original);
	if (isSsh && PM2_SOFT.test(text)) return true;
	const patterns = isSsh ? SSH_PATTERNS : PATTERNS;
	return patterns.some((pattern) => pattern.test(text));
}

/** Load persisted allow patterns (glob: `*` matches anything, incl. newlines). */
export function loadAllowPatterns(path = ALLOWLIST_PATH): string[] {
	try {
		if (!existsSync(path)) return [];
		const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
		const allow = (parsed as { allow?: unknown })?.allow;
		return Array.isArray(allow)
			? allow.filter((entry): entry is string => typeof entry === "string")
			: [];
	} catch {
		return [];
	}
}

function saveAllowPattern(pattern: string, path = ALLOWLIST_PATH): void {
	const allow = loadAllowPatterns(path);
	if (allow.includes(pattern)) return;
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(
		path,
		`${JSON.stringify({ allow: [...allow, pattern] }, null, "\t")}\n`,
		"utf8",
	);
}

/** Glob match where `*` matches any text including newlines. SSH approvals must be exact. */
export function matchesAllowPattern(command: string, pattern: string): boolean {
	const normalizedPattern = pattern.trim();
	if (
		/^(?:\/usr\/bin\/)?ssh\b/u.test(normalizedPattern) &&
		normalizedPattern.includes("*")
	) {
		return false;
	}
	const escaped = normalizedPattern
		.replace(/[.+^${}()|[\]\\?]/g, "\\$&")
		.replace(/\*/g, "[\\s\\S]*");
	return new RegExp(`^${escaped}$`).test(command.trim());
}

/** Suggested persistent approval. SSH commands are always exact-command scoped. */
export function suggestAllowPattern(command: string): string {
	return command.trim();
}

/** One-line trimmed snippet for prompt labels/previews. */
export function trimSnippet(text: string, max = 80): string {
	const oneLine = text.trim().replace(/\s+/g, " ");
	return oneLine.length > max ? `${oneLine.slice(0, max - 1)}…` : oneLine;
}

// Hint generation: fast/cheap models explain what the command does and why
// it is risky. Best-effort — the prompt still shows if this fails.
const HINT_MODELS: Array<[string, string]> = [
	["cliproxyapi", "grok-4.5"],
	["cliproxyapi", "gpt-5.6-luna"],
];
const HINT_TIMEOUT_MS = 12_000;

// biome-ignore lint/suspicious/noExplicitAny: pi-ai types resolved at runtime
type HintCtx = {
	modelRegistry?: {
		find(provider: string, id: string): any;
		getProvider(provider: string): any;
		getApiKeyAndHeaders(model: unknown): Promise<{
			ok: boolean;
			apiKey?: string;
			headers?: Record<string, string>;
			env?: Record<string, string>;
		}>;
	};
};

// Temporary debug log for hint generation failures.
function hintLog(message: string): void {
	try {
		writeFileSync(
			join(homedir(), ".pi", "agent", "destructive-command-guard-hint.log"),
			`${new Date().toISOString()} ${message}\n`,
			{ flag: "a" },
		);
	} catch {}
}

async function generateHint(
	ctx: HintCtx,
	command: string,
): Promise<string | undefined> {
	if (!ctx.modelRegistry) {
		hintLog("no modelRegistry on ctx");
		return undefined;
	}
	const prompt = `You are a shell-safety assistant. In at most 2 short sentences, explain what this command does and why it might be dangerous (what could be lost or broken). Plain text only, no markdown.\n\nCommand:\n${command.slice(0, 4000)}`;
	for (const [provider, id] of HINT_MODELS) {
		try {
			const { uuidv7 } = await import("@earendil-works/pi-ai");
			const model = ctx.modelRegistry.find(provider, id);
			if (!model) {
				hintLog(`model not found: ${provider}/${id}`);
				continue;
			}
			const providerImpl = ctx.modelRegistry.getProvider(provider);
			if (!providerImpl?.streamSimple) {
				hintLog(`no streamSimple on provider: ${provider}`);
				continue;
			}
			const auth = await ctx.modelRegistry.getApiKeyAndHeaders(model);
			if (!auth.ok || !auth.apiKey) {
				hintLog(`auth failed for ${provider}/${id}`);
				continue;
			}
			const response = await providerImpl
				.streamSimple(
					model,
					{
						messages: [
							{
								role: "user" as const,
								content: [{ type: "text" as const, text: prompt }],
								timestamp: Date.now(),
							},
						],
					},
					{
						apiKey: auth.apiKey,
						headers: auth.headers,
						env: auth.env,
						maxTokens: 512,
						reasoning: "low",
						cacheRetention: "none",
						sessionId: uuidv7(),
						signal: AbortSignal.timeout(HINT_TIMEOUT_MS),
					},
				)
				.result();
			const text = response.content
				.filter(
					(c: any): c is { type: "text"; text: string } => c.type === "text",
				)
				.map((c: { text: string }) => c.text)
				.join("\n")
				.trim();
			if (text) return text;
			hintLog(`empty hint from ${provider}/${id}`);
		} catch (error) {
			hintLog(
				`${provider}/${id}: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`,
			);
		}
	}
	return undefined;
}

function extractCommand(toolName: string, input: unknown): string | undefined {
	if (
		!COMMAND_TOOLS.has(toolName.toLowerCase()) ||
		!input ||
		typeof input !== "object"
	) {
		return undefined;
	}
	const record = input as Record<string, unknown>;
	// bash/shell/ctx_shell use `command`; some aliases use `cmd`
	const value = record.command ?? record.cmd;
	return typeof value === "string" ? value : undefined;
}

type StatusContext = {
	ui: { setStatus?(key: string, text: string): void };
};

function setGuardStatus(ctx: StatusContext, text: string): void {
	try {
		ctx.ui.setStatus?.("destructive-command-guard", text);
	} catch {}
}

function readyStatus(allowlistPath: string): string {
	const count = loadAllowPatterns(allowlistPath).length;
	return count === 0
		? "Ready"
		: `Ready · ${count} saved ${count === 1 ? "rule" : "rules"}`;
}

export default function (pi: ExtensionAPI, allowlistPath = ALLOWLIST_PATH) {
	const sessionAllow: string[] = [];

	pi.on("session_start", (_event, ctx) => {
		setGuardStatus(ctx, readyStatus(allowlistPath));
	});

	pi.on("tool_call", async (event, ctx) => {
		const command = extractCommand(event.toolName, event.input);
		if (!command || !isDestructiveCommand(command)) {
			return undefined;
		}

		const allowPatterns = [
			...loadAllowPatterns(allowlistPath),
			...sessionAllow,
		];
		if (
			allowPatterns.some((pattern) => matchesAllowPattern(command, pattern))
		) {
			return undefined;
		}

		if (!ctx.hasUI) {
			return {
				block: true,
				reason: "Destructive command requires interactive approval",
			};
		}

		const suggested = suggestAllowPattern(command);
		const suggestedLabel = trimSnippet(suggested, 60);
		const shortPreview = trimSnippet(command, 200);
		const fullPreview =
			command.length > 4000 ? `${command.slice(0, 4000)}…` : command;
		const truncated = shortPreview !== command.trim();

		try {
			pi.events.emit("warp-pi-notify:approval-required", {
				toolName: event.toolName,
				command: shortPreview,
			});
		} catch {
			return {
				block: true,
				reason: "Destructive command approval notification failed",
			};
		}
		const hint = await generateHint(ctx as unknown as HintCtx, command);
		const hintBlock = hint ? `\nHint: ${hint}\n` : "";
		let showFull = false;
		setGuardStatus(ctx, "Approval pending");
		try {
			for (;;) {
				const options = [
					"Allow once",
					`Allow for this session: ${suggestedLabel}`,
					`Always allow: ${suggestedLabel}`,
					...(truncated && !showFull ? ["Show full command"] : []),
					"Deny",
				];
				const choice = await ctx.ui.select(
					`Destructive command\nTool: ${event.toolName}\n\n${showFull ? fullPreview : shortPreview}\n${hintBlock}\nAllow this command?`,
					options,
				);

				if (choice === "Show full command") {
					showFull = true;
					continue;
				}
				if (choice === options[0]) return undefined;
				if (choice === options[1]) {
					sessionAllow.push(suggested);
					return undefined;
				}
				if (choice === options[2]) {
					const confirmed = await ctx.ui.confirm(
						"Persist destructive-command approval?",
						`Always allow this pattern?\n\n${suggested}`,
					);
					if (!confirmed) {
						return {
							block: true,
							reason: "Destructive command blocked by user",
						};
					}
					saveAllowPattern(suggested, allowlistPath);
					return undefined;
				}
				return { block: true, reason: "Destructive command blocked by user" };
			}
		} catch {
			return { block: true, reason: "Destructive command approval UI failed" };
		} finally {
			setGuardStatus(ctx, readyStatus(allowlistPath));
		}
	});

	pi.registerCommand("destructive-allowlist", {
		description: "Show saved destructive-command allow patterns",
		handler: async (
			_args: unknown,
			ctx: { ui: { notify(msg: string, type?: string): void } },
		) => {
			const saved = loadAllowPatterns(allowlistPath);
			ctx.ui.notify(
				[
					`Saved (${allowlistPath}):`,
					...(saved.length ? saved.map((p) => `  ${p}`) : ["  (none)"]),
					"Session:",
					...(sessionAllow.length
						? sessionAllow.map((p) => `  ${p}`)
						: ["  (none)"]),
				].join("\n"),
				"info",
			);
		},
	});
}
