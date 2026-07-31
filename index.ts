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

// Filesystem / system
const FILESYSTEM = [
	re(String.raw`\b${EXE}(?:rm|rmdir|unlink|shred|truncate)\b`),
	re(String.raw`\b${EXE}find\b[\s\S]*\s-delete\b`),
	re(String.raw`\b${EXE}(?:dd|mkfs(?:\.\w+)?)\b`),
	re(
		String.raw`\b${EXE}diskutil\b.*\b(?:erase|partition|reformat|unmountForce|apfs\s+delete)\b`,
	),
	re(String.raw`\b${EXE}(?:sudo|chmod|chown)\b`),
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
const RUNTIME = [
	re(String.raw`\b${EXE}kill\b(?![ \t]+-0\b)`),
	re(String.raw`\b${EXE}(?:killall|pkill)\b`),
	re(
		String.raw`\bdocker(?:-compose|\s+compose)?\s+(?:rm|rmi|down|prune|volume\s+(?:rm|prune)|system\s+prune)\b`,
	),
	re(String.raw`\bkubectl\s+(?:delete|drain)\b`),
	re(String.raw`\bkubectl\s+replace\b[^\n]*--force\b`),
	re(String.raw`\bpm2\s+(?:delete|stop|restart|reload|kill)\b`),
];

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
// receiving command is a shell/ssh that will execute them.
const HEREDOC_INTERPRETER = /\b(?:ssh|bash|sh|zsh|ksh|dash|eval|source)\b/i;
const HEREDOC_OPEN = /<<-?[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/;

function stripHeredocBodies(text: string): string {
	const lines = text.split("\n");
	const out: string[] = [];
	let i = 0;
	while (i < lines.length) {
		const line = lines[i];
		out.push(line);
		const open = line.match(HEREDOC_OPEN);
		i += 1;
		if (!open || HEREDOC_INTERPRETER.test(line)) continue;
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
	String.raw`(^|[\n;&|][ \t]*)((?:\/(?:usr\/)?bin\/)?rm(?:[ \t]+${RM_TOKEN})+)`,
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
				.replace(/^(?:\/(?:usr\/)?bin\/)?rm/i, "")
				.trim()
				.split(/[ \t]+/)
				.filter(Boolean);
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

function sanitizeCommand(text: string): string {
	let result = stripHeredocBodies(text);
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
	const patterns = /^ssh\b/i.test(original) ? SSH_PATTERNS : PATTERNS;
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

/** Glob match where `*` matches any text including newlines. */
export function matchesAllowPattern(command: string, pattern: string): boolean {
	const escaped = pattern
		.trim()
		.replace(/[.+^${}()|[\]\\?]/g, "\\$&")
		.replace(/\*/g, "[\\s\\S]*");
	return new RegExp(`^${escaped}$`).test(command.trim());
}

/**
 * Suggested "always allow" pattern for a command. For SSH commands this is
 * scoped to the destination (`ssh <alias> *`); otherwise the exact command.
 */
export function suggestAllowPattern(command: string): string {
	const text = command.trim();
	const ssh = text.match(
		/^((?:\/usr\/bin\/)?ssh)\s+((?:-\S+\s+)*)([A-Za-z0-9_.@-]+)\b/,
	);
	if (ssh) return `${ssh[1]} ${ssh[2]}${ssh[3]} *`;
	return text;
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
				.filter((c: any): c is { type: "text"; text: string } => c.type === "text")
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

export default function (pi: ExtensionAPI) {
	const sessionAllow: string[] = [];

	pi.on("tool_call", async (event, ctx) => {
		const command = extractCommand(event.toolName, event.input);
		if (!command || !isDestructiveCommand(command)) {
			return undefined;
		}

		const allowPatterns = [...loadAllowPatterns(), ...sessionAllow];
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

		pi.events.emit("warp-pi-notify:approval-required", {});
		const hint = await generateHint(ctx as unknown as HintCtx, command);
		const hintBlock = hint ? `\nHint: ${hint}\n` : "";
		let showFull = false;
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
				saveAllowPattern(suggested);
				return undefined;
			}
			return { block: true, reason: "Destructive command blocked by user" };
		}
	});

	pi.registerCommand("destructive-allowlist", {
		description: "Show saved destructive-command allow patterns",
		handler: async (
			_args: unknown,
			ctx: { ui: { notify(msg: string, type?: string): void } },
		) => {
			const saved = loadAllowPatterns();
			ctx.ui.notify(
				[
					`Saved (${ALLOWLIST_PATH}):`,
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
