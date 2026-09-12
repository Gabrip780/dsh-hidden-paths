/**
 * dsh-hidden-paths — a DeepSeek Harness (Cordis) security plugin.
 *
 * PURPOSE
 *   Deny an AI agent access (reads *and* writes) to secret-bearing files —
 *   `.env` files, credential stores, key material — and to any folder or file
 *   the user lists in `hiddenPaths`. It covers the surfaces an agent uses:
 *
 *     1. file tools   -> matched on their path arguments, resolved against the
 *                        calling session's cwd;
 *     2. shell tools  -> the command text is scanned for path-like tokens;
 *     3. search tools -> the `pattern`/`include` selectors are scanned too;
 *     4. run_code     -> the code text is scanned conservatively (see LIMITS).
 *
 * ENFORCEMENT MECHANISM
 *   `ctx.tools.guard()` — a MONOTONIC guard evaluated after the extensible
 *   `tools/pre-execute` waterfall. A returned reason denies the call before the
 *   tool body runs, and NO later listener can turn that denial back into
 *   permission. It applies to every agent in the tree (subagents included) and
 *   to `run_code` sub-dispatches, which traverse the same pipeline.
 *
 * HONEST THREAT MODEL — READ THIS
 *   This is a policy guard over a cooperative runtime, NOT a kernel boundary.
 *   It stops accidents, prompt-injected "please cat my .env", and routine
 *   overreach. It does NOT stop a determined adversary:
 *     - shell analysis is textual: an interpreter (`python -c ...`), a variable,
 *       base64, `find -exec`, `env`/`printenv`, a hardlink, or `/proc` can reach
 *       the same bytes without naming a protected path;
 *     - `run_code` executes arbitrary code with Node's full API; only literal
 *       path spellings in its text are caught, so it remains a real bypass;
 *     - the default NAME rules match basenames and never resolve symlinks, so a
 *       symlink with an innocent name pointing at a secret is not caught
 *       (configured `hiddenPaths` DO resolve symlinks, including through a link
 *       whose leaf does not exist yet);
 *     - everything the agent can read, it can copy elsewhere.
 *   Pair it with the DSH sandbox, keep critical secrets outside the workspace,
 *   or run dsh as a different user.
 *
 * DEPENDENCIES: only Node built-ins (`node:path`, `node:os`, `node:fs`).
 * The only filesystem call is `realpathSync` on a path the guard is already
 * deciding about — metadata, never file content. No network, no process
 * spawning, no `eval`.
 */

import path from "node:path";
import os from "node:os";
import { realpathSync } from "node:fs";

/** User-visible name, kept in one place so messages never drift. */
const PLUGIN_NAME = "dsh-hidden-paths";

/** Tool names whose command text is scanned as shell input. */
const SHELL_TOOLS = new Set([
	"bash",
	"sh",
	"shell",
	"zsh",
	"terminal",
	"pwsh",
	"powershell",
	"cmd",
]);

/** Tool names that execute code text (scanned conservatively). */
const CODE_TOOLS = new Set(["run_code"]);

/** Tools whose selector arguments can name files. */
const SEARCH_TOOLS = new Set(["glob", "grep"]);

/** Argument keys that carry shell command text. */
const COMMAND_ARG_KEYS = ["command", "program", "script", "cmd"];

/** Argument keys that carry executable code text. */
const CODE_ARG_KEYS = ["code", "script"];

/** Argument keys that carry a file selector expression. */
const SEARCH_ARG_KEYS = ["pattern", "include", "exclude"];

/**
 * Argument keys that carry a filesystem path on ANY tool. Key-based rather than
 * tool-based, so a tool the plugin has never heard of still gets its path
 * arguments checked. `workdir`/`cwd` matter because a shell tool can be pointed
 * at a directory whose contents are then read by a command that never names it.
 */
const PATH_ARG_KEYS = [
	"file_path",
	"path",
	"directory",
	"dir",
	"file",
	"target",
	"workdir",
	"cwd",
];

/**
 * Files that are safe examples/templates: never protected. Checked before any
 * deny rule, so `.env.example` stays readable while `.env` does not.
 */
const ALLOW_BASENAMES = [
	".env.example",
	".env.sample",
	".env.template",
	".env.dist",
	".env.default",
	".env.test",
];

/**
 * Protected basenames, expressed as globs (`*` = any run, `?` = one char).
 * Matched case-insensitively against the file's basename.
 *
 * Deliberately data-file shapes, not `*secret*`: a broad glob would also block
 * ordinary source files such as `secrets.ts` or `credentials-manager.py`.
 */
const DEFAULT_NAME_RULES = [
	// --- environment / dotenv files -------------------------------------
	{ id: "env-file", match: ".env", reason: "dotenv file: may hold live secrets" },
	{ id: "env-variant", match: ".env.*", reason: "environment-specific secret file" },
	{ id: "env-suffixed", match: "*.env", reason: "non-standard dotenv file" },
	{ id: "env-suffixed-variant", match: "*.env.*", reason: "dotenv backup or variant file" },
	{ id: "tfvars", match: "*.tfvars", reason: "Terraform variables often hold secrets" },
	{ id: "tfvars-json", match: "*.tfvars.json", reason: "Terraform variables often hold secrets" },
	// --- credential stores ----------------------------------------------
	{ id: "npmrc", match: ".npmrc", reason: "npm registry auth token" },
	{ id: "netrc", match: ".netrc", reason: "machine credentials" },
	{ id: "pypirc", match: ".pypirc", reason: "PyPI upload token" },
	{ id: "git-credentials", match: ".git-credentials", reason: "stored git credentials" },
	{ id: "credentials", match: "credentials", reason: "credential store" },
	{ id: "credentials-json", match: "credentials.json", reason: "credential store" },
	{ id: "credentials-yaml", match: "credentials.yaml", reason: "credential store" },
	{ id: "credentials-yml", match: "credentials.yml", reason: "credential store" },
	{ id: "credentials-txt", match: "credentials.txt", reason: "credential store" },
	{ id: "credentials-dot", match: ".credentials*", reason: "credential store" },
	{ id: "secrets", match: "secrets", reason: "secret store" },
	{ id: "secrets-json", match: "secrets.json", reason: "secret store" },
	{ id: "secrets-yaml", match: "secrets.yaml", reason: "secret store" },
	{ id: "secrets-yml", match: "secrets.yml", reason: "secret store" },
	{ id: "secrets-txt", match: "secrets.txt", reason: "secret store" },
	{ id: "secrets-dot", match: ".secrets*", reason: "secret store" },
	{ id: "token-txt", match: "token.txt", reason: "token file" },
	{ id: "tokens-txt", match: "tokens.txt", reason: "token file" },
	{ id: "api-keys-txt", match: "api-keys.txt", reason: "API key file" },
	{ id: "api-keys-underscore", match: "api_keys.txt", reason: "API key file" },
	{ id: "service-account", match: "*service-account*.json", reason: "cloud service-account key" },
	{ id: "pgpass", match: ".pgpass", reason: "PostgreSQL password file" },
	{ id: "htpasswd", match: ".htpasswd", reason: "password file" },
	{ id: "dockercfg", match: ".dockercfg", reason: "registry auth token" },
	// --- private keys ----------------------------------------------------
	{ id: "ssh-id-rsa", match: "id_rsa*", reason: "SSH private key" },
	{ id: "ssh-id-ed25519", match: "id_ed25519*", reason: "SSH private key" },
	{ id: "ssh-id-ecdsa", match: "id_ecdsa*", reason: "SSH private key" },
	{ id: "ssh-id-dsa", match: "id_dsa*", reason: "SSH private key" },
	{ id: "key-pem", match: "*.pem", reason: "key or certificate material" },
	{ id: "key-key", match: "*.key", reason: "private key material" },
	{ id: "key-ppk", match: "*.ppk", reason: "PuTTY private key" },
	{ id: "key-p12", match: "*.p12", reason: "key store" },
	{ id: "key-pfx", match: "*.pfx", reason: "key store" },
	{ id: "key-jks", match: "*.jks", reason: "Java key store" },
	{ id: "key-keystore", match: "*.keystore", reason: "key store" },
	{ id: "key-kdbx", match: "*.kdbx", reason: "password database" },
];

/**
 * Directory segments protected wherever they appear in a path, so the whole
 * subtree is off-limits.
 */
const DEFAULT_DIR_SEGMENTS = [
	{ id: "ssh-dir", match: ".ssh", reason: "SSH config and keys" },
	{ id: "aws-dir", match: ".aws", reason: "AWS credentials" },
	{ id: "gnupg-dir", match: ".gnupg", reason: "GnuPG keyring" },
	{ id: "kube-dir", match: ".kube", reason: "Kubernetes config: cluster credentials" },
	{ id: "docker-dir", match: ".docker", reason: "registry credentials" },
	{ id: "secret-guard-dir", match: ".secret-guard", reason: "guard storage: seal key and audit journal" },
	{ id: "secrets-dir", match: "secrets", reason: "secrets directory" },
	{ id: "secrets-dot-dir", match: ".secrets", reason: "secrets directory" },
	{ id: "credentials-dir", match: "credentials", reason: "credential store directory" },
];

/** Extensions that make a token obviously a secret-bearing file. */
const PROTECTED_EXTENSION = /\.(?:env|pem|key|ppk|p12|pfx|jks|keystore|kdbx|npmrc|netrc|pypirc)$/i;

/** Bare names that are protected without any extension. */
const BARE_PROTECTED_NAME = /^(?:credentials|secrets)$/i;

/** Cache of compiled globs, keyed by the glob source. */
const globCache = new Map();

/** Compile a `*`/`?` glob into an anchored, case-insensitive RegExp. */
function globToRegExp(glob) {
	const cached = globCache.get(glob);
	if (cached !== undefined) return cached;
	let out = "";
	for (const ch of glob) {
		if (ch === "*") out += ".*";
		else if (ch === "?") out += ".";
		else out += /[|\\{}()[\]^$+.]/.test(ch) ? `\\${ch}` : ch;
	}
	const re = new RegExp(`^${out}$`, "i");
	globCache.set(glob, re);
	return re;
}

/** The literal text of a glob up to its first wildcard (`cat .e*` -> `.e`). */
function globLiteralPrefix(glob) {
	const at = glob.search(/[*?]/);
	return at === -1 ? glob : glob.slice(0, at);
}

/** Last path segment of a candidate, for both separators. */
function basename(candidate) {
	const normalized = candidate.replaceAll("\\", "/").replace(/\/+$/, "");
	const at = normalized.lastIndexOf("/");
	return at === -1 ? normalized : normalized.slice(at + 1);
}

/** Path segments of a candidate, both separators, blanks removed. */
function segments(candidate) {
	return candidate
		.replaceAll("\\", "/")
		.split("/")
		.filter((segment) => segment !== "" && segment !== ".");
}

/**
 * Normalise a config value into an array.
 *
 * A guard must never be silently disarmed by a config typo. `hiddenPaths: "/x"`
 * used to spread into its characters, producing nonsense roots and leaving the
 * path UNPROTECTED. A string is now read as the single entry the author meant,
 * and anything else (number, object, boolean) is ignored with a warning.
 */
export function asArray(value) {
	if (value === undefined || value === null) return [];
	if (Array.isArray(value)) return value;
	if (typeof value === "string") return value.trim() === "" ? [] : [value];
	return [];
}

/**
 * Expand `~`, `$HOME` and `${HOME}` so shell text resolves like the shell
 * would, then resolve relative candidates against a base directory.
 */
function resolveCandidate(raw, base) {
	let value = raw.replace(/^["']|["']$/g, "");
	const home = os.homedir();
	value = value.replace(/^\$\{HOME\}/, home).replace(/^\$HOME/, home);
	value = value.replace(/^~(?=\/|$)/, home);
	const root = base ?? process.cwd();
	return path.normalize(path.isAbsolute(value) ? value : path.resolve(root, value));
}

/**
 * Decode the escape sequences of an ANSI-C quoted string (`$'...'`), which a
 * shell uses to build a name without writing it literally
 * (`$'\x2eenv'` is `.env`).
 */
function decodeAnsiC(body) {
	return body
		.replace(/\\x([0-9a-fA-F]{2})/g, (_m, hex) => String.fromCharCode(parseInt(hex, 16)))
		.replace(/\\([0-7]{1,3})/g, (_m, oct) => String.fromCharCode(parseInt(oct, 8)))
		.replace(/\\n/g, "\n")
		.replace(/\\t/g, "\t")
		.replace(/\\r/g, "\r");
}

/**
 * Normalise shell text the way the shell will: decode `$'...'` escapes, then
 * drop quote characters and backslashes IN PLACE.
 *
 * Replacing a quoted span with a space — the previous approach — let
 * one-character obfuscation through: `.en''v`, `"sec"rets` and `.en\v` all
 * reach `.env` while naming no protected token. Joining the fragments instead
 * closes that.
 */
export function normalizeShellText(text) {
	if (typeof text !== "string") return "";
	return text
		.replace(/\$'((?:[^'\\]|\\.)*)'/g, (_m, body) => decodeAnsiC(body))
		.replace(/["']/g, "")
		.replace(/\\(?=.)/g, "");
}

/**
 * Split shell text into candidates: quoted spans taken verbatim (so a path with
 * spaces survives) plus the tokens of the normalised text (so spliced and
 * escaped spellings are seen joined). Returns `{ value, quoted, obfuscated }`.
 *
 * `obfuscated` marks a token that exists only AFTER quotes were removed, i.e.
 * one assembled across quote boundaries (`"sec"rets`). Those are treated
 * strictly, so ordinary prose inside quotes cannot be mistaken for a filename
 * while joined spellings are still inspected.
 */
export function shellCandidates(command) {
	const found = [];
	for (const match of command.matchAll(/"([^"]*)"|'([^']*)'/g)) {
		const quoted = (match[1] ?? match[2] ?? "").trim();
		if (quoted !== "") found.push({ value: quoted, quoted: true, obfuscated: false });
	}
	const plainTokens = new Set(
		command
			.replace(/"[^"]*"|'[^']*'/g, " ")
			.replace(/\\/g, "")
			.split(/[\s;|&()<>`]+/)
			.filter((token) => token !== ""),
	);
	// Words that live inside a quoted span: a word of prose is not a filename, so
	// the normalised pass skips them (the verbatim span above still inspects the
	// whole quoted string).
	const quotedWords = new Set();
	for (const match of command.matchAll(/"([^"]*)"|'([^']*)'/g)) {
		for (const word of (match[1] ?? match[2] ?? "").split(/\s+/)) if (word !== "") quotedWords.add(word);
	}
	for (const token of normalizeShellText(command).split(/[\s;|&()<>`]+/)) {
		const value = token.trim();
		if (value === "") continue;
		found.push({ value, quoted: false, obfuscated: !plainTokens.has(value), fromQuote: quotedWords.has(value) });
	}
	const seen = new Set();
	return found.filter(({ value, quoted }) => {
		const key = `${quoted ? "q" : "b"}:${value}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
}

/**
 * Expand the spellings a shell token can produce through bracket and brace
 * expansion: `.en[v]` -> `.env`, `.{env,foo}` -> `.env`.
 *
 * Three kinds of variant are produced, and the literal expansion iterates to a
 * bounded fixed point so composed forms such as `.{en,fo}{v,x}` are covered:
 *   - every bracket/brace group collapsed to `?`, which a negated class such as
 *     `[!x]` needs because it matches characters that cannot be enumerated;
 *   - the class contents kept, and the class dropped;
 *   - each brace alternative.
 */
export function expandShellToken(token) {
	if (!/[[\]{}]/.test(token)) return [token];
	const variants = new Set([
		token,
		token.replace(/\[[^\]]*\]/g, "?"),
		token.replace(/\{[^{}]*\}/g, "?"),
	]);
	let frontier = [token];
	for (let pass = 0; pass < 3 && frontier.length > 0 && variants.size < 64; pass++) {
		const next = [];
		for (const current of frontier) {
			const bracket = current.match(/\[([^\]]*)\]/);
			if (bracket) next.push(current.replace(bracket[0], bracket[1]), current.replace(bracket[0], ""));
			const brace = current.match(/\{([^{}]*)\}/);
			if (brace) for (const alternative of brace[1].split(",")) next.push(current.replace(brace[0], alternative));
		}
		for (const variant of next) variants.add(variant);
		frontier = next;
	}
	return [...variants].filter((variant) => variant !== "");
}

/**
 * Whether a token is worth classifying as a path.
 *
 * `strict` is used for code text and search patterns, where a bare identifier
 * like `secrets` is a variable or a search term far more often than a file.
 * A token containing whitespace counts as a path only when it also contains a
 * separator, so quoted prose ending in `.env` is not treated as a filename.
 */
export function looksLikePath(token, options = {}) {
	const { strict = false } = options;
	if (token.includes("/") || token.includes("\\")) return true;
	if (/\s/.test(token)) return false;
	if (token.startsWith(".") || token.startsWith("~") || token.startsWith("$")) return true;
	if (/[*?[\]{}]/.test(token)) return true;
	if (PROTECTED_EXTENSION.test(token)) return true;
	if (/^id_(?:rsa|ed25519|ecdsa|dsa)/i.test(token)) return true;
	// Any filename-shaped token (a short extension tail) is worth classifying.
	if (/\.[A-Za-z0-9]{1,8}$/.test(token)) return true;
	if (strict) return false;
	return BARE_PROTECTED_NAME.test(token);
}

/** `realpathSync` that never throws: the guard must decide even for absent paths. */
function realPath(candidate) {
	try {
		return realpathSync(candidate);
	} catch {
		return undefined;
	}
}

/**
 * Resolve symlinks along the LONGEST EXISTING PREFIX of a path, then re-append
 * the part that does not exist yet.
 *
 * `realpathSync` throws on a missing path, so resolving only the full path
 * missed `write /link-to-secret/not-yet-there.txt`. Walking up to the nearest
 * existing ancestor closes it.
 */
export function realPathOfNearestExisting(candidate) {
	let current = candidate;
	for (let depth = 0; depth < 64; depth++) {
		const real = realPath(current);
		if (real !== undefined) {
			const remainder = candidate.slice(current.length);
			return remainder === "" ? real : real + remainder;
		}
		const parent = path.dirname(current);
		if (parent === current) return undefined;
		current = parent;
	}
	return undefined;
}

/** True when `candidate` is `root` itself or a descendant of it. */
function underRoot(candidate, root) {
	if (root === path.sep) return candidate.startsWith(path.sep);
	const withSep = root.endsWith(path.sep) ? root : root + path.sep;
	return candidate === root || candidate.startsWith(withSep);
}

/** Compile one shell glob SEGMENT (`*.env`, `va?t`, `[!x]`, `{a,b}`) to a RegExp. */
function globSegmentToRegex(segment) {
	let out = "";
	for (let i = 0; i < segment.length; i++) {
		const ch = segment[i];
		if (ch === "*") out += "[^/]*";
		else if (ch === "?") out += "[^/]";
		else if (ch === "[") {
			const end = segment.indexOf("]", i + 1);
			if (end === -1) out += "\\[";
			else {
				let body = segment.slice(i + 1, end);
				if (body.startsWith("!")) body = "^" + body.slice(1);
				out += `[${body}]`;
				i = end;
			}
		} else if (ch === "{") {
			const end = segment.indexOf("}", i + 1);
			if (end === -1) out += "\\{";
			else {
				out += `(?:${segment.slice(i + 1, end).split(",").map(escapeRegExp).join("|")})`;
				i = end;
			}
		} else out += /[.+^$()|\\]/.test(ch) ? `\\${ch}` : ch;
	}
	return new RegExp(`^${out}$`, "i");
}

/**
 * True when a glob token could reach a configured hidden path.
 *
 * A command like `cat /srv/&#42;/note.txt` names no hidden path and resolves to no
 * hidden path, yet the shell expands it to `/srv/vault/note.txt`. Two cases
 * matter:
 *   - the glob has components after it, so it can descend INTO a directory: deny
 *     when a hidden root lives under the literal prefix;
 *   - the glob is the final component, so it can name the hidden entry itself:
 *     deny when a root's parent is the prefix and its name matches the segment.
 */
export function globCouldReachRoot(token, base, roots) {
	if (roots.length === 0 || !/[*?[\]{}]/.test(token)) return false;
	const parts = token.replaceAll("\\", "/").split("/");
	let globIndex = -1;
	for (let i = 0; i < parts.length; i++) {
		if (/[*?[\]{}]/.test(parts[i])) {
			globIndex = i;
			break;
		}
	}
	if (globIndex === -1) return false;
	const literal = parts.slice(0, globIndex).join("/");
	const prefixPath = path.resolve(base ?? process.cwd(), literal === "" ? "." : literal);
	const tail = parts.slice(globIndex + 1).filter((part) => part !== "");
	if (tail.length > 0) return roots.some((root) => underRoot(root, prefixPath));
	const re = globSegmentToRegex(parts[globIndex]);
	return roots.some((root) => path.dirname(root) === prefixPath && re.test(path.basename(root)));
}

/**
 * Every directory a command's own `cd` calls can put it in, cumulatively, so a
 * relative token is resolved against them too. In
 * `cd /srv && cat vault/note.txt` the hidden path is named only after the `cd`.
 */
export function cdTargets(command, base) {
	const tokens = normalizeShellText(command)
		.split(/[\s;|&()<>`]+/)
		.filter((token) => token !== "");
	const targets = [];
	for (let i = 0; i < tokens.length - 1; i++) {
		if (tokens[i] !== "cd") continue;
		const from = targets.length > 0 ? targets[targets.length - 1] : base ?? process.cwd();
		targets.push(resolveCandidate(tokens[i + 1], from));
	}
	return targets;
}

/**
 * The configured hidden paths, normalised and de-duplicated.
 * `hiddenPaths` is the user-facing key; `guardRoots` is the original name of
 * the same feature and stays accepted so an existing config keeps working.
 */
export function hiddenPathList(config = {}) {
	const all = [...asArray(config.hiddenPaths), ...asArray(config.guardRoots)]
		.map((value) => String(value).trim())
		.filter((value) => value !== "")
		.map((value) => path.resolve(value));
	return [...new Set(all)];
}

/**
 * Config smells worth telling the operator about, so a typo cannot silently
 * remove protection. Returns human-readable warnings.
 */
export function inspectConfig(config = {}) {
	const issues = [];
	if (config.hiddenPaths !== undefined && !Array.isArray(config.hiddenPaths)) {
		issues.push(
			`config.hiddenPaths should be an array of absolute paths; received ${typeof config.hiddenPaths}. ` +
				`It was read as a single entry.`,
		);
	}
	const raw = [...asArray(config.hiddenPaths), ...asArray(config.guardRoots)]
		.map((value) => String(value).trim())
		.filter((value) => value !== "");
	for (const entry of raw) {
		if (!path.isAbsolute(entry)) {
			issues.push(
				`config path '${entry}' is not absolute; it was resolved against ${process.cwd()}, ` +
					`which may not be what you meant.`,
			);
		}
		if (/[*?[\]{}]/.test(entry)) {
			issues.push(
				`config path '${entry}' contains a glob; hidden paths are matched literally, so this ` +
					`entry protects nothing. List the real path instead.`,
			);
		}
	}
	// Compare NORMALISED paths, so respellings of the root (`//`, `/./`, `/tmp/..`)
	// are caught as well as a literal `/`.
	const normalised = raw.map((entry) => path.resolve(entry));
	if (normalised.some((entry) => entry === path.sep)) {
		issues.push(
			"a configured hidden path is the filesystem root: every absolute path is hidden and the agent cannot work.",
		);
	}
	return issues;
}

/**
 * The policy decision for one already-resolved candidate path.
 * Returns a matched rule descriptor, or `undefined` when allowed.
 *
 * ORDER MATTERS. Configured `hiddenPaths` are checked BEFORE the allow list, so
 * an allow pattern can never re-open something the operator explicitly hid —
 * including through a symlink. The allow list then wins over name/dir rules.
 */
function classify(candidate, rules, roots, allow, resolveReal = realPathOfNearestExisting) {
	const base = basename(candidate);
	const segs = segments(candidate);

	// 1. Configured hidden paths: the path itself (a file) or a directory and
	//    its whole subtree, compared literally and after symlink resolution.
	if (roots.length > 0) {
		const resolvedCandidate = resolveReal(candidate);
		for (const root of roots) {
			if (underRoot(candidate, root)) {
				return { id: "hidden-path", reason: `configured hidden path ${root}` };
			}
			if (resolvedCandidate !== undefined) {
				const resolvedRoot = resolveReal(root);
				if (resolvedRoot !== undefined && underRoot(resolvedCandidate, resolvedRoot)) {
					return { id: "hidden-path", reason: `configured hidden path ${root} (reached through a symlink)` };
				}
			}
		}
	}

	// 2. Explicit allow entries win over every name/dir rule.
	for (const pattern of allow) {
		if (globToRegExp(pattern).test(base)) return undefined;
		if (globToRegExp(pattern).test(candidate)) return undefined;
	}

	// 3. A protected directory anywhere in the path protects the whole subtree.
	for (const rule of rules.dirs) {
		if (segs.some((segment) => segment.toLowerCase() === rule.match.toLowerCase())) {
			return rule;
		}
	}

	// 4. Basename rules.
	for (const rule of rules.names) {
		if (globToRegExp(rule.match).test(base)) return rule;
	}

	// 5. Glob heuristic: `cat .e*` and `cat .*` name no protected file
	//    literally, but their expansion cannot escape the literal prefix, so a
	//    prefix that covers a protected name is denied.
	//
	//    The threshold is two characters — or a bare `.`, which covers every
	//    dotfile — because a single-letter prefix like `c*` or `s*` would deny
	//    ordinary listing work while adding almost no protection.
	if (/[*?]/.test(base)) {
		const prefix = globLiteralPrefix(base);
		if (prefix.length >= 2 || prefix === ".") {
			const covers = rules.names.some((rule) =>
				globLiteralPrefix(rule.match).toLowerCase().startsWith(prefix.toLowerCase()),
			);
			if (covers) {
				return { id: "glob-expansion", reason: `glob '${base}' may expand to a protected file` };
			}
		}
	}

	return undefined;
}

/** Build the guard configuration from the plugin row's `config`. */
export function createGuard(config = {}) {
	const roots = hiddenPathList(config);
	const allow = [...ALLOW_BASENAMES, ...asArray(config.allow).map(String)];
	const names = [
		...DEFAULT_NAME_RULES,
		...asArray(config.extraNameRules).map((entry, index) =>
			typeof entry === "string"
				? { id: `custom-${index}`, match: entry, reason: "custom rule" }
				: {
						id: String(entry?.id ?? `custom-${index}`),
						match: String(entry?.match ?? ""),
						reason: String(entry?.reason ?? "custom rule"),
					},
		),
	].filter((rule) => rule.match !== "");
	const dirs = [
		...DEFAULT_DIR_SEGMENTS,
		...asArray(config.extraDirSegments).map((entry) => ({
			id: "custom-dir",
			match: String(entry),
			reason: "custom directory rule",
		})),
	].filter((rule) => rule.match !== "");

	const rules = { names, dirs };

	// Symlink resolution is a filesystem call; memoise it per tool invocation so a
	// command with many tokens and many configured roots does not pay
	// (1 + roots) realpath walks per token.
	let realCache = new Map();
	const cachedRealPath = (candidate) => {
		if (realCache.has(candidate)) return realCache.get(candidate);
		const resolved = realPathOfNearestExisting(candidate);
		realCache.set(candidate, resolved);
		return resolved;
	};

	/** Classify one resolved candidate; returns `{ hit, target }` or undefined. */
	const findHit = (resolved, target) => {
		const hit = classify(resolved, rules, roots, allow, cachedRealPath);
		return hit === undefined ? undefined : { hit, target };
	};

	/**
	 * Scan text tokens against every base directory the text can run in. All
	 * bases are tried, because a command may `cd` before naming a relative path.
	 */
	const scanText = (text, bases, strict) => {
		for (const candidate of shellCandidates(text)) {
			if (candidate.fromQuote === true) continue;
			for (const variant of expandShellToken(candidate.value)) {
				if (!looksLikePath(variant, { strict: strict || candidate.obfuscated })) continue;
				for (const base of bases) {
					const found = findHit(resolveCandidate(variant, base), variant);
					if (found !== undefined) return found;
					if (globCouldReachRoot(variant, base, roots)) {
						return {
							hit: { id: "hidden-glob", reason: "glob could expand onto a configured hidden path" },
							target: variant,
						};
					}
				}
			}
		}
		return undefined;
	};

	return (exec) => {
		const tool = String(exec?.name ?? "");
		const args = exec?.arguments;
		if (args === null || args === undefined) return undefined;
		const cwd = exec?.agent?.session?.header?.cwd ?? process.cwd();
		realCache = new Map();

		try {
			// A malformed argument is inspected rather than waved through: a raw
			// string, or an array of strings, may itself name a path.
			if (typeof args === "string") {
				const found = scanText(args, [cwd], true);
				return found === undefined ? undefined : denial(tool, found.target, found.hit);
			}
			if (Array.isArray(args)) {
				for (const entry of args) {
					if (typeof entry !== "string" || entry === "") continue;
					const found = scanText(entry, [cwd], true);
					if (found !== undefined) return denial(tool, found.target, found.hit);
				}
				return undefined;
			}
			if (typeof args !== "object") return undefined;

			const record = args;

			// --- path arguments, on any tool ------------------------------
			for (const key of PATH_ARG_KEYS) {
				const value = record[key];
				if (typeof value !== "string" || value === "") continue;
				const found = findHit(resolveCandidate(value, cwd), value);
				if (found !== undefined) return denial(tool, found.target, found.hit);
			}

			// --- shell tools: command text scan ---------------------------
			const shellBase =
				typeof record.workdir === "string" && record.workdir !== ""
					? resolveCandidate(record.workdir, cwd)
					: typeof record.cwd === "string" && record.cwd !== ""
						? resolveCandidate(record.cwd, cwd)
						: cwd;

			if (SHELL_TOOLS.has(tool)) {
				for (const key of COMMAND_ARG_KEYS) {
					const value = record[key];
					if (typeof value !== "string" || value === "") continue;
					const bases = [shellBase, ...cdTargets(value, shellBase)];
					const found = scanText(value, bases, false);
					if (found !== undefined) return denial(tool, found.target, found.hit);
				}
			}

			// --- search tools: the selector can name files -----------------
			// `pattern` is a search expression, so it is scanned strictly: a bare
			// word such as `secrets` is a search term, not a filename. `include`
			// and `exclude` really are file selectors and stay loose.
			if (SEARCH_TOOLS.has(tool)) {
				for (const key of SEARCH_ARG_KEYS) {
					const value = record[key];
					if (typeof value !== "string" || value === "") continue;
					const found = scanText(value, [cwd], key === "pattern");
					if (found !== undefined) return denial(tool, found.target, found.hit);
				}
			}

			// --- code tools: conservative scan (see LIMITS in the header) --
			if (CODE_TOOLS.has(tool)) {
				for (const key of CODE_ARG_KEYS) {
					const value = record[key];
					if (typeof value !== "string" || value === "") continue;
					const found = scanText(value, [cwd], true);
					if (found !== undefined) return denial(tool, found.target, found.hit);
				}
			}
		} catch (error) {
			// Fail closed: a guard that cannot decide must not allow.
			return `${PLUGIN_NAME}: internal error while evaluating tool '${tool}' (${
				error instanceof Error ? error.message : String(error)
			}) — call denied for safety.`;
		}

		return undefined;
	};
}

function denial(tool, target, rule) {
	void tool;
	return (
		`${PLUGIN_NAME}: access to "${target}" is denied — ${rule.reason ?? "protected secret"} ` +
		`(rule '${rule.id}'). This path is off-limits to the agent for both reads and writes, ` +
		`including through shell commands, search selectors and code execution. If you need a value ` +
		`from a protected file, ask the user to place it in the shell environment; do not read the file.`
	);
}

/* --------------------------------------------------------------------------
 * Layer 2 — result filtering.
 *
 * Layer 1 denies access by PATH. It cannot help when a credential lives in a
 * file whose name says nothing (`notes.txt`, a scratch file, a log line). This
 * layer (a) hides configured path names and (b) masks credential-SHAPED text in
 * tool results before the model sees them.
 *
 * Only unmistakable token formats are matched. Assignment-style patterns
 * (`api_key = ...`, `password = ...`) are deliberately EXCLUDED: they fire on
 * ordinary source code such as `const api_key = process.env.API_KEY`, so the
 * model would receive a corrupted file and could write that corruption back.
 * A redactor that damages legitimate content is worse than no redactor.
 * ------------------------------------------------------------------------ */

/**
 * High-confidence credential shapes: the real thing, not a variable name.
 * PEM private-key blocks are handled separately by {@link redactPrivateKeyBlocks},
 * because a regex with a lazy body gap is either quadratic (unbounded) or leaks
 * large keys (bounded).
 */
const REDACTION_PATTERNS = [
	{ id: "openai-or-anthropic-key", re: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}/g },
	{ id: "stripe-key", re: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}/g },
	{ id: "github-token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})/g },
	{ id: "gitlab-token", re: /\bglpat-[A-Za-z0-9_-]{20,}/g },
	{ id: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{30,}/g },
	{ id: "slack-token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g },
	{ id: "aws-access-key-id", re: /\bAKIA[0-9A-Z]{16}\b/g },
	{ id: "npm-token", re: /\bnpm_[A-Za-z0-9]{30,}/g },
	{ id: "huggingface-token", re: /\bhf_[A-Za-z0-9]{30,}/g },
	{ id: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
];

/** Marker scanners for a PEM private-key block, resolved by indexOf. */
const PEM_BEGIN = /-----BEGIN[A-Z ]*PRIVATE KEY-----/g;
const PEM_END = /-----END[A-Z ]*PRIVATE KEY-----/g;

/**
 * Replace every PEM private-key block in `text` with a marker.
 *
 * Implemented with `indexOf` rather than a `[\s\S]*?` regex: that is linear in
 * the text length, so it is safe on a hostile tool result AND has no size limit,
 * which a bounded regex would need (and which silently leaked large keys).
 *
 * @returns `{ text, count }` — `count` is 0 when nothing matched.
 */
export function redactPrivateKeyBlocks(text) {
	if (typeof text !== "string" || !text.includes("-----BEGIN")) return { text, count: 0 };
	let out = "";
	let cursor = 0;
	let count = 0;
	PEM_BEGIN.lastIndex = 0;
	let begin = PEM_BEGIN.exec(text);
	while (begin !== null) {
		PEM_END.lastIndex = begin.index + begin[0].length;
		const end = PEM_END.exec(text);
		if (end === null) break;
		out += text.slice(cursor, begin.index) + "[redacted:private-key-block]";
		cursor = end.index + end[0].length;
		count++;
		PEM_BEGIN.lastIndex = cursor;
		begin = PEM_BEGIN.exec(text);
	}
	if (count === 0) return { text, count: 0 };
	out += text.slice(cursor);
	return { text: out, count };
}

/** What a hidden path is replaced with in tool results. */
export const HIDDEN_LABEL = "[hidden]";

/** Escape a literal string for use inside a RegExp. */
function escapeRegExp(literal) {
	return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Replace every credential-shaped value in `text`.
 * @returns `{ text, count, kinds }`, or `null` when nothing matched.
 */
export function redactText(text) {
	if (typeof text !== "string" || text === "") return null;
	const kinds = {};
	let count = 0;
	const pem = redactPrivateKeyBlocks(text);
	let out = pem.text;
	if (pem.count > 0) {
		count += pem.count;
		kinds["private-key-block"] = pem.count;
	}
	for (const pattern of REDACTION_PATTERNS) {
		out = out.replace(pattern.re, () => {
			count++;
			kinds[pattern.id] = (kinds[pattern.id] ?? 0) + 1;
			return `[redacted:${pattern.id}]`;
		});
	}
	if (count === 0) return null;
	return { text: out, count, kinds };
}

/**
 * Build a text filter that removes configured hidden paths from tool results,
 * so a listing (`ls`, `glob`, `find`) cannot reveal even the NAME of a hidden
 * entry.
 *
 * The absolute-path match is BOUNDARY-ANCHORED: without a trailing boundary,
 * hiding `/srv/vault` rewrote the unrelated `/srv/vaulted/x` into
 * `[hidden]ed/x` — corruption of legitimate output, the very failure mode this
 * plugin refuses to ship. The basename form is likewise restricted to real path
 * or directory-listing contexts, never a bare word in prose or a JSON key.
 */
export function createHiddenPathFilter(config = {}) {
	const hidden = hiddenPathList(config);
	if (hidden.length === 0) return null;
	const rules = hidden.map((absolute) => ({ absolute, base: basename(absolute) }));
	const isLongListing = /^[-dlbcps][rwxStTs-]{9}[.+@]?\s/;
	return (text) => {
		if (typeof text !== "string" || text === "") return null;
		let out = text;
		let count = 0;
		for (const { absolute, base } of rules) {
			// 1. The full path, requiring a boundary on BOTH sides: without the
			//    leading one, `/mnt/backup/srv/vault` was rewritten to
			//    `/mnt/backup[hidden]` and `https://host/srv/vault` to
			//    `https://host[hidden]`.
			out = out.replace(
				new RegExp(
					`(^|[\\s"'\`(:,;=}\\]])${escapeRegExp(absolute)}(?:/[^\\s"'\`,;:)\\]}]*)?(?=$|[\\s"'\`,;:)\\]}])`,
					"g",
				),
				(_match, prefix) => {
					count++;
					return `${prefix}${HIDDEN_LABEL}`;
				},
			);
			if (base === "" || base === "/" || base === "." || base === "..") continue;
			const escaped = escapeRegExp(base);

			// 2. The basename as the START of a path token: `vault/x`, `"vault/x"`.
			//    Deliberately NOT any `/vault` anywhere — that rewrote an unrelated
			//    `/mnt/backup/srv/vault` whenever only the basename matched.
			out = out.replace(new RegExp(`(^|[\\s"'])${escaped}(?=/)`, "g"), (_match, prefix) => {
				count++;
				return `${prefix}${HIDDEN_LABEL}`;
			});

			// 3. Directory-listing lines: a bare entry (`ls`) or the trailing name
			//    of a long listing (`ls -l`). Line-anchored, so normal content is
			//    never rewritten.
			out = out
				.split("\n")
				.map((line) => {
					if (line.trim() === base) {
						count++;
						return line.replace(base, HIDDEN_LABEL);
					}
					if (isLongListing.test(line) && new RegExp(`\\s${escaped}\\s*$`).test(line)) {
						count++;
						return line.replace(new RegExp(`${escaped}\\s*$`), HIDDEN_LABEL);
					}
					return line;
				})
				.join("\n");
		}
		return count === 0 ? null : out;
	};
}

/**
 * Filter every text block of a content array; non-text blocks pass through.
 * @param hideFilter - optional `(text) => string | null` applied before the
 *   credential patterns, so a hidden path name never reaches the model.
 * @param credentials - whether to apply the credential-shape patterns.
 */
export function redactBlocks(blocks, hideFilter = null, credentials = true) {
	if (!Array.isArray(blocks)) return null;
	const out = [];
	const kinds = {};
	let count = 0;
	let hiddenCount = 0;
	for (const block of blocks) {
		if (block === null || typeof block !== "object" || block.type !== "text" || typeof block.text !== "string") {
			out.push(block);
			continue;
		}
		let text = block.text;
		let changed = false;
		if (hideFilter !== null) {
			const hidden = hideFilter(text);
			if (hidden !== null) {
				text = hidden;
				hiddenCount++;
				changed = true;
			}
		}
		if (credentials) {
			const redacted = redactText(text);
			if (redacted !== null) {
				text = redacted.text;
				count += redacted.count;
				for (const [kind, n] of Object.entries(redacted.kinds)) kinds[kind] = (kinds[kind] ?? 0) + n;
				changed = true;
			}
		}
		if (!changed) {
			out.push(block);
			continue;
		}
		out.push({ ...block, text });
	}
	if (count === 0 && hiddenCount === 0) return null;
	return { blocks: out, count, kinds, hiddenCount };
}

/** `tools/post-execute` listener: hide configured paths and mask credentials. */
export function createRedactionHandler(config = {}) {
	const withNotice = config.maskNotice !== false;
	const maskCredentials = config.maskResults !== false;
	// Hiding a path name is its own concern: it stays on even when credential
	// masking is switched off, as long as there is something to hide.
	const hideFilter = config.hidePathsInResults === false ? null : createHiddenPathFilter(config);
	return async (exec, result, next) => {
		void exec;
		const downstream = await next();
		try {
			if (downstream?.kind !== "accept") return downstream;
			// A downstream `value` replacement is re-rendered by the tool itself;
			// there is no model-facing text here to mask.
			if (Object.hasOwn(downstream, "value")) return downstream;
			const content = downstream.content ?? result?.content;
			const redacted = redactBlocks(content, hideFilter, maskCredentials);
			if (redacted === null) return downstream;
			const blocks = [...redacted.blocks];
			if (withNotice) {
				const parts = [];
				if (redacted.hiddenCount > 0) {
					parts.push(`hid ${redacted.hiddenCount} reference(s) to a configured hidden path`);
				}
				if (redacted.count > 0) {
					const detail = Object.entries(redacted.kinds).map(([kind, n]) => `${kind} x${n}`).join(", ");
					parts.push(`redacted ${redacted.count} credential-shaped value(s) (${detail})`);
				}
				blocks.push({
					type: "text",
					text:
						`\n[${PLUGIN_NAME}: ${parts.join("; ")} in this tool result. ` +
						`The real values were withheld on purpose. Do not reconstruct or write this content back.]`,
				});
			}
			return {
				kind: "accept",
				content: blocks,
				additionalContexts: downstream.additionalContexts,
			};
		} catch {
			// Filtering is the best-effort second layer; the path guard remains the
			// primary control, so a filtering failure must not break the tool.
			return downstream;
		}
	};
}

/** Cordis plugin entry: registers the monotonic guard on the root context. */
export default function dshHiddenPaths(ctx, config = {}) {
	const logger = (() => {
		try {
			return ctx.logger(PLUGIN_NAME);
		} catch {
			return undefined;
		}
	})();

	let guard;
	try {
		guard = createGuard(config);
	} catch (error) {
		// Unreachable in practice — config handling is total — but a security
		// control must never fail OPEN on an unknown error. Deny everything and
		// say exactly what to fix, so the operator can correct the config.
		const message =
			`${PLUGIN_NAME}: configuration could not be read (${
				error instanceof Error ? error.message : String(error)
			}) — every tool call is denied until the plugin config is fixed.`;
		ctx.tools.guard(() => message);
		try {
			logger?.error(message);
		} catch {
			// logging is advisory
		}
		return;
	}

	ctx.tools.guard(guard);

	// Tell the operator, loudly, about config that cannot do what it looks like
	// it does (a string where an array belongs, relative paths, the root).
	for (const issue of inspectConfig(config)) {
		try {
			logger?.warn(issue);
		} catch {
			// logging is advisory
		}
	}

	const redacting = config.maskResults !== false;
	const hiding = config.hidePathsInResults !== false && hiddenPathList(config).length > 0;
	if (redacting || hiding) {
		try {
			// `prepend` makes this the outermost post-execute listener, so the filtered
			// content is the final decision and no later listener can un-mask it.
			ctx.on("tools/post-execute", createRedactionHandler(config), { prepend: true });
		} catch {
			// The path guard is the primary control; never let the optional second
			// layer prevent the plugin — or the harness — from starting.
		}
	}
	try {
		const parts = [`${PLUGIN_NAME}: deny guard active`];
		if (redacting) parts.push("credential redaction active");
		if (hiding) parts.push(`${hiddenPathList(config).length} hidden path(s) active`);
		logger?.info(parts.join(" + "));
	} catch {
		// Logging is advisory only.
	}
}

dshHiddenPaths.inject = ["tools"];
