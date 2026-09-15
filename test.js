/**
 * Decision-table test for dsh-hidden-paths. Run with `node test.js`.
 *
 * The table asserts BOTH directions: what must be denied (dotenv files,
 * credential stores, key material, through file tools and through shell) and
 * what must stay allowed (example files, ordinary source files whose names
 * merely resemble secrets, prose inside quotes). A guard that over-blocks is
 * as broken as one that under-blocks.
 */

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { createGuard } from "./lib/index.js";

const CWD = "/home/dev/project";
const HOME = "/root";
const guard = createGuard({});

const ctx = (name, args, cwd = CWD) => ({
	name,
	arguments: args,
	agent: { session: { header: { cwd } } },
});

const cases = [
	// ---------------- file tools: must deny ----------------
	["deny  read .env", ctx("read", { file_path: ".env" }), true],
	["deny  read .env.local", ctx("read", { file_path: ".env.local" }), true],
	["deny  read nested .env.production", ctx("read", { file_path: "config/deploy/.env.production" }), true],
	["deny  read absolute .env", ctx("read", { file_path: "/srv/app/.env" }), true],
	["deny  read *.env", ctx("read", { file_path: "api.env" }), true],
	["deny  read .npmrc", ctx("read", { file_path: ".npmrc" }), true],
	["deny  read git-credentials", ctx("read", { file_path: "/root/.git-credentials" }), true],
	["deny  read SSH key", ctx("read", { file_path: "/root/.ssh/id_rsa" }), true],
	["deny  read SSH dir (segment rule)", ctx("read", { file_path: HOME + "/.ssh/config" }), true],
	["deny  read AWS credentials", ctx("read", { file_path: HOME + "/.aws/credentials" }), true],
	["deny  read certificate", ctx("read", { file_path: "certs/server.pem" }), true],
	["deny  read private key", ctx("read", { file_path: "deploy/service.key" }), true],
	["deny  read credentials.json", ctx("read", { file_path: "credentials.json" }), true],
	["deny  read secrets dir", ctx("read", { file_path: "secrets/db.txt" }), true],
	// Names that upstream secret-guard's default table leaves READABLE while
	// over-blocking ordinary code: these are the gaps this guard closes.
	["deny  read secrets.yaml", ctx("read", { file_path: "secrets.yaml" }), true],
	["deny  read secrets.json", ctx("read", { file_path: "config/secrets.json" }), true],
	["deny  read token.txt", ctx("read", { file_path: "token.txt" }), true],
	["deny  read api-keys.txt", ctx("read", { file_path: "ops/api-keys.txt" }), true],
	["deny  read dotenv backup", ctx("read", { file_path: "prod.env.bak" }), true],
	["deny  read dotenv save", ctx("read", { file_path: "api.env.save" }), true],
	["deny  read terraform vars", ctx("read", { file_path: "infra/terraform.tfvars" }), true],
	["deny  read service account key", ctx("read", { file_path: "gcp/service-account.json" }), true],
	["deny  read pgpass", ctx("read", { file_path: "/root/.pgpass" }), true],
	["deny  read kubeconfig", ctx("read", { file_path: "/root/.kube/config" }), true],
	["deny  read .secret-guard storage", ctx("read", { file_path: ".secret-guard/seal.key" }), true],
	["deny  write .env", ctx("write", { file_path: ".env" }), true],
	["deny  edit credentials.yaml", ctx("edit", { file_path: "app/config/credentials.yaml" }), true],
	["deny  glob inside .ssh", ctx("glob", { path: "/root/.ssh" }), true],
	["deny  grep .env", ctx("grep", { path: ".env", pattern: "KEY" }), true],
	["deny  read_image on key", ctx("read_image", { file_path: "backup/id_ed25519.png" }), true],

	// ---------------- shell: must deny ----------------
	["deny  sh cat .env", ctx("bash", { command: "cat .env" }), true],
	["deny  sh cat .env.local", ctx("bash", { command: "cat .env.local" }), true],
	["deny  sh cat /srv/.env", ctx("bash", { command: "cat /srv/app/.env" }), true],
	["deny  sh cat ~/.aws/credentials", ctx("bash", { command: "cat ~/.aws/credentials" }), true],
	["deny  sh cat $HOME/.ssh/id_rsa", ctx("bash", { command: "cat $HOME/.ssh/id_rsa" }), true],
	["deny  sh cat quoted path", ctx("bash", { command: 'cat "/srv/my app/.env"' }), true],
	["deny  sh base64 of .key", ctx("bash", { command: "base64 deploy/service.key" }), true],
	["deny  sh copy .env out", ctx("bash", { command: "cp .env /tmp/backup.txt" }), true],
	["deny  sh glob expansion .e*", ctx("bash", { command: "cat .e*" }), true],
	["deny  sh chained after &&", ctx("bash", { command: "cd /tmp && cat .env" }), true],
	["deny  sh secrets dir", ctx("bash", { command: "ls secrets/" }), true],
	["deny  sh bare secrets file", ctx("bash", { command: "cat secrets" }), true],
	["deny  sh .npmrc", ctx("bash", { command: "cat ~/.npmrc" }), true],
	["deny  sh dotenv backup", ctx("bash", { command: "cat prod.env.bak" }), true],
	["deny  sh kubeconfig", ctx("bash", { command: "cat ~/.kube/config | head" }), true],
	["deny  sh service account", ctx("bash", { command: "cat gcp/service-account.json" }), true],

	// ---------------- must stay ALLOWED ----------------
	["allow read .env.example", ctx("read", { file_path: ".env.example" }), false],
	["allow read .env.template", ctx("read", { file_path: "config/.env.template" }), false],
	["allow read source file secrets.ts", ctx("read", { file_path: "src/secrets.ts" }), false],
	["allow read source file credentials-manager.py", ctx("read", { file_path: "src/credentials-manager.py" }), false],
	["allow read source file tokenizer.py", ctx("read", { file_path: "src/tokenizer.py" }), false],
	["allow read source file tokens.ts", ctx("read", { file_path: "src/tokens.ts" }), false],
	["allow read source file api-key-utils.ts", ctx("read", { file_path: "src/api-key-utils.ts" }), false],
	["allow read source file secret-store.ts", ctx("read", { file_path: "src/secret-store.ts" }), false],
	["allow read README", ctx("read", { file_path: "README.md" }), false],
	["allow read ordinary config", ctx("read", { file_path: "config/app.yaml" }), false],
	["allow sh echo prose", ctx("bash", { command: 'echo "no secrets here"' }), false],
	["allow sh git credential.helper", ctx("bash", { command: "git config credential.helper store" }), false],
	["allow sh npm build", ctx("bash", { command: "npm run build" }), false],
	["allow sh python inline", ctx("bash", { command: "python -c 'print(1)'" }), false],
	["allow sh find by name mention", ctx("bash", { command: "find . -name '*.ts'" }), false],
	["allow non-path tool", ctx("todo_write", { todos: [] }), false],
];

let failed = 0;
for (const [label, execution, shouldDeny] of cases) {
	const reason = guard(execution);
	const denied = reason !== undefined;
	const ok = denied === shouldDeny;
	if (!ok) failed++;
	const mark = ok ? "PASS" : "FAIL";
	const detail = denied ? `-> ${String(reason).slice(0, 72)}…` : "-> allowed";
	console.log(`${mark}  ${label.padEnd(46)} ${detail}`);
}

// ---------------- configuration behaviour ----------------
console.log("\n-- configuration --");
// Built from os.homedir() so the `~` case means something on every platform:
// hard-coding /root passes on Linux and fails on Windows, where the home
// directory is C:\Users\<name>.
const homeDir = homedir();
const vaultRoot = join(homeDir, "vault");
const withRoot = createGuard({ guardRoots: [vaultRoot] });
assert.notEqual(withRoot(ctx("read", { file_path: join(vaultRoot, "notes.txt") })), undefined, "guardRoots must deny file tools");
assert.notEqual(withRoot(ctx("bash", { command: `cat ${join(vaultRoot, "notes.txt")}` })), undefined, "guardRoots must deny shell");
assert.notEqual(withRoot(ctx("bash", { command: "cat ~/vault/notes.txt" })), undefined, "guardRoots must expand ~");
assert.equal(withRoot(ctx("read", { file_path: join(homeDir, "other", "notes.txt") })), undefined, "unrelated path must stay allowed");
console.log("PASS  guardRoots denies subtree via file tools and shell");

const withAllow = createGuard({ allow: ["secrets.json"] });
assert.equal(withAllow(ctx("read", { file_path: "secrets.json" })), undefined, "explicit allow must win");
assert.notEqual(withAllow(ctx("read", { file_path: ".env" })), undefined, "allow must not disable other rules");
console.log("PASS  explicit allow wins over rules without disabling them");

const withExtra = createGuard({ extraNameRules: ["*.vault"] });
assert.notEqual(withExtra(ctx("read", { file_path: "prod.vault" })), undefined, "extraNameRules must apply");
console.log("PASS  extraNameRules extends the table");

// The guard must never throw out of the guard function, and must fail closed
// on malformed input rather than allowing the call.
assert.doesNotThrow(() => guard(ctx("bash", { command: "" })));
assert.doesNotThrow(() => guard({ name: "read", arguments: null }));
assert.doesNotThrow(() => guard({ name: "bash", arguments: { command: "cat .env" }, agent: undefined }));
console.log("PASS  malformed executions do not throw");

// ---------------- hiddenPaths: user-configured files and folders to hide ----
console.log("\n-- hiddenPaths --");
const { hiddenPathList, createHiddenPathFilter } = await import("./lib/index.js");

const hiddenGuard = createGuard({ hiddenPaths: ["/srv/vault", "/etc/app/master.key"] });
assert.notEqual(hiddenGuard(ctx("read", { file_path: "/srv/vault" })), undefined, "a hidden folder itself must be denied");
assert.notEqual(hiddenGuard(ctx("read", { file_path: "/srv/vault/notes.txt" })), undefined, "a hidden folder subtree must be denied");
assert.notEqual(hiddenGuard(ctx("glob", { path: "/srv/vault" })), undefined, "glob in a hidden folder must be denied");
assert.notEqual(hiddenGuard(ctx("bash", { command: "ls /srv/vault" })), undefined, "a hidden folder via shell must be denied");
assert.notEqual(hiddenGuard(ctx("bash", { command: "cat srv/vault/x" }, "/")), undefined, "a hidden folder via a relative shell path must be denied");
assert.notEqual(hiddenGuard(ctx("read", { file_path: "/etc/app/master.key" })), undefined, "a hidden single file must be denied");
assert.notEqual(hiddenGuard(ctx("bash", { command: "cat /etc/app/master.key" })), undefined, "a hidden single file via shell must be denied");
assert.notEqual(hiddenGuard(ctx("write", { file_path: "/srv/vault/new.txt" })), undefined, "writes inside a hidden folder must be denied");
assert.equal(hiddenGuard(ctx("read", { file_path: "/srv/public/notes.txt" })), undefined, "an unrelated path must stay allowed");
assert.equal(hiddenGuard(ctx("bash", { command: "ls /srv" })), undefined, "listing the parent folder must stay allowed");
console.log("PASS  hiddenPaths covers folders, single files, shell, reads and writes");

assert.deepEqual(hiddenPathList({ hiddenPaths: ["/a"], guardRoots: ["/a", "/b"] }), [resolve("/a"), resolve("/b")], "hiddenPaths and guardRoots merge without duplicates");
assert.deepEqual(hiddenPathList({ hiddenPaths: ["  /a  ", ""] }), [resolve("/a")], "entries are trimmed and blanks dropped");
console.log("PASS  hiddenPathList merges hiddenPaths/guardRoots, trims and de-duplicates");

// A symlink must not become a side door into a hidden folder.
const sandbox = mkdtempSync(join(tmpdir(), "guard-hidden-"));
try {
	const vault = join(sandbox, "vault");
	mkdirSync(vault);
	writeFileSync(join(vault, "note.txt"), "secret\n");
	const publicDir = join(sandbox, "public");
	mkdirSync(publicDir);
	writeFileSync(join(publicDir, "ok.txt"), "fine\n");
	const links = join(sandbox, "links");
	mkdirSync(links);
	const shortcut = join(links, "shortcut");
	const publicLink = join(links, "pub");
	let symlinksSupported = true;
	// A directory symlink on Windows needs elevation, a JUNCTION does not, so the
	// check actually runs there instead of being skipped.
	const linkType = process.platform === "win32" ? "junction" : "dir";
	try {
		symlinkSync(vault, shortcut, linkType);
		symlinkSync(publicDir, publicLink, linkType);
	} catch {
		symlinksSupported = false;
	}

	if (!symlinksSupported) {
		console.log("SKIP  symlink checks: this platform does not allow creating symlinks");
	} else {
		const symGuard = createGuard({ hiddenPaths: [vault] });
		assert.notEqual(symGuard(ctx("read", { file_path: shortcut })), undefined, "a symlink to a hidden folder must be denied");
		assert.notEqual(symGuard(ctx("read", { file_path: join(shortcut, "note.txt") })), undefined, "a file reached through a symlink must be denied");
		assert.notEqual(symGuard(ctx("bash", { command: `cat ${shortcut}/note.txt` })), undefined, "a symlinked path via shell must be denied");
		assert.equal(symGuard(ctx("read", { file_path: join(publicLink, "ok.txt") })), undefined, "a symlink to a normal folder must stay allowed");
		console.log("PASS  symlinks into a hidden folder are resolved and denied");
	}
} finally {
	rmSync(sandbox, { recursive: true, force: true });
}

// Hiding the NAME in results, so a listing cannot reveal it either.
// The filter works on TEXT, so the spellings it is fed must use the native
// separators the plugin itself produces (path.resolve), not POSIX ones.
const vaultNative = resolve("/srv/vault");
const filter = createHiddenPathFilter({ hiddenPaths: ["/srv/vault"] });
assert.equal(filter(join(vaultNative, "a.txt")), "[hidden]", "a full hidden path must be masked");
assert.equal(filter("found " + join(vaultNative, "a.txt") + " here"), "found [hidden] here", "a path inside a sentence must be masked");
// The same root written with the OTHER separator must be masked too: on Windows
// tool output can print `C:/srv/vault/a.txt`, and matching only the native
// spelling would leave the hidden name visible. On POSIX the two coincide.
const vaultOtherSpelling = vaultNative.split(sep).join("/");
assert.equal(filter(vaultOtherSpelling + "/a.txt"), "[hidden]", "the other separator spelling must be masked");
assert.equal(filter("vault/x.txt"), "[hidden]/x.txt", "a relative path starting with the name must be masked");
assert.equal(filter("total 0\nvault\n"), "total 0\n[hidden]\n", "a bare `ls` entry must be masked");
assert.equal(filter("drwxr-xr-x 2 root root 4096 vault"), "drwxr-xr-x 2 root root 4096 [hidden]", "an `ls -l` entry must be masked");
assert.equal(filter("nothing to hide"), null, "unrelated text yields no change");
assert.equal(createHiddenPathFilter({}), null, "no hidden paths means no filter");
console.log("PASS  hidden names are masked in full paths, relative paths and listings");

// Anti-corruption: a hidden folder whose name is an ordinary word must not
// rewrite normal content (the mistake the credential patterns also avoid).
const wordFilter = createHiddenPathFilter({ hiddenPaths: ["/srv/data"] });
assert.equal(wordFilter('{"data": 1, "other": 2}'), null, "a JSON key must not be rewritten");
assert.equal(wordFilter("the data shows a rise"), null, "prose must not be rewritten");
assert.equal(wordFilter("const data = load()"), null, "code must not be rewritten");
console.log("PASS  a hidden name that is a common word does not corrupt content");

// ---------------- result redaction (layer 2) ----------------
console.log("\n-- redaction --");
const { redactText, redactBlocks, createRedactionHandler, default: plugin } = await import("./lib/index.js");

// Fixture values are assembled at runtime on purpose: a literal secret-shaped
// string inside a test file trips secret scanners (and looks like a real leak)
// even though it is worthless. The redaction patterns under test still see the
// complete value.
const fake = {
	openai: "sk-" + "abcdef0123456789ABCDEF",
	anthropic: "sk-" + "ant-api03-abcdefghijklmnopqrst",
	github: "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789",
	gitlab: "glpat-" + "abcdefghijklmnopqrst",
	aws: "AKIA" + "IOSFODNN7EXAMPLE",
	slack: "xoxb-" + "1234567890-abcdefghijkl",
	google: "AIza" + "SyA1234567890abcdefghijklmnopqrstuv",
	jwt: "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxIn0" + "." + "abcdefghijklmnop",
	pemBegin: "-----BEGIN RSA " + "PRIVATE KEY-----",
	pemEnd: "-----END RSA " + "PRIVATE KEY-----",
};
const fakePem = (body) => fake.pemBegin + "\n" + body + "\n" + fake.pemEnd;

const secretSamples = [
	["openai key", "key " + fake.openai + " end", "openai-or-anthropic-key"],
	["anthropic key", fake.anthropic, "openai-or-anthropic-key"],
	["github token", fake.github, "github-token"],
	["gitlab token", fake.gitlab, "gitlab-token"],
	["aws access key id", fake.aws, "aws-access-key-id"],
	["slack token", fake.slack, "slack-token"],
	["google api key", fake.google, "google-api-key"],
	["private key block", fakePem("MIIEow"), "private-key-block"],
	["jwt", fake.jwt, "jwt"],
];
for (const [label, text, kind] of secretSamples) {
	const result = redactText(text);
	assert.notEqual(result, null, `${label} must be redacted`);
	assert.ok(result.kinds[kind] >= 1, `${label} must be tagged '${kind}'`);
	assert.ok(!result.text.includes(text), `${label} must not survive in the output`);
}
console.log(`PASS  ${secretSamples.length} credential shapes are redacted`);

// The critical anti-corruption assertion: ordinary source code must survive
// byte-for-byte. A redactor that mangles code is worse than none.
const codeSamples = [
	"const api_key = process.env.API_KEY",
	"password: req.body.password",
	"const token = getTokenFromCache()",
	"export function secretStore() {}",
	"const credentials = loadCredentials()",
	"// rotate the github token in CI",
];
for (const code of codeSamples) {
	assert.equal(redactText(code), null, `code must NOT be redacted: ${code}`);
}
console.log("PASS  ordinary source code is never mangled");

assert.equal(redactText("just some plain text"), null, "plain text yields no redaction");
assert.equal(redactBlocks([{ type: "image", data: "x" }]), null, "non-text-only content yields no redaction");
const mixed = redactBlocks([
	{ type: "text", text: fake.github },
	{ type: "image", data: "x" },
]);
assert.equal(mixed.count, 1);
assert.equal(mixed.blocks.length, 2, "non-text blocks must pass through");
assert.equal(mixed.blocks[1].type, "image", "non-text block must be untouched");
console.log("PASS  non-text blocks pass through, clean results untouched");

// The hide filter and the credential patterns cooperate in one pass.
const hiddenBlocks = redactBlocks(
	[{ type: "text", text: "listing " + join(resolve("/srv/vault"), "a.txt") + " and key " + fake.aws }],
	createHiddenPathFilter({ hiddenPaths: ["/srv/vault"] }),
);
assert.equal(hiddenBlocks.hiddenCount, 1, "the hide filter must apply to blocks");
assert.equal(hiddenBlocks.count, 1, "credential masking must still apply alongside hiding");
assert.ok(hiddenBlocks.blocks[0].text.includes("[hidden]"), "the hidden path must be masked");
assert.ok(hiddenBlocks.blocks[0].text.includes("[redacted:aws-access-key-id]"), "the credential must be masked");
console.log("PASS  hiding and credential masking cooperate in one pass");

const runHandler = (decision) =>
	createRedactionHandler({})({ name: "bash" }, {}, async () => decision);
const redacted = await runHandler({ kind: "accept", content: [{ type: "text", text: fake.aws }] });
assert.ok(redacted.content.some((b) => b.text.includes("[redacted:aws-access-key-id]")));
assert.ok(redacted.content.some((b) => b.text.includes("dsh-hidden-paths: redacted 1")));
const untouched = await runHandler({ kind: "accept", content: [{ type: "text", text: "hello" }] });
assert.equal(untouched.content.length, 1, "clean content must not gain a notice block");
const valueDecision = await runHandler({ kind: "accept", value: { a: 1 } });
assert.deepEqual(valueDecision.value, { a: 1 }, "value decisions pass through");
const blockDecision = await runHandler({ kind: "block", feedback: [] });
assert.equal(blockDecision.kind, "block", "block decisions pass through");
console.log("PASS  redaction handler rewrites accepted text content only");

// ---------------- cordis plugin entry ----------------
console.log("\n-- plugin entry --");
const makeCtx = (onLog) => {
	const guards = [];
	const events = [];
	return {
		guards,
		events,
		tools: { guard: (fn) => { guards.push(fn); return () => {}; } },
		on: (event, handler, options) => { events.push({ event, handler, options }); return () => {}; },
		logger(name) {
			assert.equal(name, "dsh-hidden-paths");
			if (onLog) onLog();
			return { info: () => {}, warn: () => {} };
		},
	};
};

assert.deepEqual(plugin.inject, ["tools"], "plugin must declare its injected service");

const ctxA = makeCtx();
assert.doesNotThrow(() => plugin(ctxA, {}), "plugin must mount cleanly");
assert.equal(ctxA.guards.length, 1, "plugin must register exactly one deny guard");
assert.equal(ctxA.events.length, 1, "plugin must register the redaction listener by default");
assert.equal(ctxA.events[0].event, "tools/post-execute");
assert.equal(ctxA.events[0].options?.prepend, true, "redaction must be the outermost listener");
assert.notEqual(ctxA.guards[0](ctx("bash", { command: "cat .env" })), undefined, "mounted guard must deny");
console.log("PASS  plugin mounts the deny guard and the redaction listener");

const ctxB = makeCtx();
plugin(ctxB, { maskResults: false });
assert.equal(ctxB.events.length, 0, "maskResults:false must disable redaction");
assert.equal(ctxB.guards.length, 1, "maskResults:false must keep the deny guard");
console.log("PASS  maskResults:false keeps the guard and drops redaction");

// Hiding configured paths is its own concern: it must register even when
// credential masking is switched off.
const ctxH = makeCtx();
plugin(ctxH, { maskResults: false, hiddenPaths: ["/srv/vault"] });
assert.equal(ctxH.events.length, 1, "hiddenPaths must register the result filter even with maskResults:false");
assert.equal(ctxH.guards.length, 1, "the deny guard must still be registered");
console.log("PASS  hiddenPaths registers the result filter independently of maskResults");

// With nothing to hide and masking off, no post-execute listener is needed.
const ctxN = makeCtx();
plugin(ctxN, { maskResults: false, hiddenPaths: [] });
assert.equal(ctxN.events.length, 0, "no listener when there is nothing to mask");
assert.equal(ctxN.guards.length, 1, "the deny guard must still be registered");
console.log("PASS  no result listener is registered when nothing needs masking");

const ctxC = makeCtx(() => { throw new Error("logger exploded"); });
assert.doesNotThrow(() => plugin(ctxC, {}), "plugin must mount despite a logging failure");
assert.equal(ctxC.guards.length, 1, "guard must arm even when logging throws");
assert.equal(ctxC.events.length, 1, "redaction must register even when logging throws");
console.log("PASS  guard and redaction arm even when logging throws");

// If the post-execute event cannot be registered, the deny guard must still arm.
const ctxD = {
	guards: [],
	tools: { guard: (fn) => { ctxD.guards.push(fn); return () => {}; } },
	on: () => { throw new Error("event not declared"); },
	logger: () => ({ info: () => {}, warn: () => {} }),
};
assert.doesNotThrow(() => plugin(ctxD, {}), "plugin must mount when redaction cannot register");
assert.equal(ctxD.guards.length, 1, "guard must arm when redaction registration fails");
console.log("PASS  guard arms even when redaction cannot register");


// ---------------- holes closed after the independent audit ----------------
console.log("\n-- audit fixes --");
const {
	asArray,
	inspectConfig,
	realPathOfNearestExisting,
	expandShellToken,
} = await import("./lib/index.js");

const fx = createGuard({ hiddenPaths: ["/srv/vault"] });

// 1. `workdir` is a path argument, and relative shell tokens resolve against it
assert.notEqual(fx(ctx("bash", { command: "cat note.txt", workdir: "/srv/vault" })), undefined, "a workdir inside a hidden path must be denied");
assert.notEqual(fx(ctx("bash", { command: "cat note.txt", workdir: "/srv/vault/sub" })), undefined, "a nested workdir must be denied");
assert.equal(fx(ctx("bash", { command: "cat note.txt", workdir: "/srv/public" })), undefined, "an unrelated workdir must stay allowed");
console.log("PASS  workdir is inspected and becomes the shell resolution base");

// 2. search selectors can name protected files
assert.notEqual(fx(ctx("grep", { pattern: "x", path: "/srv", include: "secrets.json" })), undefined, "a grep include selector must be denied");
assert.notEqual(fx(ctx("glob", { path: "/srv", pattern: "**/.env" })), undefined, "a glob pattern naming a protected file must be denied");
assert.equal(fx(ctx("glob", { path: "/srv", pattern: "**/*.ts" })), undefined, "an ordinary glob pattern must stay allowed");
console.log("PASS  grep/glob selectors are scanned");

// 3. bracket, brace and bare-glob expansion
assert.notEqual(fx(ctx("bash", { command: "cat .en" + "[v]" })), undefined, "bracket expansion must not evade the guard");
assert.notEqual(fx(ctx("bash", { command: "cat .{env,x}" })), undefined, "brace expansion must not evade the guard");
assert.notEqual(fx(ctx("bash", { command: "cat .*" })), undefined, "a bare dotfile glob must be denied");
assert.deepEqual(expandShellToken(".en" + "[v]").includes(".env"), true, "bracket expansion must yield the literal name");
console.log("PASS  bracket/brace/dotfile globs no longer evade the shell scan");

// 4. a quoted bare protected name
assert.notEqual(fx(ctx("bash", { command: 'cat "sec' + 'rets"' })), undefined, "a quoted bare protected name must be denied");
assert.equal(fx(ctx("bash", { command: 'echo "no sec' + 'rets here"' })), undefined, "prose inside quotes must stay allowed");
console.log("PASS  quoted bare names are denied without tripping on prose");

// 5. config robustness: a string, a number, a relative path, the root
assert.deepEqual(asArray("/srv/vault"), ["/srv/vault"], "a string config value is read as one entry");
assert.deepEqual(asArray(42), [], "a number config value is ignored");
assert.deepEqual(asArray(undefined), [], "an absent config value yields no entries");
assert.ok(inspectConfig({ hiddenPaths: "/srv/vault" }).some((w) => w.includes("should be an array")), "a non-array hiddenPaths must warn");
assert.ok(inspectConfig({ hiddenPaths: ["relative/dir"] }).some((w) => w.includes("not absolute")), "a relative path must warn");
assert.ok(inspectConfig({ hiddenPaths: ["/"] }).some((w) => w.includes("filesystem root")), "the root must warn");
const stringCfg = createGuard({ hiddenPaths: "/srv/vault" });
assert.notEqual(stringCfg(ctx("read", { file_path: "/srv/vault/note.txt" })), undefined, "a string hiddenPaths must still protect the path");
const rootGuard = createGuard({ hiddenPaths: ["/"] });
assert.notEqual(rootGuard(ctx("read", { file_path: "/etc/hostname" })), undefined, "hiding the root must actually hide everything");
console.log("PASS  a config typo can no longer silently disarm the guard");

// 6. the allow list cannot re-open an explicitly hidden path
const allowGuard = createGuard({ hiddenPaths: ["/srv/vault"], allow: ["payload.json"] });
assert.notEqual(allowGuard(ctx("read", { file_path: "/srv/vault/payload.json" })), undefined, "an allow entry must not re-open a hidden path");
assert.equal(allowGuard(ctx("read", { file_path: "/srv/other/payload.json" })), undefined, "the allow entry must still work elsewhere");
console.log("PASS  hidden paths outrank the allow list");

// 7. the result filter no longer corrupts sibling paths
const sib = createHiddenPathFilter({ hiddenPaths: ["/srv/vault"] });
assert.equal(sib(resolve("/srv/vaulted/x")), null, "a sibling sharing the prefix must NOT be rewritten");
assert.equal(sib(resolve("/srv/database")), null, "an unrelated sibling must NOT be rewritten");
assert.equal(sib(join(resolve("/srv/vault"), "x")), "[hidden]", "the hidden path itself must still be rewritten");
assert.equal(sib("total 0\nvault\n"), "total 0\n[hidden]\n", "a bare ls entry must still be masked");
console.log("PASS  hidden-path masking is boundary-anchored, no sibling corruption");

// 8. a symlink whose leaf does not exist yet
const linkSandbox = mkdtempSync(join(tmpdir(), "guard-link-"));
try {
	const hiddenDir = join(linkSandbox, "vault");
	mkdirSync(hiddenDir);
	const shortcut = join(linkSandbox, "shortcut");
	let linkSupported = true;
	const linkType = process.platform === "win32" ? "junction" : "dir";
	try {
		symlinkSync(hiddenDir, shortcut, linkType);
	} catch {
		linkSupported = false;
	}
	if (!linkSupported) {
		console.log("SKIP  symlink-to-missing-leaf check: this platform does not allow creating symlinks");
	} else {
		const lg = createGuard({ hiddenPaths: [hiddenDir] });
		assert.notEqual(lg(ctx("write", { file_path: join(shortcut, "brand-new.txt") })), undefined, "a not-yet-existing file through a symlink must be denied");
		// Compared against the same resolution through the REAL directory, so the
		// assertion does not depend on Windows casing or 8.3 short names.
		assert.equal(
			realPathOfNearestExisting(join(shortcut, "brand-new.txt")),
			realPathOfNearestExisting(join(hiddenDir, "brand-new.txt")),
			"the nearest existing ancestor must resolve through the link",
		);
		console.log("PASS  a symlink to a missing leaf is still resolved and denied");
	}
} finally {
	rmSync(linkSandbox, { recursive: true, force: true });
}

// 9. code text is scanned conservatively
assert.notEqual(fx(ctx("run_code", { code: "fs.readFileSync('/srv/vault/note.txt')" })), undefined, "code naming a hidden path must be denied");
assert.equal(fx(ctx("run_code", { code: "const sec = await load();" })), undefined, "a bare identifier in code must NOT be flagged");
console.log("PASS  run_code text is scanned without flagging identifiers");

// 10. a malformed non-object argument is inspected, not waved through
assert.notEqual(fx(ctx("read", "/srv/vault/note.txt")), undefined, "a string argument must be inspected");
console.log("PASS  a string argument is inspected");

// 11. the private-key pattern is bounded (was quadratic, stalled ~1.7s)
const manyBegins = (fake.pemBegin + "\n").repeat(4000);
const started = Date.now();
redactText(manyBegins);
const elapsed = Date.now() - started;
assert.ok(elapsed < 2000, `the private-key pattern must stay bounded (took ${elapsed}ms)`);
console.log(`PASS  private-key redaction is bounded (${elapsed}ms for 4000 markers)`);

console.log(`\n${cases.length - failed}/${cases.length} table cases passed.`);

if (failed > 0) {
	console.error(`${failed} case(s) FAILED`);
	process.exit(1);
}
