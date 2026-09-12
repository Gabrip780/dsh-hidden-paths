# dsh-hidden-paths

English | [中文](README.zh.md)

A **DeepSeek Harness** (`dsh`) plugin that stops an AI agent from reading what it should not: `.env` files, credential stores, private keys, and **any folder or file you choose to hide** — blocked through the agent's file tools, its **shell commands**, its search selectors and its code execution.

## Why

`dsh`'s built-in permission vocabulary is a *sandbox mode* (`read-only` / `workspace-write` / `danger-full-access`) plus an approval policy. It gates **writes**; **reads are unconfined**. So an agent working in your project can `cat .env` or open `~/.ssh/id_rsa` unless something stops it.

This plugin is that something. It is a **policy guard**, not a kernel sandbox (see [Threat model](#threat-model--read-this)).

## Install

```bash
dsh plugin --profile web add dsh-hidden-paths
```

That is the whole install. The package declares `dsh.bundle.patch`, so `dsh plugin add` installs it **and** activates it as a profile layer with safe defaults: nothing hidden, the secret-name rules active, credential redaction on.

Restart the `dsh` server once so the new module is imported.

## Hide a folder or a file

The bundle already inserts the plugin row, so change its settings with an **id-targeted override** in your profile's own patch layer:

```yaml
# $DSH_HOME/profiles/web/cordis.patch.yml
- id: dsh-hidden-paths
  config:
    hiddenPaths:
      - /home/you/private          # a folder: its whole subtree is protected
      - /etc/app/master.key        # or a single file
```

> Do **not** add an `insert` block for this plugin. The bundle layer already inserts the row, and a second `insert` with the same `id` is a duplicate loader entry: the profile fails to boot. Override by `id` instead.

For every path listed:

| Effect | Detail |
|---|---|
| Access denied | reads **and** writes, from file tools (`read`, `write`, `edit`, `glob`, `grep`, `read_image`), from shell commands (`cat`, `ls`, `cp`, `rm`, …), from search selectors (`glob`/`grep` `pattern`, `include`, `exclude`) and from code executed through `run_code` |
| Subtree covered | if it is a folder, everything inside is protected |
| Name hidden | the **name** is masked as `[hidden]` in results, so `ls`, `ls -l`, `glob` or `find` cannot leak it either |
| Symlinks resolved | a link pointing inside a hidden path is resolved and denied — including when the target leaf does not exist yet |
| Outranks the allow list | an `allow` entry can never re-open a path you explicitly hid |
| Subagents included | applies to every agent in the tree, not just the root one |

## Two layers

**Layer 1 — path denial.** Registered with `ctx.tools.guard()`, a **monotonic** guard evaluated after the extensible `tools/pre-execute` waterfall. A returned reason denies the call *before the tool body runs*, and **no later listener can turn that denial back into permission**.

**Layer 2 — result filtering.** Registered on `tools/post-execute` with `prepend`, so it is the outermost listener and the final decision. It (a) masks hidden path names as `[hidden]`, and (b) redacts credential-shaped values as `[redacted:kind]` before the model sees them — because a secret can live in a file whose name says nothing (`notes.txt`, a log line, a script).

Layer 2 redacts **only unmistakable token formats**: OpenAI/Anthropic keys, GitHub/GitLab tokens, Stripe keys, `AKIA…`, `xox…`, `AIza…`, npm/Hugging Face tokens, JWTs, and PEM private-key blocks.

## Protected by default

Besides `hiddenPaths`, these names are protected anywhere they appear:

| Category | Rules |
|---|---|
| Dotenv files | `.env`, `.env.*`, `*.env`, `*.env.*` (backups and variants) |
| Credential stores | `.npmrc`, `.netrc`, `.pypirc`, `.git-credentials`, `.pgpass`, `.htpasswd`, `.dockercfg`, `credentials`, `credentials.{json,yaml,yml,txt}`, `.credentials*`, `*service-account*.json` |
| Secrets | `secrets`, `secrets.{json,yaml,yml,txt}`, `.secrets*`, `token.txt`, `tokens.txt`, `api-keys.txt`, `api_keys.txt` |
| Private keys | `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`, `*.pem`, `*.key`, `*.ppk`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.kdbx` |
| Infrastructure variables | `*.tfvars`, `*.tfvars.json` |
| Whole directories | `.ssh`, `.aws`, `.gnupg`, `.kube`, `.docker`, `.secret-guard`, `secrets`, `.secrets`, `credentials` |

Example and template files (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.default`, `.env.test`) stay **readable**.

The rules are deliberately **precise**, not `*secret*`: a broad glob would also block ordinary source files such as `secrets.ts`, `credentials-manager.py` or `tokenizer.py`.

## Configuration

```yaml
- id: dsh-hidden-paths
  config:
    hiddenPaths: []           # ABSOLUTE paths (folders or files) to hide
    guardRoots: []            # legacy alias of hiddenPaths, still accepted
    extraNameRules: []        # extra basename globs, e.g. "*.vault"
    extraDirSegments: []      # extra directory names protected anywhere
    allow: []                 # exceptions; never re-opens a hiddenPath
    maskResults: true         # layer 2: credential redaction
    hidePathsInResults: true  # layer 2: also mask hidden path names
    maskNotice: true          # add a notice line when something was hidden
```

A config typo cannot silently disarm the guard:

- a **string** where an array is expected is read as the single entry you meant (it used to spread into characters and protect nothing);
- a **relative path** is resolved against the process cwd and logged as a warning;
- `hiddenPaths: ["/"]` really does hide everything, and says so in a warning;
- if the configuration cannot be read at all, the plugin **denies every tool call** and logs why, rather than failing open.

## Design note: no content corruption

An aggressive redactor is worse than none. Three rules keep this one safe:

- The credential patterns never match assignment shapes like `api_key = ...`, because that fires on ordinary source code (`const api_key = process.env.API_KEY`) and would hand the model a corrupted file it might write back.
- A hidden **name** is only replaced where it really is a path (`/folder/x`, `folder/x`) or a directory-listing line — never as a word in a sentence or a JSON key. Hide a folder called `data` and a JSON body `{"data": 1}` you read elsewhere is left untouched.
- The absolute-path match is **boundary-anchored**: hiding `/srv/vault` does not rewrite the unrelated `/srv/vaulted/x`.

All three are enforced by dedicated tests.

## Threat model — read this

**This is a policy guard on a cooperative runtime, not a kernel boundary.** It stops accidents, prompt-injected "please `cat` my `.env`", and routine overreach. It does **not** stop a determined adversary, because:

- shell analysis is textual: `cat "$SOMEVAR"`, `python -c '...'`, `find -name '*.env' -exec cat {} +`, `base64`, `env`/`printenv`, `/proc`, hardlinks, or reading an already-open file descriptor can reach the same bytes without naming a protected path;
- splitting a **bare** name across quote boundaries (`"sec"rets`) is not caught — quoted fragments are joined, but a word that came from inside a quoted span is treated as prose so that `git commit -m "update .env"` is not blocked. Names with a path separator or a leading dot are unaffected;
- **`run_code` executes arbitrary code with Node's full API.** Only literal path spellings in its text are caught, so it remains a real bypass;
- the **default name rules never resolve symlinks** — only configured `hiddenPaths` do, so a symlink with an innocent name pointing at a secret is not caught;
- layer 2 recognises *shapes*, not *meanings*: a credential in an unusual format passes;
- anything the agent can read, it can also copy elsewhere.

The guard also errs towards blocking: a glob whose expansion *could* reach a protected name (`cat .*`, `/srv/*/note.txt`, `ls se*`) is denied even when harmless. Narrow the glob or add an `allow` entry.

Complementary defences: keep truly critical secrets **outside** the agent's workspace, run `dsh` as a different user than the one owning the files, or confine the whole process (container, seccomp, Landlock).

## Development

```bash
git clone https://github.com/Gabrip780/dsh-hidden-paths.git
cd dsh-hidden-paths
node test.js
```

Zero runtime dependencies — only Node built-ins (`node:path`, `node:os`, `node:fs`). The only filesystem call is `realpathSync` on a path the guard is already deciding about: metadata, never file content. No network, no process spawning, no `eval`.

`node test.js` prints a 62-case decision table plus the configuration, hidden-path, redaction, plugin-wiring and post-audit regression groups — 93 `PASS` lines in total, and it exits non-zero on any failure. The suite asserts **both** directions: what must be denied, and what must stay allowed. A guard that over-blocks is as broken as one that under-blocks.

## How it was reviewed

Before its first release this plugin was audited by five independent adversarial reviewers (a bug auditor, a deep code reviewer, a 0-day hunter, a red/blue team pair, and a lateral-thinking reviewer) plus a documentation cross-verifier. That review found twelve real defects — a bypass through the shell `workdir`, unscanned `grep`/`glob` selectors, bracket-expansion and bare-glob evasions, quoted bare names, a config typo that silently disarmed the guard, sibling-path corruption in the result filter, an allow-list that outran the hidden paths, and a quadratic regex — all of which are fixed here and covered by regression tests.

## Ecosystem

`dsh` is MIT-licensed and its [CONTRIBUTING guide](https://github.com/deepseek-ai/deepseek-harness/blob/master/CONTRIBUTING.md) invites community plugins, asking authors to add the [`dsh-plugin`](https://github.com/topics/dsh-plugin) topic for discoverability. This plugin was written from scratch after auditing community guards for the same problem; it shares no code with them. Feedback is welcome via [GitHub Discussions](https://github.com/deepseek-ai/deepseek-harness/discussions).

## License

MIT
