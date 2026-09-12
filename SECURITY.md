# Security Policy

## What this plugin is, and is not

`dsh-hidden-paths` is a **policy guard on a cooperative runtime**, not a kernel
sandbox. It denies an AI agent's tool calls when they resolve to a protected path,
through file tools, shell commands, search selectors and code text.

It is designed to stop accidents, prompt-injected instructions ("please `cat` my
`.env`") and routine overreach. It is **not** a boundary against a determined
adversary, and the README documents the known bypasses in full — textual shell
analysis, arbitrary code execution through `run_code`, symlinks on the default
name rules, and shape-based (not semantic) redaction in layer 2.

Reports that show a bypass which the README already lists as a limitation will be
answered with a pointer to that section. Reports that show a bypass **not** listed,
a false positive that blocks legitimate work, a way to silently disarm the guard,
or corruption of legitimate tool output are all genuinely useful — those are the
bugs worth fixing here.

## Reporting a vulnerability

Please **do not** open a public issue for a security-relevant finding. Use GitHub's
private vulnerability reporting for this repository (Security → Report a
vulnerability), or reach the maintainer directly.

Include:

- the version of the plugin, of `dsh`, and the Node version;
- the configuration in force (redact anything secret);
- a minimal reproduction: the exact tool call, command or file layout;
- what you expected and what happened;
- whether the same input is reachable by accident, or only deliberately.

## Scope

In scope:

- a bypass of a **configured `hiddenPaths`** entry;
- a false positive that blocks ordinary work in a way the README does not describe;
- a way to make the guard fail **open**, crash the mount, or deny everything
  unintentionally;
- corruption of tool output by the layer-2 filter;
- anything the plugin does that its documentation does not disclose.

Out of scope (documented limitations, not vulnerabilities):

- shell indirection: interpreters, variables, `base64`, `find -exec`, `env`,
  `/proc`, hardlinks, file descriptors;
- splitting a **bare** name across quote boundaries (`"sec"rets`). Quoted
  fragments are joined, but a word that came from inside a quoted span is treated
  as prose so that `git commit -m "update .env"` is not blocked — the price is
  that this one spelling of a bare name is not caught. Names with a path
  separator or a leading dot are unaffected;
- `run_code` executing arbitrary code — the plugin only inspects its text;
- a credential in a format layer 2 does not recognise;
- a symlink with an innocent name pointing at a secret (default name rules);
- anything an agent can read being copyable elsewhere.

Explicitly **covered** (do report a failure here):

- `workdir`/`cwd` arguments, and relative paths after a `cd` in the same command;
- bracket `[v]`, brace `{a,b}`, ANSI-C `$'\x2eenv'`, backslash and quote-splicing
  spellings of a name with a separator or a leading dot;
- a glob that could expand onto a configured hidden path, including one that
  descends through a directory (`/srv/*/note.txt`);
- symlinks — including a link whose target leaf does not exist yet;
- a `hiddenPaths` entry that a config typo would otherwise disarm.

## Supported versions

The latest released minor line receives fixes.
