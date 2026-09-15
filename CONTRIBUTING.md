# Contributing

Thanks for considering a contribution. This is a small, focused plugin, and the
most valuable contributions are precisely the ones the security policy asks for:
a bypass that is **not** already documented, a false positive that blocks
legitimate work, or a way to disarm the guard silently.

## Before you open a pull request

```bash
node test.js          # must print 93 PASS lines and exit 0
```

There is no build step and no dependency to install — the plugin uses only Node
built-ins and runs directly from `lib/index.js`.

## What a good change looks like

- **A failing test first.** The suite is a decision table plus grouped assertions
  and it asserts both directions: what must be denied, and what must stay allowed.
  A fix without a test that fails before it and passes after it will be asked for
  one, because a guard that over-blocks is as broken as one that under-blocks.
- **No content corruption.** The two rules that keep layer 2 safe are load-bearing:
  never match assignment shapes (`api_key = ...`), and never rewrite a hidden name
  outside a real path or directory-listing context. Both have dedicated tests.
- **Honest documentation.** If your change alters what the plugin can or cannot do,
  update the README's threat model in the same change. An overclaim is a bug.
- **No literal secret-shaped strings.** A fixture that must look like a key is
  assembled at runtime — `"AKIA" + "IOSFODNN7EXAMPLE"`, `"-----BEGIN RSA " +
  "PRIVATE KEY-----"` — never written as one literal. A literal one trips GitHub
  secret scanning: a false positive that still raises a real alert and, under push
  protection, can block a push. See the `fake` table in `test.js`.
- **No new dependencies.** The plugin is deliberately dependency-free, and the only
  filesystem call is `realpathSync` on a path the guard is already deciding about.
  A change that reads file content, opens sockets, or spawns processes will be
  rejected regardless of what it enables.

## Commit messages

A short imperative subject line, then a body explaining *why* the change is needed
and what it changes about the plugin's security properties.

## Reporting

- Security-relevant findings: see [SECURITY.md](SECURITY.md) — do not open a public
  issue.
- Everything else: open an issue, or start a thread in the
  [DeepSeek Harness Discussions](https://github.com/deepseek-ai/deepseek-harness/discussions).

## License

By contributing you agree that your contribution is licensed under the MIT License
of this project.
