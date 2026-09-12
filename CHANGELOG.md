# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-12

First public release.

### Added

- **Layer 1 — path denial** through a monotonic `ctx.tools.guard()`, covering file
  tools, shell commands, `glob`/`grep` selectors and `run_code` text.
- **Layer 2 — result filtering** through a `tools/post-execute` listener that masks
  hidden path names as `[hidden]` and credential-shaped values as `[redacted:kind]`.
- `hiddenPaths` configuration for arbitrary files and folders, with `guardRoots` kept
  as a legacy alias, plus `extraNameRules`, `extraDirSegments`, `allow`,
  `maskResults`, `hidePathsInResults` and `maskNotice`.
- Symlink resolution for configured `hiddenPaths`, including through a link whose
  target leaf does not exist yet.
- A 62-case decision table plus configuration, hidden-path, redaction, wiring and
  regression tests.

### Security

Twelve defects found by an independent pre-release audit, all fixed and covered by
regression tests:

- the shell `workdir` argument was not inspected, and relative command tokens
  ignored it;
- `grep`/`glob` selectors (`pattern`, `include`, `exclude`) were not scanned;
- bracket (`[v]`) and brace (`{a,b}`) expansion evaded the shell scan;
- the bare dotfile glob `.*` slipped past the prefix heuristic;
- a quoted bare protected name (`cat "secrets"`) evaded the scan;
- a **string** `hiddenPaths` value spread into its characters and silently disarmed
  the guard;
- `hiddenPaths: ["/"]` protected nothing;
- the result filter corrupted sibling paths sharing the hidden prefix
  (`/srv/vault` rewrote `/srv/vaulted/x`);
- a symlink to a not-yet-existing leaf escaped the realpath check;
- the `allow` list could re-open an explicitly hidden path, including through a
  symlink;
- an unbounded private-key regex could stall the awaited post-execute hook
  (quadratic on repeated markers); the block is now found by a linear scan, which
  also removes the size limit that silently left large keys unredacted;
- a config type error could abort plugin mount instead of arming the guard.

### Security — second audit round

A verification round over the fixes above found more, all fixed and covered:

- quote splicing (`.en''v`), backslash escapes (`.en\v`) and ANSI-C quoting
  (`$'\x2eenv'`) reached protected names; shell text is now normalised the way the
  shell reads it, and bracket/brace expansion iterates to a bounded fixed point
  (covering `.{en,fo}{v,x}` and negated classes such as `.en[!x]`);
- a glob that could expand onto a hidden path without naming it
  (`cat /srv/*/note.txt`) was allowed; globs are now tested against the configured
  hidden paths, including one that descends through a directory;
- a relative path after a `cd` in the same command (`cd /srv && cat vault/x`) was
  resolved only against the original base; every `cd` target is now tried;
- the result filter still corrupted unrelated paths that merely ended with the
  hidden basename (`/mnt/backup/srv/vault`); the basename form is now anchored to
  the start of a path token;
- over-blocking introduced by the first round: searching for the words `secrets`
  or `credentials`, single-character globs (`ls c*`) and quoted prose mentioning a
  protected name (`git commit -m "update .env"`) were wrongly denied, and are not
  any more;
- `hiddenPaths` entries containing a glob now warn instead of silently protecting
  nothing, and respellings of the filesystem root (`//`, `/./`) are detected.

[1.0.0]: https://github.com/Gabrip780/dsh-hidden-paths/releases/tag/v1.0.0
