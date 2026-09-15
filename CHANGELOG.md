# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] — 2026-09-15

### Changed

- Description aligned with the repository and the README: the plugin also covers the
  search selectors (`glob`/`grep` patterns, `include`, `exclude`) and code executed
  through `run_code`, not only file tools and shell commands.

### Fixed

- **Windows paths in shell commands were not protected.** `normalizeShellText` strips
  backslashes — correct for POSIX escaping, and needed to catch `.en\v` — but on
  Windows the backslash is the path separator, so `cat C:\Users\me\vault\f` collapsed
  into `C:Usersmevaultf` and was never recognised as a path. A second pass now keeps
  backslashes, so a Windows path stays one token; the stripping pass is unchanged.
- **POSIX-style absolute spellings on Windows.** `resolveCandidate` normalised
  `/srv/vault` into a drive-less `\srv\vault`, which could never match a configured
  root resolved as `C:\srv\vault`. Both sides are now resolved with `path.resolve`,
  so the spellings agree.
- **The filesystem-root warning never fired on Windows.** The check compared against
  `path.sep`, so `hiddenPaths: ["/"]` (which resolves to `C:\`) raised no warning;
  the root is now detected with `path.parse(p).root === p`.
- The test suite assumed a POSIX host and **failed on Windows**: it hard-coded `/root`
  as the home directory, compared raw filter text against native-separator paths, and
  created symlinks without allowing for platforms that forbid it. It now builds paths
  from `os.homedir()` and `resolve`, and creates a **junction** on Windows — which
  needs no elevation — falling back to a skip only where the platform still refuses.
- A hidden root is now masked in **both separator spellings**, so a Windows path
  printed as `C:/srv/vault/a.txt` no longer leaves the hidden name visible.

### Security

- The credential-shaped values used as test fixtures are now **assembled at runtime**
  instead of appearing as literals. A literal string with the shape of a key (`AIza…`,
  `ghp_…`, `AKIA…`, PEM blocks) trips GitHub secret scanning: a false positive, but a
  real alert, and under push protection it can block a push. No key was ever real and
  nothing needed revoking. The redaction tests are unchanged and still exercise every
  pattern.

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

[1.0.1]: https://github.com/Gabrip780/dsh-hidden-paths/releases/tag/v1.0.1
[1.0.0]: https://github.com/Gabrip780/dsh-hidden-paths/releases/tag/v1.0.0
