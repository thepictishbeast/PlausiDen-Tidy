# Tidy = file-rule engine emitting Atrium-compatible cleaners

**Decision date:** 2026-04-26.

Tidy is a Rust-first deterministic rule engine. It walks the filesystem,
applies user-configured rules, and emits cleaner definitions as JSON
matching the
[`DYNAMIC_CLEANER_SCHEMA`](https://github.com/thepictishbeast/PlausiDen-Meta/blob/main/DYNAMIC_CLEANER_SCHEMA.md).

Tidy ships **no UI**. Atrium (a fork of BleachBit) consumes Tidy's
JSON output and presents the cleaners alongside BleachBit's stock ones.

## What Tidy emits

Files at `/var/lib/atrium/dynamic-cleaners/tidy-*.json` (system mode)
or `~/.local/share/atrium/dynamic-cleaners/tidy-*.json` (per-user mode).

Each file is one cleaner. Tidy refreshes its output on every scan;
Atrium auto-reloads via inotify.

## Initial rule set (v0.1 — covers today's biggest offenders)

| Rule id | Catches |
|---|---|
| `tidy-mail-spool-overgrown` | `/var/mail/<user>` > 100 MB |
| `tidy-npm-cache-stale` | `~/.npm` not accessed in 90+ days |
| `tidy-cargo-registry-cache` | `~/.cargo/registry/{cache,src}` |
| `tidy-vscode-caches` | `~/.config/Code/Cache*` etc. |
| `tidy-docker-overlay-stale` | docker overlay layers from removed containers (if docker installed) |
| `tidy-rotated-logs` | `/var/log/*.{1..N,gz}` older than 30 days |
| `tidy-build-artifacts` | `target/` `node_modules/` `dist/` in repos with last commit > 60 days |
| `tidy-tmpfs-leftovers` | `/tmp/*` older than 7 days (best-effort) |
| `tidy-orphan-app-data` | `~/.config/<app>` where binary no longer exists |
| `tidy-broken-symlinks` | dangling symlinks in user dirs |

Rules live in `rules/*.toml`. New rules are PRs.

## Architecture (planned)

```
tidy-cli           → operator interface: scan / inspect / emit
tidy-core (lib)    → rule engine + path walker + predicate evaluator
tidy-rules/        → rule library (TOML files)
tidy-emitter (lib) → schema-compliant JSON writer
tidy-watcher       → systemd timer triggering periodic scans
```

Rust crates, edition 2024, follows PlausiDen-Engine code standards.

## What Tidy does NOT do

- **Never deletes anything.** Tidy only emits recommendations. Atrium
  (or a CLI invocation of `tidy execute --approve`) does the actual
  cleaning, and only after explicit approval.
- **No predicates beyond file metadata.** Rules act on
  size/atime/mtime/owner/type. Anything more sophisticated is computed
  by the rule code at scan time and embedded as a fixed cleaner.
- **No app-detection.** That's AppGuard's job.

## Status

Planning. First implementation slice: tidy-cli + tidy-core + the first
3 rules (mail spool, npm cache, vscode caches) + JSON emitter.
Estimated 1-2 days of focused work.
