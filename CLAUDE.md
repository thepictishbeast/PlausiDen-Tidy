## Project: plausiden-tidy

Smart filesystem cleaner. Finds duplicates, old files, and large files, using an importance-aware safety classifier that refuses to touch protected paths (dotfiles, source trees, keys, package manifests).

## Safety-critical rules

- **Metadata-only by default.** The scanner must NEVER read file contents into anything that could end up in a log or conversation context. Content reads happen only where strictly needed (e.g. BLAKE3 hashing for dedup) and only to produce a hash digest. Paths and hashes are fine; raw bytes are not.
- **Dry-run by default.** Every operation shows a plan. Deletion requires explicit confirmation.
- **Default-safe importance classifier.** Never suggest deleting paths under `~/.ssh`, `~/.gnupg`, `~/Development`, `~/.config`, dotfiles, package manifests, or anything the importance classifier flags as critical.
- **Two delete paths.** Simple delete (fast, built-in) OR Purge delegation (secure multi-pass wipe via plausiden-purge, behind the `purge` feature). User chooses per-action.

## Modules

- `error` — error enum
- `scanner` — metadata-only walker
- `importance` — path classification and safety heuristics
- `dedup` — two-stage duplicate detection (size bucket → hash)
- `age_analyzer` — old-file detection by atime/mtime
- `size_analyzer` — largest-files ranking
- `action` — FileAction trait, SimpleDelete, PurgeDelete
- `plan` — CleanupPlan builder

## Integrates with

- `plausiden-purge` — via optional `purge` feature for secure wipe
- Shared frontend UI fronts both tools

## Code Standards

Rust 2024, thiserror, serde, no unwrap in library code. Every module has 8-12 tests. Dry-run default, explicit delete confirmation.
