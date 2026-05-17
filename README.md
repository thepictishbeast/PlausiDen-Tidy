> # ⚠️ DO NOT USE — UNVERIFIED — UNSAFE ⚠️
>
> This software is **unverified and unsafe for any production use**.
> It is published publicly only for transparency, third-party audit,
> and reproducibility. Treat every commit as guilty until proven
> innocent.
>
> By using this code you accept:
> - **No warranty** of any kind, express or implied.
> - **No fitness** for any particular purpose.
> - **No guarantee** of correctness, safety, or freedom from defects.
> - **Zero liability** on the maintainer for any damages — data loss,
>   security compromise, financial loss, or any consequential damages.
>
> The code is under active engineering development per the
> [Adversarial Validation Protocol v2](https://github.com/thepictishbeast/PlausiDen-AVP-Doctrine/blob/main/AVP2_PROTOCOL.md).
> Every commit's default verdict is **STILL BROKEN**. AVP-2 requires
> a minimum of 36 verification passes before a `SHIP-DECISION:`
> annotation may be considered. **No commit in this repository has
> reached `SHIP-DECISION:` status.**

# PlausiDen-Tidy

Smart filesystem cleaner with importance-aware safety and optional secure-wipe delegation to [PlausiDen-Purge](https://github.com/thepictishbeast/PlausiDen-Purge).

Part of the [PlausiDen](https://github.com/thepictishbeast) civil rights toolkit. Where Purge provides paranoid multi-pass destruction, Tidy is the everyday cleaner you reach for when you just want to reclaim disk space without losing anything important.

## Design goals

- **Metadata-first.** The scanner walks the filesystem looking at `stat` output — sizes, timestamps, inode counts — not contents. Content reads happen only where strictly necessary (duplicate hashing) and never leave the device.
- **Safety classifier refuses to touch what matters.** Dotfiles, SSH/GPG keys, source repositories, package manifests, configuration databases, browser profile cores — all off-limits by default.
- **Dry-run by default.** Every operation produces a plan. Nothing is deleted without explicit, per-batch confirmation.
- **Two delete paths.** Simple `unlink(2)` for everyday cleanup, optional delegation to PlausiDen-Purge for secure multi-pass wipe. You choose per-action.
- **Connectable with Purge.** A shared frontend UI can host both tools so the simple cleaner and the paranoid shredder live on the same dashboard.

## Features

- Duplicate file detection (two-stage: size bucket → BLAKE3)
- Old-file analysis (atime/mtime) with configurable age thresholds
- Largest-files ranking
- Importance classifier with user-adjustable allowlist/blocklist
- `CleanupPlan` abstraction: a sequence of pending actions that can be reviewed, filtered, and committed
- Simple delete built-in; Purge delegation behind the `purge` feature flag

## Usage

```bash
tidy scan ~/Downloads               # dry-run report
tidy duplicates ~/Documents         # find dup groups
tidy old --days 365 ~/Downloads     # flag stale files
tidy large --top 50 ~/              # biggest files
tidy plan --out plan.json ~/tmp     # write a plan to disk
tidy apply plan.json                # interactive commit
tidy apply --purge plan.json        # secure wipe via PlausiDen-Purge
```

## Project status

Under active development. Scanner, importance classifier, and duplicate detection are the first modules to land.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
