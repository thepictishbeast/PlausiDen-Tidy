#!/usr/bin/env python3
"""composition.py — composition / DRY enforcement audit.

Walks a target tree and runs language-aware checks for duplicated
behaviour that should be promoted into a typed reuse mechanism
(CSS custom properties, Rust derive macros, blanket impls, TS mixins,
etc.).

Subcommands:
    css     — raw colour/spacing literals + duplicated rule bodies
    rust    — duplicated impl blocks + manual-impl-of-derivable
    ts      — duplicated class methods + decorator-stack repetition
    dry     — cross-language duplicated code blocks
    derive  — fast subset of `rust` for manual-impl-of-derivable only
    baseline — write the current finding set as the suppression baseline
    all     — every check above (default)

Exit codes:
    0  — clean (no NEW findings; baseline-listed findings ignored)
    1  — new findings present (CI gate fails)
    2  — tool error

Usage:
    python3 scripts/composition.py [SUBCOMMAND] [PATH]
    python3 scripts/composition.py baseline [PATH]   # snapshot current

Default PATH is the current working directory. Baseline file lives
at <PATH>/.composition-baseline.json — commit it so the ratchet
moves with the repo.

Environment toggles (rarely needed):
    COMPOSITION_DRY_MIN_LINES (default 3)
    COMPOSITION_DRY_MIN_OCC   (default 3)
    COMPOSITION_DRY_MIN_TOKENS (default 10)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

# ---------------------------------------------------------------------------
# Ignore patterns
# ---------------------------------------------------------------------------

IGNORE_DIR_PARTS = {
    "target",
    "node_modules",
    ".git",
    "dist",
    "build",
    ".cargo",
    ".venv",
    "vendor",
    "runs",
    "snapshots",
    "static",  # compiled / minified bundles + framework-emitted assets
    "public",
    "out",
    "coverage",
    "__pycache__",
}

# File-name regexes that mark a generated artefact even when the parent dir
# isn't listed above (typical hashed-bundle outputs).
GENERATED_FILE_RE = re.compile(
    r"(\.min\.|-[0-9a-f]{8,}\.|bundle\.|chunk\.|vendor\.)"
)

# Files / paths that are inherently allowed to hold raw values
# (token sources, generated outputs).
TOKEN_SOURCE_HINTS = (
    "loom-tokens",
    "tokens.css",
    "tokens.rs",
    "tokens.scss",
    "/static/loom.css",
    "design-tokens",
)


def is_ignored(path: Path) -> bool:
    parts = set(path.parts)
    if parts & IGNORE_DIR_PARTS:
        return True
    return bool(GENERATED_FILE_RE.search(path.name))


def is_token_source(path: Path) -> bool:
    s = str(path)
    return any(hint in s for hint in TOKEN_SOURCE_HINTS)


def walk(root: Path, suffixes: tuple[str, ...]) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored dirs in-place
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIR_PARTS]
        for fn in filenames:
            if fn.endswith(suffixes):
                yield Path(dirpath) / fn


# ---------------------------------------------------------------------------
# Finding model + reporter
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    path: Path
    line: int
    rule: str
    detail: str
    fix: str

    def emit(self, root: Path) -> str:
        rel = self.path.relative_to(root) if self.path.is_relative_to(root) else self.path
        return f"{rel}:{self.line}: [{self.rule}] {self.detail}\n  fix: {self.fix}"

    def baseline_key(self, root: Path) -> str:
        """Stable identity for baseline matching: rule + relative path
        + finding detail. Line numbers omitted on purpose so cosmetic
        re-orderings don't require a baseline rewrite."""
        rel = self.path.relative_to(root) if self.path.is_relative_to(root) else self.path
        return f"{self.rule}|{rel}|{self.detail}"


class Reporter:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.findings: list[Finding] = []

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def render(self) -> str:
        if not self.findings:
            return "composition: clean\n"
        out = [f"composition: {len(self.findings)} finding(s)\n"]
        # Group by rule for readability
        by_rule: dict[str, list[Finding]] = defaultdict(list)
        for f in self.findings:
            by_rule[f.rule].append(f)
        for rule in sorted(by_rule):
            entries = by_rule[rule]
            out.append(f"\n# [{rule}] — {len(entries)} finding(s)\n")
            for f in entries[:50]:  # cap per-rule output
                out.append(f.emit(self.root))
                out.append("")
            if len(entries) > 50:
                out.append(f"  ... + {len(entries) - 50} more\n")
        return "\n".join(out)


# ---------------------------------------------------------------------------
# CSS check
# ---------------------------------------------------------------------------

# Match #abc, #aabbcc, #aabbccdd
HEX_COLOUR = re.compile(r"#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b")
RGB_COLOUR = re.compile(r"\brgba?\s*\(", re.IGNORECASE)
SPACING_LITERAL = re.compile(r"\b(?<!--)\d+(?:\.\d+)?(px|rem|em)\b")
# Named CSS colors that should be tokenized (very common ones)
NAMED_COLOUR = re.compile(r":\s*(white|black|red|blue|green|yellow)\s*[;}]", re.IGNORECASE)


def check_css(root: Path, reporter: Reporter) -> None:
    bodies: dict[str, list[tuple[Path, int, str]]] = defaultdict(list)
    for p in walk(root, (".css", ".scss")):
        if is_ignored(p) or is_token_source(p):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Per-line literal scan
        for ln, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "/*", "*", "#", "--")):
                # Comment / custom-property declaration line
                continue
            if HEX_COLOUR.search(line):
                reporter.add(Finding(
                    path=p, line=ln, rule="css-raw-colour",
                    detail=line.strip()[:120],
                    fix="promote to var(--loom-color-*) in loom-tokens",
                ))
            if RGB_COLOUR.search(line):
                reporter.add(Finding(
                    path=p, line=ln, rule="css-raw-colour",
                    detail=line.strip()[:120],
                    fix="promote to var(--loom-color-*) in loom-tokens",
                ))
            if SPACING_LITERAL.search(line):
                reporter.add(Finding(
                    path=p, line=ln, rule="css-raw-spacing",
                    detail=line.strip()[:120],
                    fix="promote to var(--loom-space-*) in loom-tokens",
                ))
        # Duplicated rule bodies
        for selector, body in _split_css_rules(text):
            key = _normalize_css_body(body)
            if key:
                bodies[key].append((p, body.count("\n"), selector))
    for key, occs in bodies.items():
        if len(occs) >= 3:
            head = occs[0]
            reporter.add(Finding(
                path=head[0], line=head[1] or 1, rule="css-duplicated-body",
                detail=f"identical declaration body across {len(occs)} selectors: {head[2][:60]} …",
                fix="extract a utility class or @apply / @extend",
            ))


_RULE_RE = re.compile(r"([^{}]+)\{([^{}]+)\}", re.MULTILINE)


def _split_css_rules(text: str) -> list[tuple[str, str]]:
    return [(m.group(1).strip(), m.group(2).strip()) for m in _RULE_RE.finditer(text)]


def _normalize_css_body(body: str) -> str:
    decls = sorted(d.strip() for d in body.split(";") if d.strip())
    return ";".join(decls)


# ---------------------------------------------------------------------------
# Rust check
# ---------------------------------------------------------------------------

DERIVABLE_TRAITS = {
    "Debug", "Clone", "Copy", "Default", "Hash", "PartialEq", "Eq",
    "Ord", "PartialOrd", "Serialize", "Deserialize",
}

MANUAL_IMPL = re.compile(
    r"impl\s+(?:<[^>]+>\s+)?(\w+)(?:<[^>]+>)?\s+for\s+(\w+)(?:<[^>]+>)?\s*\{",
)

# Heuristic: very-short bodies likely trivial enough to derive.
TRIVIAL_BODY_LINE_BUDGET = 10


def check_rust(root: Path, reporter: Reporter) -> None:
    impl_bodies: dict[tuple[str, str], list[tuple[Path, int, str]]] = defaultdict(list)

    for p in walk(root, (".rs",)):
        if is_ignored(p):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Derive-detector
        for ln, line in enumerate(text.splitlines(), start=1):
            m = MANUAL_IMPL.search(line)
            if not m:
                continue
            trait = m.group(1)
            ty = m.group(2)
            if trait not in DERIVABLE_TRAITS:
                # Non-derivable trait — but still candidate for impl-dedup
                body, body_lines = _slurp_block(text, line_idx=ln - 1)
                if body:
                    impl_bodies[(trait, _normalize_rust_body(body))].append((p, ln, ty))
                continue
            # Try to read a few lines after the impl to estimate body size
            body, body_lines = _slurp_block(text, line_idx=ln - 1)
            if body_lines <= TRIVIAL_BODY_LINE_BUDGET:
                reporter.add(Finding(
                    path=p, line=ln, rule="rust-manual-derivable",
                    detail=f"manual impl {trait} for {ty} (trivial body)",
                    fix=f"replace with #[derive({trait})] on the type",
                ))

    # Duplicated impl bodies across types — same trait, same body, ≥3 types
    for (trait, _key), occs in impl_bodies.items():
        if len(occs) >= 3:
            types = sorted({ty for _, _, ty in occs})
            head = occs[0]
            reporter.add(Finding(
                path=head[0], line=head[1], rule="rust-impl-dupe",
                detail=f"impl {trait} duplicated across {len(types)} types: {', '.join(types[:5])}{' …' if len(types) > 5 else ''}",
                fix=f"write a blanket impl<T: Bound> {trait} for T or factor through a supertrait",
            ))


def _slurp_block(text: str, line_idx: int) -> tuple[str, int]:
    """Best-effort capture of the brace-delimited body starting at line_idx.

    Stops at the first closing brace at brace-depth 0. Returns the body and
    the line count.
    """
    lines = text.splitlines()
    if line_idx >= len(lines):
        return "", 0
    depth = 0
    started = False
    body: list[str] = []
    for line in lines[line_idx:]:
        for ch in line:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        body.append(line)
        if started and depth <= 0:
            break
        if len(body) > 200:  # safety cap
            break
    return "\n".join(body), len(body)


def _normalize_rust_body(body: str) -> str:
    # Strip comments + whitespace; keep structural shape for grouping.
    out: list[str] = []
    for line in body.splitlines():
        s = line.strip()
        if not s or s.startswith("//"):
            continue
        out.append(re.sub(r"\s+", " ", s))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# TS / JS check
# ---------------------------------------------------------------------------

DECORATOR_RE = re.compile(r"^\s*(@\w+(?:\([^)]*\))?\s*)+", re.MULTILINE)


def check_ts(root: Path, reporter: Reporter) -> None:
    method_bodies: dict[str, list[tuple[Path, int, str]]] = defaultdict(list)
    decorator_chains: dict[str, list[tuple[Path, int]]] = defaultdict(list)

    for p in walk(root, (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        if is_ignored(p):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Decorator chains
        for m in DECORATOR_RE.finditer(text):
            chain = re.sub(r"\s+", " ", m.group(0).strip())
            if chain.count("@") >= 2:
                ln = text[: m.start()].count("\n") + 1
                decorator_chains[chain].append((p, ln))

        # Class method bodies — simple regex, name { body }
        for m in re.finditer(r"^\s*(?:public\s+|private\s+|protected\s+|static\s+)*async?\s*(\w+)\s*\([^)]*\)\s*(?::\s*[^\{]+)?\s*\{", text, flags=re.MULTILINE):
            ln = text[: m.start()].count("\n") + 1
            body, n_lines = _slurp_block(text, line_idx=ln - 1)
            if n_lines >= 3:
                key = _normalize_ts_body(body)
                if key and len(key) > 60:
                    method_bodies[key].append((p, ln, m.group(1)))

    for key, occs in method_bodies.items():
        if len(occs) >= 3:
            names = sorted({name for _, _, name in occs})
            head = occs[0]
            reporter.add(Finding(
                path=head[0], line=head[1], rule="ts-method-dupe",
                detail=f"method body duplicated across {len(occs)} sites; method names: {', '.join(names[:5])}",
                fix="extract base class, mixin, or composition function",
            ))

    for chain, occs in decorator_chains.items():
        if len(occs) >= 3:
            head = occs[0]
            reporter.add(Finding(
                path=head[0], line=head[1], rule="ts-decorator-chain-dupe",
                detail=f"decorator chain `{chain}` repeated {len(occs)} times",
                fix="wrap into a composite decorator",
            ))


def _normalize_ts_body(body: str) -> str:
    out: list[str] = []
    for line in body.splitlines():
        s = line.strip()
        if not s or s.startswith("//") or s.startswith("/*"):
            continue
        out.append(re.sub(r"\s+", " ", s))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Cross-language DRY check
# ---------------------------------------------------------------------------

DRY_SUFFIXES = (
    ".rs", ".ts", ".tsx", ".js", ".jsx", ".css", ".scss",
    ".py", ".sh", ".yaml", ".yml", ".toml", ".sql", ".html",
)

# Lines that don't count toward the duplication threshold.
DRY_TRIVIAL = re.compile(r"^\s*(?://|#|/\*|\*|--|<!--|use |import |from |pub use|\}|\{|\)|;|$)")


def check_dry(root: Path, reporter: Reporter) -> None:
    min_lines = int(os.environ.get("COMPOSITION_DRY_MIN_LINES", "3"))
    min_occ = int(os.environ.get("COMPOSITION_DRY_MIN_OCC", "3"))
    min_tokens = int(os.environ.get("COMPOSITION_DRY_MIN_TOKENS", "10"))

    blocks: dict[str, list[tuple[Path, int]]] = defaultdict(list)

    for p in walk(root, DRY_SUFFIXES):
        if is_ignored(p):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        for i in range(len(lines) - min_lines + 1):
            window = lines[i : i + min_lines]
            # Skip if any line carries a per-line suppression marker
            if any("composition-allow:" in ln for ln in window):
                continue
            # Skip if any line in the window is trivial
            if any(DRY_TRIVIAL.match(ln) for ln in window):
                continue
            # Token count gate
            tokens = sum(len(ln.split()) for ln in window)
            if tokens < min_tokens:
                continue
            normalized = "\n".join(re.sub(r"\s+", " ", ln.strip()) for ln in window)
            digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:16]
            blocks[digest].append((p, i + 1))

    for _digest, occs in blocks.items():
        if len(occs) >= min_occ:
            head = occs[0]
            unique_paths = sorted({str(p) for p, _ in occs})
            # Skip if all occurrences are in the same file (often legitimate)
            if len(unique_paths) == 1:
                continue
            reporter.add(Finding(
                path=head[0], line=head[1], rule="dry-duplicate-block",
                detail=f"{min_lines}+ identical-line block recurs {len(occs)} times across {len(unique_paths)} files",
                fix="extract a function / mixin / shared module",
            ))


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

CHECKS = {
    "css": check_css,
    "rust": check_rust,
    "ts": check_ts,
    "dry": check_dry,
    "derive": lambda root, rep: check_rust(root, rep),  # fast subset
}


BASELINE_FILE = ".composition-baseline.json"


def load_baseline(root: Path) -> set[str]:
    p = root / BASELINE_FILE
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"composition: baseline at {p} unreadable: {e}", file=sys.stderr)
        return set()
    return set(data.get("suppressed", []))


def write_baseline(root: Path, findings: list[Finding]) -> None:
    p = root / BASELINE_FILE
    keys = sorted({f.baseline_key(root) for f in findings})
    payload = {
        "schema": "composition-baseline/1",
        "comment": (
            "Snapshot of pre-existing composition findings. Committed so "
            "the CI gate fails only on NEW findings. Re-snapshot via "
            "`python3 .github/scripts/composition.py baseline .`"
        ),
        "suppressed": keys,
    }
    p.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"composition: wrote baseline with {len(keys)} suppressed finding(s) → {p}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Composition / DRY audit.")
    parser.add_argument(
        "subcommand",
        nargs="?",
        default="all",
        choices=["all", "css", "rust", "ts", "dry", "derive", "baseline"],
        help="Which sub-check to run, or `baseline` to snapshot the current findings.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Target directory (default: cwd).",
    )
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"composition: target {root} does not exist", file=sys.stderr)
        return 2

    reporter = Reporter(root)
    if args.subcommand in ("all", "baseline"):
        for name in ("css", "rust", "ts", "dry"):
            CHECKS[name](root, reporter)
    else:
        CHECKS[args.subcommand](root, reporter)

    if args.subcommand == "baseline":
        write_baseline(root, reporter.findings)
        return 0

    suppressed = load_baseline(root)
    if suppressed:
        before = len(reporter.findings)
        reporter.findings = [f for f in reporter.findings if f.baseline_key(root) not in suppressed]
        skipped = before - len(reporter.findings)
        if skipped:
            print(
                f"composition: {skipped} pre-existing finding(s) suppressed by baseline "
                f"({BASELINE_FILE})"
            )

    print(reporter.render())
    return 0 if not reporter.findings else 1


if __name__ == "__main__":
    sys.exit(main())
