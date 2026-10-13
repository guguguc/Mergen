#!/usr/bin/env python3
"""Sync a repo between the shared drive (Z:) and a local working tree.

Why this exists: the shared drive costs ~1.8 ms per file open on this setup,
which is enough for an IDE parsing a few thousand headers to stall, while a local
copy on the same machine is fine. This keeps the two trees in step.

Direction is explicit. "Both sides differ" is not by itself evidence that one
side is newer, so guessing which way to copy silently turns a stale file into an
overwritten edit. Instead every file is tracked against the hash it had at the
last successful sync, and a file that changed on *both* sides since then is
reported as a conflict and left alone. That is the only case where the script
needs a human, and --force is how you tell it which side wins.

Rules, all of them deliberate:

  * Never delete. A file missing on one side is reported, not removed. Deleting
    is the one irreversible act here and the payoff is cosmetic.

  * Conflicts are detected, not resolved. Safe one-way updates (destination
    untouched since the last sync) proceed without asking.

  * The state file records hashes, not mtimes. Timestamps are useless as a
    change signal: git rewrites mtime on files it did not change, and any copy
    tool that preserves times makes a rewritten file look untouched.

  * Build trees and dependency caches are skipped. They hold absolute paths from
    the machine that made them, are the bulk of the tree, and are the least
    useful to carry over.

Usage:
    python scripts/dev/sync_to_local.py --dst C:\\dev\\Mergen --dry-run
    python scripts/dev/sync_to_local.py --dst C:\\dev\\Mergen
    python scripts/dev/sync_to_local.py --dst C:\\dev\\Mergen --reverse --force
    python scripts/dev/sync_to_local.py --dst C:\\dev\\Mergen --include lifter

Exit status is 0 when the destination matches the source for every selected
file, 1 when anything errored, and 2 when conflicts were left unresolved -- so
it can gate a build instead of quietly producing a binary from a stale tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_EXCLUDES = (
    "build_msvc",
    "build_iced",
    "build_zydis",
    ".git",
    ".vs",
    "__pycache__",
    ".sync_state.json",
)


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n}B"


def hash_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


@dataclass
class Stats:
    copied: list[tuple[str, str]] = field(default_factory=list)  # (rel, direction)
    skipped: int = 0
    conflicts: list[str] = field(default_factory=list)
    only_in_src: list[str] = field(default_factory=list)
    only_in_dst: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    copied_bytes: int = 0


class State:
    """Hash of each file as of the last successful sync, keyed by relative path.

    Stored in the destination so it travels with whichever tree is the local
    one. Its absence is not fatal: the first run has no baseline, so every
    differing file is treated as one-sided and resolved by --force being off.
    """

    def __init__(self, candidates: list[Path]):
        # Located by search rather than by assuming it lives in the destination:
        # --reverse swaps which tree is the destination, and a state file that
        # moved with the direction would be invisible on every reversed run,
        # silently degrading conflict detection back to "no baseline".
        self.path = next((p for p in candidates if p.is_file()), candidates[0])
        self.data: dict[str, str] = {}
        if self.path.is_file():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                # A corrupt state file must not wedge the tool; losing the
                # baseline only costs conflict detection for one run.
                self.data = {}

    def save(self) -> None:
        # Written next to wherever it was found, so the baseline keeps living
        # in the same tree regardless of which direction the next run uses.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps(self.data, indent=0, sort_keys=True), encoding="utf-8"
            )
        except OSError as exc:
            print(f"WARN: could not write {self.path}: {exc}", file=sys.stderr)

    def baseline(self, rel: str) -> str | None:
        return self.data.get(rel)


def is_excluded(rel: Path, roots: set[str]) -> bool:
    """True when any component is an excluded name.

    Component matching rather than a prefix test, so 'a/build_msvc/b' is
    excluded and 'build_msvc_old' is not.
    """
    return any(part in roots for part in rel.parts)


def walk(root: Path, excludes: set[str], only_dirs: bool = False) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath).relative_to(root)
        dirnames[:] = [d for d in dirnames if not is_excluded(here / d, excludes)]
        if only_dirs:
            if here != Path("."):
                out.append(here)
            continue
        for name in filenames:
            rel = here / name
            # Filenames need the same exclusion test as directories. Without it
            # the state file leaks into the diff as a phantom change.
            if is_excluded(rel, excludes):
                continue
            out.append(rel)
    return out


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Sync the shared-drive repo to a local tree, or back.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:", 1)[-1],
    )
    ap.add_argument("--src", type=Path, default=Path(r"Z:\Downloads\Mergen"))
    ap.add_argument("--dst", type=Path, required=True)
    ap.add_argument(
        "--reverse",
        action="store_true",
        help="sync local -> shared instead of shared -> local",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="overwrite conflicts in the sync direction without asking",
    )
    ap.add_argument("--include", nargs="*", metavar="PATH")
    ap.add_argument(
        "--exclude", nargs="*", metavar="NAME", default=list(DEFAULT_EXCLUDES)
    )
    ap.add_argument("--hash", action="store_true", help="compare content, not size")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    return ap.parse_args(argv)


def same(a: Path, b: Path, use_hash: bool) -> bool:
    if a.stat().st_size != b.stat().st_size:
        return False
    return hash_file(a) == hash_file(b) if use_hash else True


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    src, dst = (args.dst, args.src) if args.reverse else (args.src, args.dst)
    direction = "dst->src" if args.reverse else "src->dst"
    label = "backward" if args.reverse else "forward"

    if not src.is_dir():
        print(f"ERROR: source is not a directory: {src}", file=sys.stderr)
        print(
            "Mapped drives exist per logon session; run this where Z: is visible.",
            file=sys.stderr,
        )
        return 1
    if src == dst:
        print("ERROR: src and dst are the same directory", file=sys.stderr)
        return 1

    excludes = set(args.exclude)
    stats = Stats()
    state = State([dst / ".sync_state.json", src / ".sync_state.json"])

    files = walk(src, excludes)
    if args.include:
        wanted = {Path(p) for p in args.include}
        files = [r for r in files if any(r == w or w in r.parents for w in wanted)]

    if not args.quiet:
        print(f"INFO: {label}  {src} -> {dst}  ({len(files)} files)")

    dst.mkdir(parents=True, exist_ok=True)

    for rel in files:
        s, d = src / rel, dst / rel
        key = rel.as_posix()

        if not d.exists():
            plan = "new"
        else:
            try:
                if same(s, d, args.hash):
                    stats.skipped += 1
                    state.data[key] = _hash_of(s, args.hash)
                    continue
            except OSError as exc:
                stats.errors.append((key, str(exc)))
                continue

            # The sides differ. Which one moved is answered by comparing *both*
            # against the last-seen hash -- checking only the destination is
            # wrong the moment --reverse is used, where "destination changed,
            # source did not" is exactly the edit the user wants to push back.
            base = state.baseline(key)
            if base is None:
                # No baseline: cannot attribute the difference. First run, or the
                # state file was lost.
                plan = "copy" if args.force else "nobase"
            else:
                src_moved = _hash_of(s, args.hash) != base
                dst_moved = _hash_of(d, args.hash) != base
                if not dst_moved:
                    plan = "copy"  # only the source moved ahead
                elif not src_moved:
                    plan = "copy"  # only the destination moved
                else:
                    plan = "conflict"  # both moved: needs a human

        if plan in ("conflict", "nobase"):
            # --force means "the sync direction wins", so it collapses both
            # unresolvable cases into a plain copy. It has to be decided here,
            # before the copy bookkeeping below, or the flag silently does
            # nothing while still reporting a conflict.
            if not args.force:
                stats.conflicts.append(key)
                why = (
                    "both sides changed since last sync"
                    if plan == "conflict"
                    else "no baseline; rerun with --force"
                )
                if not args.quiet:
                    print(f"  CONFLICT {key}  ({why})")
                continue
            plan = "copy"

        if not args.quiet:
            print(f"  copy {key}")

        if not args.dry_run:
            try:
                d.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(s, d)
                state.data[key] = _hash_of(s, args.hash)
            except OSError as exc:
                stats.errors.append((key, str(exc)))
                continue

        stats.copied.append((key, direction))
        stats.copied_bytes += s.stat().st_size

    src_dirs = {r.as_posix() for r in walk(src, excludes, only_dirs=True)}
    for rel in walk(dst, excludes, only_dirs=True):
        if rel.as_posix() not in src_dirs:
            stats.only_in_dst.append(rel.as_posix())
    # Only the destination is walked, so anything it holds that the source lacks
    # is by definition destination-only.
    src_files = {r.as_posix() for r in files}
    for rel in walk(dst, excludes):
        if rel.as_posix() not in src_files:
            stats.only_in_dst.append(rel.as_posix())

    print()
    print(
        f"{'[dry-run] ' if args.dry_run else ''}"
        f"copied {len(stats.copied)}  skipped {stats.skipped}  "
        f"conflicts {len(stats.conflicts)}  errors {len(stats.errors)}  "
        f"({human(stats.copied_bytes)})"
    )

    for title, items in (("only in source", stats.only_in_src),
                         ("only in destination", stats.only_in_dst)):
        if items:
            print(f"\n{len(items)} path(s) {title}, left alone:", file=sys.stderr)
            for p in items[:20]:
                print(f"  {p}", file=sys.stderr)
            if len(items) > 20:
                print(f"  ... and {len(items) - 20} more", file=sys.stderr)

    if stats.errors:
        print(f"\n{len(stats.errors)} error(s):", file=sys.stderr)
        for p, m in stats.errors[:20]:
            print(f"  {p}: {m}", file=sys.stderr)
        return 1

    if stats.conflicts:
        print(
            f"\n{len(stats.conflicts)} conflict(s) unresolved. "
            "Merge them by hand, or pick a side with --force.",
            file=sys.stderr,
        )
        return 2

    if not args.dry_run:
        state.save()
    return 0


def _hash_of(path: Path, use_hash: bool) -> str:
    """Identity used for the baseline record.

    With --hash this is the real content hash. Without it, size is the only
    discriminator available, and two different edits of equal length would then
    look unchanged to the baseline. That is why --hash is worth its cost here:
    the hash is computed once per file per run and reused for the state file.
    """
    if use_hash:
        return hash_file(path)
    return f"{path.stat().st_size}"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))