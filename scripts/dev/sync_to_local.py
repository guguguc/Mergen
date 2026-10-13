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

  * Build trees are skipped; .git is not. See DEFAULT_EXCLUDES. Under .git the
    lock and in-progress files are filtered out, because a copied index.lock
    makes every later git operation fail with "File exists".

Usage:
    python scripts/dev/sync_to_local.py --dst C:\\dev\\Mergen --dry-run
    python scripts/dev/sync_to_local.py --dst C:\\dev\\Mergen
    python scripts/dev/sync_to_local.py --dst C:\\dev\\Mergen --reverse --force
    python scripts/dev/sync_to_local.py --dst C:\\dev\\Mergen --include lifter
    python scripts/dev/sync_to_local.py --dst C:\\dev\\Mergen --fast
    python scripts/dev/sync_to_local.py --dst C:\\dev\\Mergen --jobs 16

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
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

# Files under .git that must never be carried across, even when .git is being
# synced (it is excluded by default; --exclude without it opts in).
#
# A stale lock makes git refuse every operation with "Unable to create
# '.../index.lock': File exists" and the obvious fix -- deleting the file --
# can destroy a concurrent operation's real state. Copying one in is worse than
# not copying it at all. The tmp_pack_* files are the same idea: they exist only
# mid-receive and are meaningless anywhere else.
GIT_TRANSIENT = (".lock", "gc.log")
GIT_TMP_PREFIXES = ("tmp_pack_", "tmp_idx_")

# .git is deliberately absent: it is synced. A plain clone's object store and
# refs are relocatable, and keeping the two trees' history in step matters more
# than the handful of files that assume absolute paths (see the note on config
# below). The transient files that make .git unsafe to copy casually are filtered
# by is_git_transient regardless of this list.
#
# What is left out, and why:
#   build_*  carry absolute paths from the machine that generated them; a stale
#           CMakeCache points at the old root, and the build script already wipes
#           it when it detects a mismatch. They are also most of the bytes.
#   .vs      regenerable IDE state, and the build script has its own action for
#           clearing it while VS is closed.
#   .sync_state.json  this script's own bookkeeping; syncing it would let the
#           baseline leak between the two trees.
DEFAULT_EXCLUDES = (
    "build_msvc",
    "build_iced",
    "build_zydis",
    "build_vs",
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
    pruned: list[str] = field(default_factory=list)
    # (seconds, relpath) for the slowest files, so a slow run can be attributed
    # to specific paths instead of guessed at.
    slowest: list[tuple[float, str]] = field(default_factory=list)

    def note(self, seconds: float, rel: str) -> None:
        self.slowest.append((seconds, rel))
        # Keep only the worst few; the list is bounded so a long run does not
        # accumulate one entry per file.
        if len(self.slowest) > 200:
            self.slowest.sort(reverse=True)
            del self.slowest[20:]


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

    def baselines(self):
        return tuple(self.data)


def is_git_transient(rel: Path) -> bool:
    """True for lock and in-progress files under a .git directory."""
    if ".git" not in rel.parts[:-1]:
        return False
    name = rel.name
    return name.endswith(GIT_TRANSIENT) or name.startswith(GIT_TMP_PREFIXES)


def is_excluded(rel: Path, roots: set[str]) -> bool:
    """True when any component is an excluded name.

    Component matching rather than a prefix test, so 'a/build_msvc/b' is
    excluded and 'build_msvc_old' is not.
    """
    if is_git_transient(rel):
        return True
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
    ap.add_argument(
        "--src",
        type=Path,
        default=Path(r"Z:\Downloads\Mergen"),
        help="canonical tree to read from (default: %(default)s)",
    )
    ap.add_argument("--dst", type=Path, required=True, help="tree to write to")
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
    ap.add_argument(
        "--include",
        nargs="*",
        metavar="PATH",
        help="only these entries, relative to --src (everything else ignored; "
        "never affects what --prune deletes)",
    )
    ap.add_argument(
        "--exclude",
        nargs="*",
        metavar="NAME",
        default=list(DEFAULT_EXCLUDES),
        help="directory names to skip; replaces the default list (see README)",
    )
    ap.add_argument(
        "--size-only",
        action="store_true",
        help="compare file sizes only (fastest, misses every same-length edit)",
    )
    ap.add_argument(
        "--fast",
        action="store_true",
        help="trust matching mtimes instead of reading both files (much faster, "
        "misses an edit whose timestamp was preserved)",
    )
    ap.add_argument(
        "--jobs",
        type=int,
        default=8,
        metavar="N",
        help="compare this many files concurrently (default: %(default)s)",
    )
    ap.add_argument(
        "--prune",
        action="store_true",
        help="delete files that the last sync recorded and the source no longer "
        "has; never touches anything absent from that record",
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    return ap.parse_args(argv)


def classify(
    a: Path, b: Path, use_hash: bool, use_mtime: bool = True
) -> tuple[str, str | None, str | None]:
    """Compare two files, returning (verdict, src_hash, dst_hash).

    Three tiers, cheapest first, because on a shared drive the cost is
    dominated by per-open latency rather than bytes transferred -- roughly 3700
    files times two sides is over ten thousand opens, and hashing all of them is
    what makes a no-op run feel slow.

      1. Size differs -> "differ". A stat pair, no file body read. This settles
         almost every genuinely edited file.
      2. Size and mtime match -> "same", unverified. No open at all, which is
         what removes the bulk of the work on an unchanged tree.
      3. Size matches but mtime differs -> hash both. An edit that preserves the
         length normally still moves mtime, so this catches the 0x1234 ->
         0x5678 case; it is only skipped when a tool rewrote the content while
         restoring the timestamp, which --hash is there to catch.

    The hashes are returned rather than computed internally so the caller reuses
    them for the baseline instead of reading each file a second time.
    """
    sa, sb = a.stat(), b.stat()
    if sa.st_size != sb.st_size:
        return "differ", None, None
    if not use_hash:
        return "same", None, None
    if use_mtime and sa.st_mtime_ns == sb.st_mtime_ns:
        return "same", None, None
    ha, hb = hash_file(a), hash_file(b)
    return ("same" if ha == hb else "differ"), ha, hb


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

    # Content hashing is the default. Size alone cannot tell an edit that keeps
    # the length -- 0x1234 -> 0x5678 is the common case in this repo -- so
    # size-only is an opt-in speed trade, not the safe default.
    use_hash = not args.size_only
    # Content is compared by default. The mtime shortcut -- --fast -- is off,
    # because a preserved timestamp on an edited file would read as unchanged;
    # --size-only drops content reads entirely, which is a stronger trade still.
    # Concurrency is on by default because the comparison is per-open latency
    # bound, not CPU bound: threads keep the share busy instead of waiting on
    # one file at a time.
    use_mtime = args.fast

    t_start = time.perf_counter()

    excludes = set(args.exclude)
    stats = Stats()
    state = State([dst / ".sync_state.json", src / ".sync_state.json"])

    t_walk = time.perf_counter()
    files = walk(src, excludes)
    if args.include:
        wanted = {Path(p) for p in args.include}
        files = [r for r in files if any(r == w or w in r.parents for w in wanted)]

    walk_secs = time.perf_counter() - t_walk

    if not args.quiet:
        print(f"INFO: {label}  {src} -> {dst}  ({len(files)} files)")

    dst.mkdir(parents=True, exist_ok=True)

    # Comparison is the slow half and it is per-file independent, so it is the
    # only part worth fanning out. The cost being optimised is per-open latency,
    # not CPU, which is exactly the shape threads help with: the share is idle
    # waiting on I/O while each thread could be queuing the next open.
    #
    # Results are consumed in the original order regardless of completion order,
    # so --jobs changes speed and nothing else -- no ordering-dependent
    # decisions, no different conflict report.
    def probe(rel: Path):
        s, d = src / rel, dst / rel
        t0 = time.perf_counter()
        if not d.exists():
            out = (rel, "new", None, None, None)
        else:
            try:
                verdict, sh, dh = classify(s, d, use_hash, use_mtime)
                out = (rel, verdict, sh, dh, None)
            except OSError as exc:
                out = (rel, "error", None, None, exc)
        stats.note(time.perf_counter() - t0, rel.as_posix())
        return out

    t_cmp = time.perf_counter()
    if args.jobs > 1 and len(files) > 1:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            probes = list(pool.map(probe, files))
    else:
        probes = [probe(rel) for rel in files]
    compare_secs = time.perf_counter() - t_cmp

    t_copy = time.perf_counter()
    for rel, verdict, src_hash, dst_hash, err in probes:
        s, d = src / rel, dst / rel
        key = rel.as_posix()

        if verdict == "error":
            stats.errors.append((key, str(err)))
            continue

        if verdict == "new":
            plan = "new"
        elif verdict == "same":
            stats.skipped += 1
            # Only record a baseline that was actually verified by content.
            # Under the mtime fast path no hash was computed, so the existing
            # entry is kept rather than replaced with an unverified value.
            if src_hash:
                state.data[key] = src_hash
            continue
        else:
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
                if src_hash is None:
                    src_hash = _hash_of(s, use_hash)
                if dst_hash is None:
                    dst_hash = _hash_of(d, use_hash)
                src_moved = src_hash != base
                dst_moved = dst_hash != base
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
                state.data[key] = _hash_of(s, use_hash)
            except OSError as exc:
                stats.errors.append((key, str(exc)))
                continue

        stats.copied.append((key, direction))
        stats.copied_bytes += s.stat().st_size

    copy_secs = time.perf_counter() - t_copy

    # --- prune -------------------------------------------------------------
    # Deletion is the one irreversible act here, so it is gated on the baseline
    # rather than on "the source does not have it".
    #
    # The baseline is the set of paths the two trees provably agreed on. A path
    # in it that the source no longer has was deleted at the source: a file the
    # user dropped into the destination by hand was never recorded, and a path
    # merely outside --include is still present in the source and so never
    # qualifies. Neither case can be mistaken for a deletion.
    if args.prune:
        # Pruning must judge against the *whole* source tree, not the --include
        # subset. Narrowing the list makes every baseline entry outside it look
        # absent, and pruning would then delete files that are still sitting
        # right there in the source. --include is a selection of what to copy,
        # never a statement that the rest was deleted.
        prune_scan = walk(src, excludes)
        src_files_now = {r.as_posix() for r in prune_scan}
        for key in sorted(state.baselines()):
            if key in src_files_now:
                continue
            victim = dst / key
            if not victim.is_file():
                continue
            if not args.dry_run:
                try:
                    victim.unlink()
                except OSError as exc:
                    stats.errors.append((key, f"prune: {exc}"))
                    continue
                state.data.pop(key, None)
            stats.pruned.append(key)
            if not args.quiet:
                print(f"  prune {key}")

        # Directories are not recorded in the baseline, so they are removed only
        # when the prune emptied them. rmdir-on-non-empty is the safety net.
        if stats.pruned and not args.dry_run:
            for dirpath, dirnames, filenames in os.walk(dst, topdown=False):
                rel = str(Path(dirpath).relative_to(dst))
                if rel == "." or is_excluded(Path(rel), excludes):
                    continue
                try:
                    os.rmdir(dirpath)
                    stats.pruned.append(rel + "/")
                except OSError:
                    pass  # not empty: something in it is not ours to remove

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

    total_secs = time.perf_counter() - t_start

    print()
    print(
        f"{'[dry-run] ' if args.dry_run else ''}"
        f"copied {len(stats.copied)}  skipped {stats.skipped}  "
        f"pruned {len(stats.pruned)}  conflicts {len(stats.conflicts)}  "
        f"errors {len(stats.errors)}  ({human(stats.copied_bytes)})"
    )

    # Timings answer "why was that slow", which on a share with per-open
    # latency is almost always a question about where the time went rather than
    # how long it took. Walking, comparing and copying have very different
    # profiles: --fast makes compare nearly free, while copying on Z: is where
    # the bytes actually cost.
    print(
        f"time {total_secs:.2f}s   scan {walk_secs:.2f}s   "
        f"compare {compare_secs:.2f}s   copy {copy_secs:.2f}s   "
        f"({len(files)} files, jobs={args.jobs})"
    )
    if stats.slowest:
        stats.slowest.sort(reverse=True)
        top = ", ".join(f"{sec * 1000:.0f}ms {name}" for sec, name in stats.slowest[:3])
        print(f"     slowest compare: {top}")

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
    """Identity recorded in the baseline file.

    Always the real content hash, independent of the comparison mode. Recording
    size here instead would be a quiet correctness hole: a same-length edit
    would compare equal to its own baseline forever, so the conflict machinery
    would keep believing the file never moved. The hash is computed once per
    file per run and reused by the baseline, the conflict test and the state
    write, so --size-only buys nothing by weakening this.
    """
    return hash_file(path)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))