#!/usr/bin/env python3
"""One-shot LF vs DR insn/write trace analysis (no manual hop-by-hop).

Usage:
  python scripts/dev/trace_lf_dr_once.py
  python scripts/dev/trace_lf_dr_once.py --lf build_msvc_dbg/mix_rcx_insn_wr.csv \\
      --dr D:/sogen/dr/vmptest/mix_dr_insn.csv --wr build_msvc_dbg/mix_rcx_wr.csv
  python scripts/dev/trace_lf_dr_once.py --stop-rva 0x3fccd7 --delta 0x120
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

REGS = "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split()
LF_BASE = 0x140000000
STACK_SLOTS = (
    0x14FC58,
    0x14FC60,
    0x14FC68,
    0x14FCD8,
    0x14FE58,
    0x14FE60,
    0x14FE64,
    0x14FE68,
)


def parse_val(s: str | None) -> int | None:
    if not s or s == "-":
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def infer_dr_base(dr_path: Path, lf_path: Path, sample: int = 5000) -> int:
    with open(dr_path, encoding="utf-8", errors="replace") as fd, open(
        lf_path, encoding="utf-8", errors="replace"
    ) as fl:

        def nxt(f):
            for line in f:
                if line.startswith("I,"):
                    p = line.strip().split(",")
                    while len(p) < 19:
                        p.append("-")
                    return p
            return None

        d, l = nxt(fd), nxt(fl)
        n = 0
        while d and l and n < sample:
            sd, sl = int(d[1], 0), int(l[1], 0)
            if sd != sl:
                if sd < sl:
                    d = nxt(fd)
                else:
                    l = nxt(fl)
                continue
            if d[2] != l[2]:
                d, l = nxt(fd), nxt(fl)
                continue
            ds, ls = parse_val(d[7]), parse_val(l[7])
            if ds and ls and 0x140200000 <= ls <= 0x140300000:
                return ds - (ls - LF_BASE)
            d, l = nxt(fd), nxt(fl)
            n += 1
    return 0x7FF7A3360000


def mod_rva(addr: int | None, dr_base: int) -> int | None:
    if addr is None:
        return None
    if LF_BASE <= addr < LF_BASE + 0x08000000:
        return addr - LF_BASE
    if dr_base <= addr < dr_base + 0x08000000:
        return addr - dr_base
    if (addr & 0xFF000000) == 0x40000000:
        return addr & 0xFFFFFF
    return None


def is_module_ptr(addr: int | None, dr_base: int) -> bool:
    r = mod_rva(addr, dr_base)
    if r is None:
        return False
    return 0x00200000 <= r <= 0x00500000


@dataclass
class RegDiff:
    seq: int
    rva: int
    reg: str
    dr: int
    lf: int
    dr_rva: int
    lf_rva: int

    @property
    def rva_delta(self) -> int:
        return self.lf_rva - self.dr_rva


@dataclass
class Store:
    seq: int
    insn: int
    slot: int
    size: int
    value: int | None
    sym: bool


def iter_insn_rows(path: Path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.startswith("I,"):
                continue
            p = line.strip().split(",")
            while len(p) < 3 + len(REGS):
                p.append("-")
            yield int(p[1], 0), int(p[2], 0), [parse_val(p[3 + i]) for i in range(len(REGS))]


def load_write_stream(path: Path | None) -> list[Store]:
    if not path or not path.exists() or path.stat().st_size < 64:
        return []
    out: list[Store] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.startswith("W,"):
                continue
            p = line.strip().split(",")
            if len(p) < 6:
                continue
            try:
                seq = int(p[1], 0)
                insn = int(p[2], 0)
                slot = int(p[3], 0)
                size = int(p[4], 0)
            except ValueError:
                continue
            sym = p[5] in ("-", "")
            val = None if sym else parse_val(p[5])
            out.append(Store(seq, insn, slot, size, val, sym))
    return out


def scan_insn_pairs(
    lf_path: Path,
    dr_path: Path,
    dr_base: int,
    max_seq: int | None,
    delta: int,
    persist: int,
):
    dr_it = iter_insn_rows(dr_path)
    lf_it = iter_insn_rows(lf_path)
    d = next(dr_it, None)
    l = next(lf_it, None)

    aligned = 0
    first_rva_split: tuple[int, int, int] | None = None
    stack_cx_delta: int | None = None
    stack_cx_delta_seq: int | None = None

    module_diffs: list[RegDiff] = []
    module_diff_by_key: dict[tuple[int, str], RegDiff] = {}

    # consecutive module 0x120 on same (rva, reg)
    streak: dict[tuple[int, str], int] = defaultdict(int)
    lasting_module: list[tuple[int, RegDiff, int]] = []

    adc_hits: list[tuple[int, int, int, int, int]] = []  # seq, rdx_dr, rdx_lf, cx_dr, cx_lf

    while d and l:
        sd, sr, dregs = d
        sl, lr, lregs = l
        if max_seq is not None and sd > max_seq:
            break

        if sd != sl:
            if sd < sl:
                d = next(dr_it, None)
            else:
                l = next(lf_it, None)
            continue

        if sr != lr:
            if first_rva_split is None:
                first_rva_split = (sd, sr, lr)
            break

        aligned += 1

        cx_d = (dregs[2] or 0) & 0xFFFF
        cx_l = (lregs[2] or 0) & 0xFFFF
        if stack_cx_delta is None and cx_d != cx_l:
            stack_cx_delta = (cx_l - cx_d) & 0xFFFF
            stack_cx_delta_seq = sd

        # adc dx,cx site snapshot: rva 0x414464, after insn rdx differs
        if lr == 0x414467:
            adc_hits.append((sd, dregs[3] or 0, lregs[3] or 0, cx_d, cx_l))

        for i, name in enumerate(REGS):
            dv, lv = dregs[i], lregs[i]
            if not (is_module_ptr(dv, dr_base) and is_module_ptr(lv, dr_base)):
                streak[(lr, name)] = 0
                continue
            dr_r, lf_r = mod_rva(dv, dr_base), mod_rva(lv, dr_base)
            if dr_r is None or lf_r is None:
                streak[(lr, name)] = 0
                continue
            diff = lf_r - dr_r
            if diff != delta and diff != -delta:
                streak[(lr, name)] = 0
                continue

            rd = RegDiff(sd, lr, name, dv, lv, dr_r, lf_r)
            module_diffs.append(rd)
            key = (lr, name)
            if key not in module_diff_by_key:
                module_diff_by_key[key] = rd
            streak[key] += 1
            if streak[key] == persist:
                lasting_module.append((sd, rd, persist))

        d = next(dr_it, None)
        l = next(lf_it, None)

    return {
        "aligned": aligned,
        "first_rva_split": first_rva_split,
        "stack_cx_delta": stack_cx_delta,
        "stack_cx_delta_seq": stack_cx_delta_seq,
        "module_diffs": module_diffs,
        "module_diff_by_key": module_diff_by_key,
        "lasting_module": lasting_module,
        "adc_hits": adc_hits,
    }


def analyze_writes(
    stores: list[Store],
    dr_base: int,
    delta: int,
    lo_seq: int,
    hi_seq: int,
):
    last_by_slot: dict[int, Store] = {}
    module_slot_stores: list[Store] = []
    delta_stores: list[tuple[Store, int, int]] = []

    for st in stores:
        if st.seq > hi_seq:
            break
        last_by_slot[st.slot] = st
        if lo_seq <= st.seq <= hi_seq and st.slot in STACK_SLOTS:
            if not st.sym and is_module_ptr(st.value, dr_base):
                module_slot_stores.append(st)
                # compare to "canonical" DR-ish value: strip delta from lf side
                lf_r = mod_rva(st.value, dr_base)
                if lf_r is not None:
                    dr_equiv = lf_r - delta
                    delta_stores.append((st, lf_r, dr_equiv))

    # stores where value low16 fingerprint or exact module delta pattern
    poison_fp = []
    for st in stores:
        if st.sym or st.value is None:
            continue
        r = mod_rva(st.value, dr_base)
        if r is None:
            continue
        if st.slot in STACK_SLOTS and lo_seq <= st.seq <= hi_seq:
            poison_fp.append(st)

    return {
        "last_by_slot": last_by_slot,
        "module_slot_stores": module_slot_stores,
        "tracked_slot_writes": poison_fp,
    }


def format_ptr(v: int | None) -> str:
    if v is None:
        return "-"
    return f"0x{v:x}"


def main() -> int:
    ap = argparse.ArgumentParser(description="One-shot LF/DR trace diverge analysis")
    ap.add_argument(
        "--lf",
        type=Path,
        default=Path("build_msvc_dbg/mix_rcx_insn_wr.csv"),
        help="LF insn stream (MERGEN_INSN_STREAM_FILE)",
    )
    ap.add_argument(
        "--dr",
        type=Path,
        default=None,
        help="DR insn stream (default: first mix_dr_insn.csv under D:/sogen/dr)",
    )
    ap.add_argument(
        "--wr",
        type=Path,
        default=Path("build_msvc_dbg/mix_rcx_wr.csv"),
        help="LF write stream (optional)",
    )
    ap.add_argument("--dr-base", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--delta", type=lambda x: int(x, 0), default=0x120)
    ap.add_argument(
        "--persist",
        type=int,
        default=3,
        help="Consecutive insn snapshots with same module delta = lasting",
    )
    ap.add_argument("--max-seq", type=int, default=None)
    ap.add_argument("--stop-rva", type=lambda x: int(x, 0), default=0x3FCCD7)
    ap.add_argument("--window", type=int, default=5000, help="Seq window before stop for writes")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    repo = Path(__file__).resolve().parents[2]
    lf = args.lf if args.lf.is_absolute() else repo / args.lf
    wr = args.wr if args.wr.is_absolute() else repo / args.wr
    if args.dr:
        dr = args.dr if args.dr.is_absolute() else repo / args.dr
    else:
        dr = next(Path(r"D:/sogen/dr").rglob("mix_dr_insn.csv"))

    if not lf.exists():
        print(f"LF missing: {lf}", file=sys.stderr)
        return 2
    if not dr.exists():
        print(f"DR missing: {dr}", file=sys.stderr)
        return 2

    dr_base = args.dr_base if args.dr_base is not None else infer_dr_base(dr, lf)
    scan = scan_insn_pairs(lf, dr, dr_base, args.max_seq, args.delta, args.persist)
    stores = load_write_stream(wr)

    # Find stop seq from LF stream (first rva split or last aligned before stop-rva visits)
    stop_seq = None
    for seq, rva, _ in iter_insn_rows(lf):
        if rva == args.stop_rva:
            stop_seq = seq
    if stop_seq is None and scan["first_rva_split"]:
        stop_seq = scan["first_rva_split"][0]

    lo = max(0, (stop_seq or 400000) - args.window)
    hi = stop_seq or 999999999
    wr_info = analyze_writes(stores, dr_base, args.delta, lo, hi)

    lines: list[str] = []
    def emit(s: str = "") -> None:
        lines.append(s)
        print(s)

    emit("=== trace_lf_dr_once ===")
    emit(f"LF: {lf}")
    emit(f"DR: {dr}")
    emit(f"WR: {wr} ({'ok' if stores else 'missing'})")
    emit(f"DR_BASE: {format_ptr(dr_base)}")
    emit(f"aligned_insn_rows: {scan['aligned']}")
    emit()

    if scan["first_rva_split"]:
        s, dr_r, lf_r = scan["first_rva_split"]
        emit(f"first_rva_diverge: seq={s} DR={format_ptr(dr_r)} LF={format_ptr(lf_r)}")
    else:
        emit("first_rva_diverge: (none within scan)")
    emit()

    emit("=== stack pointer low16 (rcx) ===")
    emit(
        f"cx delta: {format_ptr(scan['stack_cx_delta'])} "
        f"@ seq {scan['stack_cx_delta_seq']}"
    )
    emit()

    emit(f"=== module pointer delta == {format_ptr(args.delta)} (reg snapshots) ===")
    if scan["module_diffs"]:
        first = scan["module_diffs"][0]
        emit(
            f"first: seq={first.seq} rva={format_ptr(first.rva)} reg={first.reg} "
            f"DR_rva={format_ptr(first.dr_rva)} LF_rva={format_ptr(first.lf_rva)}"
        )
    else:
        emit("first: (none)")
    emit()
    emit(f"lasting (>={args.persist} consecutive snapshots at same rva/reg):")
    shown = set()
    for seq, rd, n in scan["lasting_module"][:20]:
        key = (rd.rva, rd.reg)
        if key in shown:
            continue
        shown.add(key)
        emit(
            f"  seq={seq} rva={format_ptr(rd.rva)} reg={rd.reg} "
            f"DR_rva={format_ptr(rd.dr_rva)} LF_rva={format_ptr(rd.lf_rva)} streak={n}"
        )
    emit()

    emit("=== adc dx,cx site (rva 0x414467 snapshot) ===")
    for hit in scan["adc_hits"][:5]:
        seq, drx, lfx, cx_d, cx_l = hit
        emit(
            f"  seq={seq} rdx DR={format_ptr(drx)} LF={format_ptr(lfx)} "
            f"cx DR={format_ptr(cx_d)} LF={format_ptr(cx_l)} "
            f"low16_delta={(lfx-drx)&0xffff:x}"
        )
    if scan["adc_hits"]:
        emit("  note: mov [r10],rbp at 0x414467 writes rbp; rdx poison cleared by movzx @0x41446d")
    emit()

    emit(f"=== write stream (slots {', '.join(hex(s) for s in STACK_SLOTS)}, seq {lo}-{hi}) ===")
    by_slot: dict[int, list[Store]] = defaultdict(list)
    for st in wr_info["tracked_slot_writes"]:
        by_slot[st.slot].append(st)
    for slot in STACK_SLOTS:
        arr = by_slot.get(slot, [])
        if not arr:
            continue
        emit(f"  slot {format_ptr(slot)}: {len(arr)} module stores")
        for st in arr[-5:]:
            emit(
                f"    wr_seq={st.seq} insn={format_ptr(st.insn)} "
                f"val={format_ptr(st.value)} rva={format_ptr(mod_rva(st.value, dr_base))}"
            )
    emit()

    emit("=== chain checklist (405644 class) ===")
    emit("  1. stack cx delta -> adc dx,cx poisons rdx briefly (may not escape to memory)")
    emit("  2. lasting module delta on rbp/rax/rcx at later handler RVAs")
    emit("  3. mov [rsp+r8] / mov [r9] stores wrong module ptr into stack slot")
    emit("  4. NOR @ 0x3c3184 uses [r9] -> wrong trip count -> jne @ stop-rva")
    emit()
    emit("Run with --wr and full LF to fill section 3 automatically; grep slot 0x14fe60 / 0x14fcd8 above.")

    if args.out:
        args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"\nWrote {args.out}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
