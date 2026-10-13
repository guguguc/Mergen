#!/usr/bin/env python3
"""Auto-chase LF vs DR insn diverge (no assumed 0x120 / slot theory).

Pipeline:
  1. Find first RVA diverge (control-flow stop).
  2. Detect constant XOR bias on hot RVAs for a focus reg (default rcx).
  3. Walk back: each pre-exec reg change => previous insn wrote it; disasm.
  4. Skip ASLR-only diffs (same low20 / same module RVA).
  5. If write-stream present, show last stores to LF stack slots near loads.

Usage:
  python scripts/dev/chase_mix_diverge.py
  python scripts/dev/chase_mix_diverge.py \\
      --lf build_msvc_dbg/mix_noreg_insn.csv \\
      --dr D:/sogen/dr/vmptest/mix_dr_insn.csv \\
      --wr build_msvc_dbg/mix_noreg_wr.csv \\
      --pe D:/sogen/dr/vmptest/test_fixed4.exe \\
      --stop-seq 301739 --regs rbp,r10,rcx --steps 12

When LF stops on length (same RVA prefix as DR), pass --stop-seq with the last LF
insn seq. The tool compares reg values at that seq (not only first_rva_diverge)
and indexes the write stream for pseudo-stack slot poison (concrete -> '-').
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

REGS = "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split()
LF_BASE = 0x140000000
STACKP = 0x14FEA0
DEFAULT_SLOTS = (0x14FE68, 0x14FE70, 0x14FD08, 0x14FDD8)

try:
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    _MD = Cs(CS_ARCH_X86, CS_MODE_64)
except Exception:  # pragma: no cover
    _MD = None


def parse_val(s: str | None) -> int | None:
    if not s or s == "-":
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def hx(v: int | None) -> str:
    if v is None:
        return "-"
    return f"0x{v:x}"


def rva24(v: int) -> int:
    return v & 0xFFFFFF


def norm_rva(va: int) -> int:
    if va >= LF_BASE:
        return va - LF_BASE
    if (va & 0xFF000000) == 0x40000000:
        return va & 0xFFFFFF
    return rva24(va)


def looks_stack(v: int, rsp: int | None) -> bool:
    if rsp is None:
        # LF pseudo-stack window around STACKP
        return 0x14F000 <= (v & 0xFFFFFFFF) <= 0x150000 or (v >> 32) >= 0x1000 and (v & 0xFFFFF000) != 0
    return abs(v - rsp) < 0x2000


def same_aslr(a: int, b: int, dr_rsp: int | None = None, lf_rsp: int | None = None) -> bool:
    """True if values look like the same object under different image/stack bases."""
    if a == b:
        return True
    if (a & 0xFFFFF) == (b & 0xFFFFF) and (a >> 40) != (b >> 40):
        return True
    # stack pointers: same offset from respective rsp
    if dr_rsp is not None and lf_rsp is not None:
        if looks_stack(a, dr_rsp) and looks_stack(b, lf_rsp):
            if (a - dr_rsp) == (b - lf_rsp):
                return True
    # LF STACKP-relative vs DR arbitrary stack with same displacement from a
    # common scratch base (loose): both in stack band and low12 match
    if looks_stack(a, dr_rsp) and looks_stack(b, lf_rsp):
        if (a & 0xFFF) == (b & 0xFFF):
            return True
    # module RVA equality under different bases
    ra, rb = a & 0xFFFFFF, b & 0xFFFFFF
    if ra == rb and abs(a - b) > 0x1000000:
        if (a >> 28) >= 0x7 or (a >> 28) == 0x1:
            if (b >> 28) >= 0x7 or (b >> 28) == 0x1:
                return True
    return False


def classify_diff(
    dr: int | None,
    lf: int | None,
    dr_rsp: int | None = None,
    lf_rsp: int | None = None,
) -> str:
    if dr is None and lf is None:
        return "both-sym"
    if dr is None:
        return "lf-sym"
    if lf is None:
        return "dr-sym"
    if dr == lf:
        return "eq"
    if same_aslr(dr, lf, dr_rsp, lf_rsp):
        return "aslr"
    return "real"


@dataclass
class InsnRow:
    seq: int
    rva: int
    regs: list[int | None]  # parallel to REGS


@dataclass
class Store:
    memseq: int
    insn_va: int
    slot: int
    size: int
    value: int | None


def load_insn(path: Path) -> list[InsnRow]:
    rows: list[InsnRow] = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.startswith("I,"):
                continue
            p = line.rstrip("\n").split(",")
            while len(p) < 3 + len(REGS):
                p.append("-")
            rows.append(
                InsnRow(
                    seq=int(p[1], 0),
                    rva=int(p[2], 0) & 0xFFFFFFFF,
                    regs=[parse_val(p[3 + i]) for i in range(len(REGS))],
                )
            )
    return rows


def load_wr(path: Path | None) -> list[Store]:
    if not path or not path.exists():
        return []
    out: list[Store] = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.startswith("W,"):
                continue
            p = line.rstrip("\n").split(",")
            if len(p) < 6:
                continue
            try:
                out.append(
                    Store(
                        memseq=int(p[1], 0),
                        insn_va=int(p[2], 0),
                        slot=int(p[3], 0),
                        size=int(p[4], 0),
                        value=None if p[5] in ("-", "") else parse_val(p[5]),
                    )
                )
            except ValueError:
                continue
    return out


class PeDisasm:
    def __init__(self, pe_path: Path | None):
        self.ok = False
        self.data = b""
        self.secs: list[tuple[int, int, int, int]] = []
        if not pe_path or not pe_path.exists() or _MD is None:
            return
        self.data = pe_path.read_bytes()
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        nsec = struct.unpack_from("<H", self.data, e_lfanew + 6)[0]
        optsz = struct.unpack_from("<H", self.data, e_lfanew + 20)[0]
        sec = e_lfanew + 24 + optsz
        for i in range(nsec):
            o = sec + i * 40
            va, vsz, raw, rsz = struct.unpack_from("<IIII", self.data, o + 8)
            self.secs.append((va, vsz, raw, rsz))
        self.ok = True

    def rva2off(self, rva: int) -> int | None:
        for va, vsz, raw, rsz in self.secs:
            if va <= rva < va + max(vsz, rsz):
                return raw + (rva - va)
        return None

    def disasm(self, rva: int, n: int = 8) -> list[str]:
        if not self.ok:
            return []
        off = self.rva2off(rva)
        if off is None:
            return []
        out: list[str] = []
        for insn in _MD.disasm(self.data[off : off + 48], LF_BASE + rva):
            out.append(f"{insn.mnemonic} {insn.op_str}")
            if len(out) >= n:
                break
        return out


def find_rva_diverge(dr: list[InsnRow], lf: list[InsnRow]) -> int | None:
    n = min(len(dr), len(lf))
    for i in range(n):
        if rva24(dr[i].rva) != rva24(lf[i].rva):
            return i
    return None


def find_index_by_seq(rows: list[InsnRow], seq: int) -> int | None:
    for i, row in enumerate(rows):
        if row.seq == seq:
            return i
    return None


def build_seq_by_rva24(rows: list[InsnRow]) -> dict[int, list[int]]:
    out: dict[int, list[int]] = defaultdict(list)
    for row in rows:
        out[rva24(row.rva)].append(row.seq)
    return out


def reg_diffs_at_index(
    dr: list[InsnRow],
    lf: list[InsnRow],
    idx: int,
    regs: list[str],
) -> list[tuple[str, str, int | None, int | None]]:
    """Return (kind, reg, dr_val, lf_val) for each reg at aligned index idx."""
    rsi = REGS.index("rsp")
    out: list[tuple[str, str, int | None, int | None]] = []
    for reg in regs:
        ri = REGS.index(reg)
        dv, lv = dr[idx].regs[ri], lf[idx].regs[ri]
        kind = classify_diff(dv, lv, dr[idx].regs[rsi], lf[idx].regs[rsi])
        if kind == "eq":
            continue
        out.append((kind, reg, dv, lv))
    return out


def slot_poison_report(
    wr: list[Store],
    seq_by_rva24: dict[int, list[int]],
    before_seq: int,
    slots: list[int],
    tail: int = 6,
) -> list[str]:
    """For each slot: last concrete write and last write before before_seq."""
    lines: list[str] = []
    for slot in slots:
        hits = [st for st in wr if st.slot == slot]
        if not hits:
            lines.append(f"  {hx(slot)} (STACKP{slot - STACKP:+#x}): no wr rows")
            continue

        def insn_for(st: Store) -> int | None:
            cands = [s for s in seq_by_rva24.get(rva24(st.insn_va), []) if s <= before_seq]
            return max(cands) if cands else None

        before = [st for st in hits if insn_for(st) is not None]
        if not before:
            lines.append(f"  {hx(slot)}: {len(hits)} wr rows (none mapped before seq {before_seq})")
            continue

        last_any = before[-1]
        last_conc = next((st for st in reversed(before) if st.value is not None), None)
        sym_after_conc: Store | None = None
        if last_conc is not None:
            for st in before:
                if st.memseq > last_conc.memseq and st.value is None:
                    sym_after_conc = st
            if sym_after_conc is None:
                for st in before:
                    if st.memseq >= last_conc.memseq and st.value is None:
                        sym_after_conc = st
                        break

        lines.append(
            f"  {hx(slot)} (STACKP{slot - STACKP:+#x}): {len(before)} wr before stop "
            f"({sum(1 for st in before if st.value is None)} sym)"
        )
        if last_conc:
            lines.append(
                f"    last concrete: memseq={last_conc.memseq} ~seq={insn_for(last_conc)} "
                f"wr_rva={hx(last_conc.insn_va)} val={hx(last_conc.value)}"
            )
        if sym_after_conc and (last_conc is None or sym_after_conc.memseq >= last_conc.memseq):
            lines.append(
                f"    first sym after: memseq={sym_after_conc.memseq} ~seq={insn_for(sym_after_conc)} "
                f"wr_rva={hx(sym_after_conc.insn_va)} val=-"
            )
        lines.append(f"    last write: memseq={last_any.memseq} ~seq={insn_for(last_any)} "
                     f"val={hx(last_any.value)}")
        lines.append("    recent tail:")
        for st in before[-tail:]:
            lines.append(
                f"      memseq={st.memseq} ~seq={insn_for(st)} wr_rva={hx(st.insn_va)} "
                f"val={hx(st.value)}"
            )
    return lines


def scan_reg_flip_back(
    lf: list[InsnRow],
    before_idx: int,
    reg: str,
    limit: int = 5000,
) -> tuple[int, int | None, int | None] | None:
    """Last concrete -> symbolic transition for reg walking back from before_idx."""
    ri = REGS.index(reg)
    start = max(0, before_idx - limit)
    prev: int | None = lf[before_idx].regs[ri]
    for i in range(before_idx, start, -1):
        cur = lf[i].regs[ri]
        if prev is not None and cur is None:
            return i, prev, cur
        prev = cur
    return None


def bias_report(
    dr: list[InsnRow], lf: list[InsnRow], diverge: int, reg: str, hot_limit: int = 12
) -> list[tuple[int, int, int, list[tuple[int, int | None, int | None]]]]:
    """For each hot RVA before diverge, if focus-reg XOR is constant, report it."""
    ri = REGS.index(reg)
    hits: dict[int, list[tuple[int, int | None, int | None]]] = defaultdict(list)
    for i in range(diverge):
        if rva24(dr[i].rva) != rva24(lf[i].rva):
            break
        rva = rva24(lf[i].rva)
        hits[rva].append((lf[i].seq, dr[i].regs[ri], lf[i].regs[ri]))

    # Prefer RVAs near the stop (recent), not globally hottest
    recent = {rva24(lf[i].rva) for i in range(max(0, diverge - 5000), diverge)}
    ranked = sorted(
        hits.items(),
        key=lambda kv: (0 if kv[0] in recent else 1, -len(kv[1])),
    )[: hot_limit * 3]

    out = []
    for rva, arr in ranked:
        xors = []
        # sample rsp from a mid hit for ASLR classify
        for seq, dv, lv in arr:
            # find row for rsp
            # arr only has seq; approximate without rsp => stack filter via STACKP band
            if dv is not None and lv is not None and dv != lv:
                if same_aslr(dv, lv, None, None):
                    continue
                # drop pure stack-vs-STACKP when low12 matches
                if looks_stack(dv, None) and looks_stack(lv, None) and (dv & 0xFFF) == (lv & 0xFFF):
                    continue
                xors.append(dv ^ lv)
        if not xors:
            continue
        c = Counter(xors)
        mode, cnt = c.most_common(1)[0]
        if cnt >= 2 and cnt >= len(xors) * 0.6 and mode < (1 << 24):
            # keep small/meaningful biases (counters, flags, offsets); drop huge ptr xors
            out.append((rva, mode, cnt, arr[-5:]))
        if len(out) >= hot_limit:
            break
    return out


def xor_pair(a: int | None, b: int | None) -> int | None:
    if a is None or b is None:
        return None
    return a ^ b


def first_real_writer(
    dr: list[InsnRow],
    lf: list[InsnRow],
    diverge: int,
    reg: str,
    require_xor_change: bool = True,
) -> tuple[int, int, int | None, int | None] | None:
    """Walk back from diverge: find last insn that wrote `reg` to a real-diff pair.

    If require_xor_change, skip writers that keep DR^LF identical (e.g. parallel dec).
    """
    ri = REGS.index(reg)
    rsi = REGS.index("rsp")
    for i in range(diverge - 1, 0, -1):
        pd, pl = dr[i - 1].regs[ri], lf[i - 1].regs[ri]
        cd, cl = dr[i].regs[ri], lf[i].regs[ri]
        if (cd, cl) == (pd, pl):
            continue
        dr_rsp, lf_rsp = dr[i].regs[rsi], lf[i].regs[rsi]
        if classify_diff(cd, cl, dr_rsp, lf_rsp) != "real":
            continue
        if require_xor_change:
            xo = xor_pair(cd, cl)
            xp = xor_pair(pd, pl)
            if xo is not None and xp is not None and xo == xp:
                # trivial parallel update (dec/inc both sides) — keep searching
                continue
        return i - 1, rva24(lf[i - 1].rva), cd, cl
    return None


def find_bias_onset(
    dr: list[InsnRow], lf: list[InsnRow], diverge: int, reg: str, bias: int
) -> int | None:
    """Earliest aligned index where DR^LF==bias and both look like small counters."""
    ri = REGS.index(reg)

    def small(v: int | None) -> bool:
        return v is not None and v < 0x10000

    first = None
    for i in range(diverge):
        if rva24(dr[i].rva) != rva24(lf[i].rva):
            break
        dv, lv = dr[i].regs[ri], lf[i].regs[ri]
        if xor_pair(dv, lv) == bias and small(dv) and small(lv):
            first = i
            break
    return first


_LOAD_RE = re.compile(
    r"mov\s+(?P<dst>\w+)\s*,\s*(?:qword|dword|word|byte)\s+ptr\s+"
    r"\[(?P<base>r9|rsp|rbp|rbx|rdi|rsi|rax|rcx|rdx|r8|r10|r11)"
    r"(?:\s*(?P<sign>[+-])\s*(?P<off>0x[0-9a-fA-F]+|\d+))?\]",
    re.I,
)
_STORE_RE = re.compile(
    r"mov\s+(?:qword|dword|word|byte)\s+ptr\s+"
    r"\[(?P<base>r9|rsp|rbp|rbx|rdi|rsi|rax|rcx|rdx|r8|r10|r11)"
    r"(?:\s*(?P<sign>[+-])\s*(?P<off>0x[0-9a-fA-F]+|\d+))?\]\s*,\s*(?P<src>\w+)",
    re.I,
)


def _mem_off(sign: str | None, off: str | None) -> int:
    if not off:
        return 0
    v = int(off, 0)
    return -v if sign == "-" else v


def parse_load_to_reg(asm: list[str], focus: str) -> tuple[str, int] | None:
    """If first matching insn loads into focus (or its subreg), return (base, disp)."""
    focus_set = {focus, focus[1:] if focus.startswith("r") else focus}  # rcx/ecx rough
    # also accept eax for rax etc.
    aliases = {
        "rax": {"rax", "eax", "ax", "al"},
        "rbx": {"rbx", "ebx", "bx", "bl"},
        "rcx": {"rcx", "ecx", "cx", "cl"},
        "rdx": {"rdx", "edx", "dx", "dl"},
        "rsi": {"rsi", "esi", "si", "sil"},
        "rdi": {"rdi", "edi", "di", "dil"},
        "rbp": {"rbp", "ebp", "bp", "bpl"},
        "rsp": {"rsp", "esp", "sp", "spl"},
        "r8": {"r8", "r8d", "r8w", "r8b"},
        "r9": {"r9", "r9d", "r9w", "r9b"},
        "r10": {"r10", "r10d", "r10w", "r10b"},
        "r11": {"r11", "r11d", "r11w", "r11b"},
    }
    want = aliases.get(focus, focus_set)
    for line in asm:
        m = _LOAD_RE.search(line)
        if not m:
            continue
        if m.group("dst").lower() not in want:
            continue
        return m.group("base").lower(), _mem_off(m.group("sign"), m.group("off"))
    return None


def parse_store_from_reg(asm: list[str]) -> tuple[str, int, str] | None:
    """First store [base+disp], src — return (base, disp, src_reg_canonical)."""
    aliases_rev = {}
    for canon, names in {
        "rax": {"rax", "eax", "ax", "al"},
        "rbx": {"rbx", "ebx", "bx", "bl"},
        "rcx": {"rcx", "ecx", "cx", "cl"},
        "rdx": {"rdx", "edx", "dx", "dl"},
        "rsi": {"rsi", "esi", "si", "sil"},
        "rdi": {"rdi", "edi", "di", "dil"},
        "rbp": {"rbp", "ebp", "bp", "bpl"},
        "r8": {"r8", "r8d", "r8w", "r8b"},
        "r9": {"r9", "r9d", "r9w", "r9b"},
        "r10": {"r10", "r10d", "r10w", "r10b"},
        "r11": {"r11", "r11d", "r11w", "r11b"},
    }.items():
        for n in names:
            aliases_rev[n] = canon
    for line in asm:
        m = _STORE_RE.search(line)
        if not m:
            continue
        src = m.group("src").lower()
        canon = aliases_rev.get(src)
        if canon is None:
            continue
        return m.group("base").lower(), _mem_off(m.group("sign"), m.group("off")), canon
    return None


def slot_from_base(row: InsnRow, base: str, disp: int) -> int | None:
    if base not in REGS:
        return None
    bv = row.regs[REGS.index(base)]
    if bv is None:
        return None
    return bv + disp


def find_prev_store_to_slot(
    dr: list[InsnRow],
    lf: list[InsnRow],
    before_idx: int,
    slot: int,
    pe: PeDisasm,
    max_scan: int = 12000,
    prefer_divergent_src: bool = True,
) -> tuple[int, int, str, bool] | None:
    """Walk LF backward for a store into `slot`.

    Returns (idx, rva, src_reg, src_is_real_diff).
    If prefer_divergent_src, skip stores whose source reg is eq/aslr on both sides
    (they cannot explain a later divergent load of this slot).
    """
    r9i = REGS.index("r9")
    rsi = REGS.index("rsp")
    fallback: tuple[int, int, str, bool] | None = None

    for i in range(before_idx - 1, max(0, before_idx - max_scan), -1):
        if rva24(dr[i].rva) != rva24(lf[i].rva):
            continue
        asm = pe.disasm(rva24(lf[i].rva), 6)
        st = parse_store_from_reg(asm)
        if st is None:
            continue
        base, disp, src = st
        got = slot_from_base(lf[i], base, disp)
        if got != slot:
            if not (base == "r9" and lf[i].regs[r9i] is not None and lf[i].regs[r9i] + disp == slot):
                continue
        sj = REGS.index(src)
        real = (
            classify_diff(
                dr[i].regs[sj],
                lf[i].regs[sj],
                dr[i].regs[rsi],
                lf[i].regs[rsi],
            )
            == "real"
        )
        hit = (i, rva24(lf[i].rva), src, real)
        if real:
            return hit
        if fallback is None:
            fallback = hit
        if not prefer_divergent_src:
            return hit
    return fallback


def walk_chain(
    dr: list[InsnRow],
    lf: list[InsnRow],
    diverge: int,
    start_reg: str,
    pe: PeDisasm,
    wr: list[Store],
    steps: int,
    stop_xor: int | None = None,
) -> list[str]:
    lines: list[str] = []
    focus = start_reg
    seen: set[tuple[int, str, int | None]] = set()  # rva, reg, slot
    wr_by_slot: dict[int, list[Store]] = defaultdict(list)
    for st in wr:
        wr_by_slot[st.slot].append(st)

    # Optional pending: jump to a known store idx instead of first_real_writer
    force_idx: int | None = None

    if stop_xor is not None:
        onset = find_bias_onset(dr, lf, diverge, focus, stop_xor)
        if onset is not None:
            lines.append(
                f"[onset] {focus} xor={hx(stop_xor)} first small-counter @ "
                f"seq={lf[onset].seq} rva={hx(lf[onset].rva)} "
                f"DR={hx(dr[onset].regs[REGS.index(focus)])} "
                f"LF={hx(lf[onset].regs[REGS.index(focus)])}"
            )
            diverge = onset + 1

    for step in range(steps):
        if force_idx is not None:
            widx = force_idx
            wrva = rva24(lf[widx].rva)
            force_idx = None
        else:
            hit = first_real_writer(dr, lf, diverge, focus, require_xor_change=True)
            if hit is None:
                hit = first_real_writer(dr, lf, diverge, focus, require_xor_change=False)
                if hit is None:
                    lines.append(f"[{step}] no more real writer for {focus}")
                    break
                lines.append(f"[{step}] (fallback: xor-preserving writer)")
            widx, wrva, _nd, _nl = hit

        after = min(widx + 1, len(lf) - 1)
        ri = REGS.index(focus)
        asm = pe.disasm(wrva, 10)
        load = parse_load_to_reg(asm, focus)
        slot = None
        if load is not None:
            base, disp = load
            slot = slot_from_base(lf[widx], base, disp)

        key = (wrva, focus, slot)
        if key in seen:
            lines.append(f"[{step}] loop on {focus} @ {hx(wrva)} slot={hx(slot)}")
            break
        seen.add(key)

        old_dr, old_lf = dr[widx].regs[ri], lf[widx].regs[ri]
        xo = xor_pair(dr[after].regs[ri], lf[after].regs[ri])
        lines.append(
            f"[{step}] writer seq={lf[widx].seq} rva={hx(wrva)} reg={focus} "
            f"BEFORE DR={hx(old_dr)} LF={hx(old_lf)}  "
            f"AFTER DR={hx(dr[after].regs[ri])} LF={hx(lf[after].regs[ri])} "
            f"xor={hx(xo)}"
        )
        if asm:
            for a in asm[:6]:
                lines.append(f"       {a}")
        else:
            lines.append("       (no disasm)")

        # --- VSP / mem-load path: follow slot write chain, do NOT switch to rax ---
        if load is not None and slot is not None:
            base, disp = load
            lines.append(
                f"       load {focus} <- [{base}+{disp}] LF_slot={hx(slot)} "
                f"(STACKP{slot - STACKP:+#x})"
            )

            # Module/bytecode load: chase the address register, not a stack store.
            if slot >= LF_BASE or (slot & 0xFFFFFF) > 0x100000 and not (
                0x14F000 <= (slot & 0xFFFFFFFF) <= 0x150000
            ):
                if base in REGS and base != focus:
                    bj = REGS.index(base)
                    lines.append(
                        f"       module/non-stack load — next_focus={base} "
                        f"DR={hx(dr[widx].regs[bj])} LF={hx(lf[widx].regs[bj])} "
                        f"xor={hx(xor_pair(dr[widx].regs[bj], lf[widx].regs[bj]))}"
                    )
                    focus = base
                    diverge = widx
                    continue

            hist = wr_by_slot.get(slot, [])
            if hist:
                lines.append(f"       wr-stream last stores to slot ({len(hist)} total):")
                for st in hist[-5:]:
                    lines.append(
                        f"         memseq={st.memseq} insn={hx(st.insn_va)} "
                        f"size={st.size} val={hx(st.value)}"
                    )

            prev = find_prev_store_to_slot(dr, lf, widx, slot, pe, prefer_divergent_src=True)
            if prev is None:
                lines.append(
                    f"       no prior store to {hx(slot)} in scan window; stop slot chase"
                )
                diverge = widx
                continue

            sidx, srva, src, src_real = prev
            tag = "divergent-src" if src_real else "eq-src-fallback"
            lines.append(
                f"       prior store ({tag}) seq={lf[sidx].seq} rva={hx(srva)} "
                f"<- {src}  "
                f"DR_{src}={hx(dr[sidx].regs[REGS.index(src)])} "
                f"LF_{src}={hx(lf[sidx].regs[REGS.index(src)])} "
                f"xor={hx(xor_pair(dr[sidx].regs[REGS.index(src)], lf[sidx].regs[REGS.index(src)]))}"
            )
            store_asm = pe.disasm(srva, 6)
            for a in store_asm[:4]:
                lines.append(f"         {a}")

            if not src_real:
                lines.append(
                    "       store src not divergent — slot poison may be overlapping/"
                    "partial write; continue scanning older stores via focus stay"
                )
                # Keep focus on the loaded reg, move window before this useless store
                diverge = sidx
                continue

            # Divergent source written into the slot: chase that register's producers.
            focus = src
            diverge = sidx
            lines.append(f"       next_focus={src} (VSP store source; stay on mem chain)")
            continue

        # --- ALU / non-load path: pick a real-diff operand that appears in asm ---
        joined = " ; ".join(asm)
        next_focus = None
        rsi = REGS.index("rsp")
        for name in REGS:
            if name in ("rsp", focus):
                continue
            j = REGS.index(name)
            bd, bl = dr[widx].regs[j], lf[widx].regs[j]
            ad, al = dr[after].regs[j], lf[after].regs[j]
            if (ad, al) == (bd, bl):
                continue
            if classify_diff(ad, al, dr[after].regs[rsi], lf[after].regs[rsi]) != "real":
                continue
            if name in joined:
                next_focus = name
                break
            if next_focus is None:
                next_focus = name
        if next_focus is not None:
            ad = dr[after].regs[REGS.index(next_focus)]
            al = lf[after].regs[REGS.index(next_focus)]
            lines.append(
                f"       next_focus={next_focus} AFTER DR={hx(ad)} LF={hx(al)} "
                f"xor={hx(xor_pair(ad, al))}"
            )
            focus = next_focus

        diverge = widx

    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description="Auto chase mix LF/DR diverge (bias-agnostic)")
    repo = Path(__file__).resolve().parents[2]
    ap.add_argument("--lf", type=Path, default=repo / "build_msvc_dbg" / "mix_rerun_insn.csv")
    ap.add_argument("--dr", type=Path, default=Path(r"D:/sogen/dr/vmptest/mix_dr_insn.csv"))
    ap.add_argument("--wr", type=Path, default=repo / "build_msvc_dbg" / "mix_rerun_wr.csv")
    ap.add_argument("--pe", type=Path, default=Path(r"D:/sogen/dr/vmptest/test_fixed4.exe"))
    ap.add_argument("--reg", default="rcx", choices=REGS, help="Primary reg for walk-back chain")
    ap.add_argument(
        "--regs",
        default="",
        help="Comma-separated regs to diff at stop (default: --reg only). "
        "Example: rbp,r10,rcx,rsi",
    )
    ap.add_argument(
        "--stop-seq",
        type=int,
        default=0,
        help="LF insn seq to treat as stop (length stop when RVAs still align). "
        "0 = use first_rva_diverge or aligned prefix end.",
    )
    ap.add_argument(
        "--slots",
        default="",
        help="Comma-separated pseudo-stack slot VAs for wr poison index "
        f"(default: {','.join(hx(s) for s in DEFAULT_SLOTS)})",
    )
    ap.add_argument("--steps", type=int, default=12)
    ap.add_argument("--window", type=int, default=8, help="Insn rows to print around stop")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    diff_regs = [r.strip() for r in args.regs.split(",") if r.strip()] or [args.reg]
    for r in diff_regs:
        if r not in REGS:
            print(f"unknown reg: {r}", file=sys.stderr)
            return 2
    slot_list: list[int] = []
    if args.slots.strip():
        for tok in args.slots.split(","):
            tok = tok.strip()
            if tok:
                slot_list.append(int(tok, 0))
    else:
        slot_list = list(DEFAULT_SLOTS)

    for label, p in (("LF", args.lf), ("DR", args.dr)):
        if not p.exists():
            print(f"{label} missing: {p}", file=sys.stderr)
            return 2

    print(f"loading LF {args.lf} ...")
    lf = load_insn(args.lf)
    print(f"loading DR {args.dr} ...")
    dr = load_insn(args.dr)
    wr = load_wr(args.wr if args.wr.exists() else None)
    pe = PeDisasm(args.pe if args.pe.exists() else None)
    print(f"LF={len(lf)} DR={len(dr)} WR={len(wr)} disasm={'yes' if pe.ok else 'no'}")

    lines: list[str] = []

    def emit(s: str = "") -> None:
        lines.append(s)
        print(s)

    rva_diverge = find_rva_diverge(dr, lf)
    seq_by_rva24 = build_seq_by_rva24(lf)
    emit("=== chase_mix_diverge ===")
    emit(f"LF={args.lf}")
    emit(f"DR={args.dr}")
    emit(f"WR={args.wr} ({'ok' if wr else 'missing'})")
    emit()

    if rva_diverge is None:
        emit("first_rva_diverge: none (streams aligned to min length)")
        emit(f"aligned_prefix={min(len(dr), len(lf))} LF_len={len(lf)} DR_len={len(dr)}")
    else:
        drow, lrow = dr[rva_diverge], lf[rva_diverge]
        ri = REGS.index(args.reg)
        emit(
            f"first_rva_diverge: seq={lrow.seq} DR={hx(drow.rva)} LF={hx(lrow.rva)} "
            f"{args.reg} DR={hx(drow.regs[ri])} LF={hx(lrow.regs[ri])}"
        )
        if drow.regs[ri] is not None and lrow.regs[ri] is not None:
            emit(
                f"  {args.reg} xor={hx(drow.regs[ri] ^ lrow.regs[ri])} "
                f"delta={lrow.regs[ri] - drow.regs[ri]}"
            )
        emit(f"aligned_prefix={rva_diverge}")
    emit()

    if args.stop_seq:
        stop_idx = find_index_by_seq(lf, args.stop_seq)
        if stop_idx is None:
            print(f"--stop-seq {args.stop_seq} not found in LF stream", file=sys.stderr)
            return 2
        stop_kind = "stop-seq"
    elif rva_diverge is not None:
        stop_idx = rva_diverge
        stop_kind = "first_rva_diverge"
    else:
        stop_idx = min(len(dr), len(lf)) - 1
        stop_kind = "aligned_prefix_end"

    if stop_idx < 0:
        emit("no insn rows to analyze")
        if args.out:
            args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 0

    drow, lrow = dr[stop_idx], lf[stop_idx]
    emit(f"=== stop ({stop_kind}) idx={stop_idx} seq={lrow.seq} rva={hx(lrow.rva)} ===")
    emit()

    emit(f"=== reg diff at stop ({', '.join(diff_regs)}) ===")
    diffs = reg_diffs_at_index(dr, lf, stop_idx, diff_regs)
    if not diffs:
        emit("  (all listed regs eq/aslr/both-sym at stop)")
    for kind, reg, dv, lv in diffs:
        extra = ""
        if dv is not None and lv is not None and kind == "real":
            extra = f" xor={hx(dv ^ lv)}"
        emit(f"  [{kind}] {reg}: DR={hx(dv)} LF={hx(lv)}{extra}")
    emit()

    emit("=== LF reg concrete->sym flip (scan back from stop) ===")
    for reg in diff_regs:
        flip = scan_reg_flip_back(lf, stop_idx, reg)
        if flip is None:
            emit(f"  {reg}: no concrete->sym flip in scan window")
            continue
        idx, prev_v, _ = flip
        emit(
            f"  {reg}: last concrete->sym @ seq={lf[idx].seq} rva={hx(lf[idx].rva)} "
            f"prev={hx(prev_v)}"
        )
    emit()

    if wr:
        emit(f"=== wr slot poison index (before seq {lrow.seq}) ===")
        for line in slot_poison_report(wr, seq_by_rva24, lrow.seq, slot_list):
            emit(line)
        emit()
    else:
        emit("=== wr slot poison index: skipped (no WR file) ===")
        emit()

    diverge = stop_idx
    ri = REGS.index(args.reg)

    emit(f"=== window around stop (±{args.window}) ===")
    for i in range(max(0, diverge - args.window), min(len(lf), diverge + args.window)):
        mark = " <<<" if i == diverge else ""
        emit(
            f"  {lf[i].seq} DR={hx(dr[i].rva)} LF={hx(lf[i].rva)} "
            f"{args.reg}={hx(dr[i].regs[ri])}/{hx(lf[i].regs[ri])}{mark}"
        )
    emit()

    emit(f"=== constant XOR bias on hot RVAs ({args.reg}) ===")
    biases = bias_report(dr, lf, diverge, args.reg)
    stop_xor = None
    if drow.regs[ri] is not None and lrow.regs[ri] is not None:
        stop_xor = drow.regs[ri] ^ lrow.regs[ri]
        emit(f"  stop_xor={hx(stop_xor)}")
    if not biases:
        emit("  (none with stable small xor)")
    for rva, mode, cnt, tail in biases:
        emit(f"  rva={hx(rva)} xor={hx(mode)} hits_with_xor≈{cnt}")
        for seq, dv, lv in tail:
            emit(f"    seq={seq} DR={hx(dv)} LF={hx(lv)}")
    emit()

    emit(f"=== walk-back chain (focus={args.reg}, steps={args.steps}) ===")
    for line in walk_chain(
        dr, lf, diverge, args.reg, pe, wr, args.steps, stop_xor=stop_xor
    ):
        emit(line)
    emit()

    emit("=== notes ===")
    emit("  - insn stream is pre-exec; writer of value at seq N is the insn at seq N-1.")
    emit("  - ASLR-only diffs (same module RVA / same low20) are skipped.")
    emit("  - wr stream is LF-only; ~seq maps wr insn VA to last matching insn seq.")
    emit("  - use --stop-seq for length stops (same RVA prefix, reg/value diverge).")
    emit("  - no assumed 0x120 / 0x14fcd8; bias is measured from this pair of streams.")

    if args.out:
        args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"\nWrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
