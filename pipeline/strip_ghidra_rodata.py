#!/usr/bin/env python3
"""Drop Ghidra rodata string-soup from handler dumps.

Keeps real C (if, FUN_, assignments). Writes *.clean.c next to the source.

  python3 tools/strip_ghidra_rodata.py artifacts/decomp/c4-sage-ghidra/attack_fleet_59ad057b.c
  python3 tools/strip_ghidra_rodata.py artifacts/decomp/c4-sage-ghidra/*.c
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# Quoted rodata blobs: pure ident glue OR any >=48-char literal (words+prose mix),
# e.g. "gamemintlootlistfileFour0.17itertools: .zip_eq() reached ..."
SOUP = re.compile(r'"[A-Za-z0-9_]{80,}"')
SOUP_MIXED = re.compile(r'"(?:[^"\\\n]|\\.){48,}"')
TRUNC_MARK = "TRUNCATED STRING LITERAL"
IDENT_RUN = re.compile(r"[a-z]{3,}(?:_[a-z0-9]+){8,}")
DANGLING_ASSIGN = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*$")


def keep(line: str) -> bool:
    s = line.strip()
    if not s:
        return True
    if s.startswith("/*") or s.startswith("*") or s.startswith("//"):
        return True
    if TRUNC_MARK in line:
        return False
    if SOUP.search(s) or SOUP_MIXED.search(s) or IDENT_RUN.search(s):
        return False
    if s.count('"') >= 2 and len(s) > 200 and s.count("_") > 20:
        return False
    return True


def repair(lines: list[str]) -> list[str]:
    """Fix shells left by dropped string lines: 'x =' + ';', ',arg' after ',', bare ','."""
    out: list[str] = []
    for ln in lines:
        s = ln.strip()
        prev = out[-1].rstrip() if out else ""
        ps = prev.strip()
        if s == ";":
            if ps.endswith("="):
                out.pop()  # dead assignment: 'x =' + ';'
                continue
            if s == ";" and ps.endswith(","):
                # dead last arg: 'f(a,' + ';'  -> close the call
                out[-1] = prev + ";"
                continue
        if s.startswith(",") and (ps.endswith(",") or ps.endswith("=") or ps.endswith("(")):
            ln = ln.lstrip()[1:]  # arg left orphaned by a removed string
            if not ln.strip():
                continue
        out.append(ln)
    # second pass: assignments whose RHS line vanished entirely
    return [ln for ln in out if not DANGLING_ASSIGN.match(ln.rstrip("\n"))]


def clean_file(src: Path) -> Path:
    lines = src.read_text(errors="replace").splitlines(True)
    kept = [ln for ln in lines if keep(ln)]
    kept = repair(repair(kept))  # run twice: repairs can cascade
    out = src.with_suffix(".clean.c")
    out.write_text("".join(kept))
    return out


def main() -> None:
    paths = [Path(a) for a in sys.argv[1:]]
    if not paths:
        sys.exit("usage: strip_ghidra_rodata.py <file.c>...")
    for p in paths:
        if not p.is_file():
            continue
        o = clean_file(p)
        raw, new = p.stat().st_size, o.stat().st_size
        print(f"{p.name}: {raw} → {new} bytes ({100 * new / max(raw, 1):.0f}%)")


if __name__ == "__main__":
    main()
