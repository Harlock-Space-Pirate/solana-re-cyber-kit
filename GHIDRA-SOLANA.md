# Ghidra workarounds for Solana programs

These are the mistakes we already paid for. Treat them as law.

## Wrong tool: stock eBPF

Nalen98/eBPF-for-Ghidra is **Linux kernel eBPF**. Pitfalls that **do not** apply to Solana:

| Kernel eBPF myth | Solana sBPF |
|------------------|------------|
| `e_machine=247` only | Also **263** |
| no loops | loops exist |
| `bpf_*` helpers | `sol_*` syscalls (`sol_log`, `sol_invoke`, memcpy, …) |
| memory is stack-ish | map **`0x1` text / `0x2` rodata / `0x3` stack / `0x4` heap** + account vmaddrs |

Ghidra **requires a stack pointer**. Kernel eBPF only has frame pointer **R10**. Labeling R10 as SP with Stack Depth 0 **drops stores/loads on R10 as dead code**. Solana still uses R10 as FP. **Keep `sBPF.cspec`: `<stackpointer register="R10" space="ram"/>`.** Changing R10 to “fix” decompile makes C worse (Nalen98). We wrote this on the so-guard:

> Do NOT retune sBPF.cspec / R10 / SLEIGH to "fix" decompile. Re-import the live ELF instead.

Our compiler spec also:

- `pointer_size=8`
- calling convention `__fastcall`: args **R1–R5**, return **R0**, R6–R10 unaffected
- extra address space **`syscall`** (needed so decompiler does not eat syscall-side effects)

## Language id

Always: **`-processor sBPF:v1 -cspec default`**.

Address convention used everywhere in Star Atlas dumps:

```
Ghidra / file offset in .text  =  sol_addr - 0x100000000
example: sol 0x10013ec68  →  Ghidra 0x13ec68
```

`DecompileCallTree.java` accepts either form.

## ELF hash guard

Ghidra **projects cache analysis**. A new on-chain upgrade silently leaves you decompiling yesterday’s `.so`.

`pipeline/ghidra_so_guard.sh`:

- sidecar `<proj>/<name>.so.sha256`
- mismatch → `NEED_REIMPORT=1`
- `FORCE_REIMPORT=1` deletes `.gpr` / `.rep` and imports again

Never “analyze harder” on a stale project.

## Handler dumps ingest rodata soup

Full-handler `.c` often inlines **account-name string tables** (115 kB of `"gameMintLootListFile…"`). That is not the formula.

1. `python3 pipeline/strip_ghidra_rodata.py dump.c` → `dump.clean.c`
2. Prefer **call-tree** (`DecompileCallTree.java`) with `SKIP_DATA` (non-executable “functions” skipped)
3. Formulas often live in **asm immediates**, not pretty C — `sbf_disasm.py` + a small callee, then **live RPC** to pin the number

## Function creation

Stripped Rust/StarFrame: Ghidra will not name handlers. `DecompileSbfHandlers.java`:

1. Resolve addr from CSV (`name,elf_vaddr_hex,sol_addr_hex,disc8`)
2. `clearListing` + `disassemble` + `createFunction` if missing
3. Decompile timeout 120s
4. Write `name_disc8.c` + `INDEX.md`

If `NO_ADDR`: image base / memory map wrong (wrong processor or not ELF).
If `DECOMP_FAIL`: usually soup or a giant function — slice with call-tree depth 2, not the whole handler.

## Binary Ninja (optional, not required)

Personal license **blocks headless**. ottersec `bn-ebpf-solana` **CallDestination** on relative `call` **crashes** StarFrame SBF. Fix in `staratlas-analysis/tools/bn-ebpf-solana/instr.py`: default **off**; `SA_ALLOW_CALLDEST=1` to opt in. GUI only, analysis mode **controlled**.

Always-available path without BN: `tools/sbf_handlers_to_readable.py` → annotated asm.

## StarFrame vs Anchor

C4 SAGE is **StarFrame**, not Anchor.

- Anchor: `sha256("global:"+name)[:8]`, `sol_log "Instruction: Foo"`, error 2000/2002
- StarFrame: different discs; **do not** run IDLGuesser as the pipeline
- SAGE official IDL ≠ C4 on-chain layout (`ProgressionConfig` missing on C4; PXP pot is Character @ offset 282)

## What Ghidra is for

Readable C for **one handler + callees**. Not:

- walking 239 ixs in an LLM
- prettier C as source of numeric truth
- a replacement for `getAccountInfo` / GPA

Pipeline stays: **strip ELF → Ghidra call-tree → hint script → live RPC**.
