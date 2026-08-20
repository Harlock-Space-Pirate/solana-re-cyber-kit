# Pipeline: Solana `.so` → facts

Worked example lives under `staratlas-analysis/` (C4 SAGE). Same steps for any program.

## 0. Fetch the binary

```bash
# cluster that actually runs the program
solana program dump -u "$RPC" "$PROGRAM_ID" program.so
shasum -a 256 program.so
```

Keep the hash. Upgrade = new hash = re-import Ghidra.

## 1. Cheap recon (before Ghidra)

- `strings program.so | rg -i 'anchor|starframe|sol_log|error'`
- 8-byte discriminators at entry (Anchor: `sha256("global:"+name)[:8]`)
- IDL account on-chain? (Anchor often; StarFrame often not)
- Size, ELF machine 247 vs 263

C4 we already have:

- discs / builders: `staratlas-analysis` + `runtime/c4-wire/`
- catalog: `knowledge/data/c4-wire-catalog.json` (240 ixs)
- bytecode: `staratlas-analysis/artifacts/bytecode/c4-sage.so`

## 2. Import + batch decompile

Handlers CSV (`name,elf_vaddr_hex,sol_addr_hex,disc8`), then:

```bash
export GHIDRA_HOME="${GHIDRA_HOME:-$HOME/ghidra}"
export KIT_ROOT="${KIT_ROOT:-$(pwd)}"
"$KIT_ROOT/pipeline/decompile-program.sh" /path/to/program.so ./out handlers.csv
```

If you keep a separate analysis tree (`$ANALYSIS_ROOT`):

```bash
cd "$ANALYSIS_ROOT"
FORCE_REIMPORT=1 ./tools/ghidra_decompile_top10.sh   # if ELF hash changed
./tools/ghidra_calltree.sh <handler> <sol_addr> 2
```

## 3. Strip soup

```bash
python3 pipeline/strip_ghidra_rodata.py out/attack_fleet_*.c
```

Do not paste 100 kB soup into a model.

## 4. Formula / mechanic pin (scripts first)

```bash
cd staratlas-analysis
python3 scripts/extract_formula_hints.py --ix complete_crafting_process
```

Looks at lean dumps + Ghidra `.c` / `.clean.c` for `FUN_ram_*` and known magics (`240`, `360`, `86400`, …).

**Then live:** `getAccountInfo` / GPA / decode on the real RPC. If SAGE IDL and C4 disagree, **C4 live wins**.

One leftover UNKNOWN number → one `FUN_ram_*` file in an LLM, not the whole program.

## 5. Address cheat sheet

| Kind | Example |
|------|---------|
| Solana vm text | `0x100000000 + file_off` |
| Ghidra | `file_off` after import with sBPF:v1 |
| Insn index (8-byte sBPF) | `file_off // 8` |

## Scripts in this repo

| File | Role |
|------|------|
| `scripts/DecompileSbfHandlers.java` | Named handlers from CSV |
| `scripts/DecompileCallTree.java` | Handler + callees, skip non-exec |
| `scripts/ListCallers.java` / `XListCallers.java` | Xrefs |
| `pipeline/ghidra_so_guard.sh` | SHA-256 sidecar |
| `pipeline/strip_ghidra_rodata.py` | Drop string soup |
| `pipeline/sbf_disasm.py` | Ground-truth disasm (no Ghidra) |
| `pipeline/decompile-program.sh` | Generic headless import |

C4 copies of the shell wrappers also sit in `pipeline/ghidra_*.sh` (they still point at `staratlas-analysis` paths — use them from that repo).
