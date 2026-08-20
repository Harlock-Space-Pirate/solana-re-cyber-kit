# Install Ghidra for Solana sBPF

## 1. Prerequisites

- **Java 17** (`application.java.min=17` for Ghidra 10.3)

```bash
# macOS
export JAVA_HOME="$(/usr/libexec/java_home -v 17)"
```

- **Ghidra 10.3+** unpacked to `$GHIDRA_HOME` (default `$HOME/ghidra`)
- Headless: `$GHIDRA_HOME/support/analyzeHeadless`
- SLEIGH: `$GHIDRA_HOME/support/sleigh`

If you upgrade Ghidra major versions, **recompile `.sla`**.

## 2. Processor pack (this repo)

Stock Ghidra **Linux eBPF** is the wrong ISA. Install **sBPF**:

```bash
export GHIDRA_HOME="${GHIDRA_HOME:-$HOME/ghidra}"
chmod +x install/install-sbpf-processor.sh
./install/install-sbpf-processor.sh
```

Languages: `sBPF:v1` (use this), `sBPF:v2`, `sBPF:v3`.

## 3. GUI check

1. `$GHIDRA_HOME/ghidraRun`
2. Import a Solana `.so`
3. Language **`sBPF:v1`**, compiler **default**
4. `sBPF.cspec` uses stackpointer **R10**, `pointer_size=8`

ELF `e_machine` 247 and 263 are both accepted (`sBPF.opinion`).

## 4. Headless smoke

```bash
./pipeline/decompile-program.sh /path/to/program.so /tmp/sbpf-out
```

Log must mention `sBPF:v1`.

## 5. Do not “fix” SLEIGH for formulas

Re-import the ELF when hashes change. Do not retune R10. See [GHIDRA-SOLANA.md](GHIDRA-SOLANA.md).
