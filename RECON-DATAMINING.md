# Datamining / recon / pentest — what actually worked

Lessons from reversing closed-source Solana programs (StarFrame + a parallel public IDL that did **not** match the live cluster).

## Source order (mechanics)

1. **Named RE file** for that instruction (reconstructed handler or vendor IDL).
2. **Live account** on the cluster that actually runs it. Decode the field.
3. **Ghidra / asm** only for the leftover expression.
4. If live ≠ IDL → **live wins**. A public IDL for “the same game” can omit accounts that GPA shows are missing.

Never invent “probably a daily cap”. Pin offsets with `getAccountInfo`. One burned example: XP lived on a character account field, not on a fleet hop handler the IDL naming suggested.

## Binary recon

- Dump `.so`, hash it, keep versions (upgrade txs change everything).
- Discriminators: 8 bytes. Anchor `sha256("global:"+name)[:8]`; StarFrame is its own table — build the catalog from the binary, not from hope.
- Account metas from handler: writable/signer flags in the decoded sequence, then confirm with a **real tx** / `getAccountInfo`.
- Authority often sits in **CPI** (System, SPL, Bubblegum). If your decompiler hides `call` (BN crash workaround), you **cannot** close the vuln from static analysis — flag it and POC live.
- Strings: program ids, error text, `sol_log`. Not formulas.
- Hidden ixs: scan entry dispatch + historical ELF diffs (old `.so` vs new).

## Chain recon

- `getAccountInfo` / `getProgramAccounts` with filters. One field, one print.
- PDA seeds from `find_program_address` sites; then derive and fetch.
- Do not send mutating txs unless the operator asked.
- Testnet faucet / test SOL is often the blocker for POCs — static flags stay flags until a live tx.

## Infra / web recon (report-only)

Patterns that paid off:

- **Certificate transparency** → subdomain inventory across every zone in scope.
- Fingerprint: open JSON, Grafana, mail hostnames, secrets-manager UIs on `*.dev`.
- **Object storage**: list anonymously (`gsutil ls -l -r gs://bucket/`). A bucket *name* is not attribution — **read the JS**. Confirm from a first-party page.
- On-chain metadata URIs: HTML app vs JSON, leftover Cloud Run staging, dead CDN hosts.
- 3D/GLB: if the chain has no GLB URI, stop claiming studio attribution from chain.

Public buckets + **sourcemaps** = source disclosure (CRA `asset-manifest` + `.js.map`).

## Client / UI

- **Live site is UI truth.** Archives are dated. Dump ≠ “how SAGE works today”.
- `sa-assets` is loot-crate art, not the game client.

## Pentest / authz flags (static)

What the RE actually showed (Zink/C4, not mainnet SAGE unless said):

- Profile create without emptiness-check → ownership takeover of an empty account (self-inflicted unless another slot picks the target).
- Some C4 ixs: writable, **no signer** in the decoded metas — may be permissionless cranks or hidden PDA authority in CPI. Confirm live.
- `amount: Option<u32>` vs `0` vs `null` on the wire — repair path: null ≠ 0.
- Mainnet SAGE `depositCargoToFleet` is SPL transfer; a C4 “admin deposit” flag does not automatically exist on mainnet.

Write: **accounts, missing check, abuse path**. Hypothesis labeled. No “probably exploitable”.

## Tooling we keep

| Tool | Use |
|------|-----|
| `sbf_disasm.py` / readable asm | always-on |
| Ghidra sBPF:v1 + call-tree | one handler |
| `extract_formula_hints.py` | magics + callees |
| Zink RPC decode | pin the number |
| `c4-wire` catalog | discs / builders |
| GCS / CT / curl | infra |
| BN GUI | optional HLIL; not headless on Personal |

## Qwen Cyber in this loop

Use Ghidra **output files** (clean `.c`, call-tree, hints JSON), not “read the whole ELF in chat”. Policy: `/set-executionpolicy` for any live scan. Lab `10.42.0.0/24` is fake; real recon is RPC + HTTP + dump.
