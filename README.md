# Attested builder

Standalone producer of BitcoinPIR production databases and build
evidence. It is not the serving runtime, not the browser verifier, and
not a multi-builder quorum service.

The locked production commit is the one BitcoinPIR pins in
`PRODUCTION_ORAM_DB_PROOF_V2_PINS` and
`scripts/build_uki_attested_builder_tier3.sh`. Do not copy that hash
into this file. Operator steps that boot this code on VPSBG live in
BitcoinPIR: Flow H in `docs/PRODUCTION_OPERATIONS.md` and
`docs/ATTESTED_BUILDER_TIER3_UKI.md`.

`PLAN.md` is a frozen 2026-06 design note (k-of-n Ed25519 bundles,
Nitro, client strict mode). It is not the current contract.

## What one production run covers

A production generation is one native full-build V2 pipeline:

| Mode | Script | Input |
| --- | --- | --- |
| Snapshot | `scripts/build-snapshot-database.sh` | one Core `dumptxoutset` v2 file + `gettxoutsetinfo muhash` |
| Delta | `scripts/build-delta-database.sh` | two snapshot files + both MuHashes; set-diff is inside this process |

The measured UKI only accepts:

- `MODE=native-full-build-v2-snapshot`
- `MODE=native-full-build-v2-delta`
- `MODE=reattest-existing-v2` (proof-migration only; ineligible for
  production TEE-ORAM)

Native V2 forces `ROOTS_ONLY=0`, `STAGE_SERVER_DB=1`, `RUN_ONION_FFI=1`,
`BUILD_EVIDENCE_VERSION=2`. `latest/` is published only after the
runner sees V2, `evidence_mode=full_build`, and no predecessor hashes.

From those inputs the same run emits every serving backend's bytes:

| Backend | Artifacts | Bound in evidence |
| --- | --- | --- |
| DPF-PIR | `batch_pir_cuckoo.bin`, `chunk_pir_cuckoo.bin`, bucket Merkle | `bucket_super_root` |
| HarmonyPIR queries | same INDEX/CHUNK + bucket Merkle as DPF | same `bucket_super_root` |
| OnionPIR | packed entries, cuckoo, Merkle, FFI `onion_shared_ntt.bin` / `onion_index_all.bin` / sibling rows | `onion_super_root` + typed Onion v2 layout |
| Direct ORAM | `oram-direct-inputs/utxo_chunks_{index,}_nodust.bin` and `[direct_oram]` in `server-db/MANIFEST.toml` | server-db manifest hash |

Plus the trust sidecars the BitcoinPIR runtime serves verbatim:

- `server-db/` (server-loadable tree + `MANIFEST.toml`)
- `root-bundle-payload.bin` (v2 payload; scanner-verified Onion layout)
- `build-evidence.bin` / `build-evidence.report-data`
- `build-evidence.sev-snp-report.bin` when `EMIT_SEV_SNP_QUOTE=1`
- `database.manifest.sha256`, `all-artifacts.manifest.sha256`

There is no separate “DPF builder” or “Onion builder”. A collection
assembled after the fact is not a production candidate.

## What this repo does not cover

These are out of scope here, not unfinished backends:

| Concern | Where it actually lives |
| --- | --- |
| Harmony hint blobs | pir1 runtime hint pool; fingerprint-checked in the browser, not a DB-proof family |
| BHTM / trust-chain (`fromMuhash`, block hash) | `Bitcoin-PIR/bhtm` producer; BitcoinPIR `web/public/proofs/trust-chain/` |
| Serving pir1 binary pin | BitcoinPIR `PIR1_PIN` |
| Serving pir2 UKI measurement | BitcoinPIR `PIR2_TIER3_PIN` (runtime UKI, not this image) |
| Formal / EasyCrypt wire-shape | BitcoinPIR `verification/locks/formal-proofs.json` |
| Client k-of-n builder-key quorum | `PLAN.md` Phase 2; not shipped. Production clients pin evidence + builder binary/commit |
| Nitro / TDX guests | not implemented; SEV-SNP `/dev/sev-guest` is the only quote provider |
| Multi-builder diversity | not implemented |
| Development databases | BitcoinPIR `scripts/build_full.sh` / `tools/db-builder` — must not produce a production rotation |

`BUILD_EVIDENCE_VERSION=1` and `ROOTS_ONLY=1` still exist as host/legacy
paths. They are not the production UKI contract. `reattest-existing-v2`
can re-bind already-built serving images and must report
`direct_oram_eligible=no`.

The live BitcoinPIR `940611 -> 948454` lineage is a mixed-provenance
exception retained on that side. Do not rebuild it here to make the
history look uniform.

## How BitcoinPIR consumes the output

BitcoinPIR does not treat this repo as the live pin catalog.

| Evidence | BitcoinPIR pin / lock | Who verifies |
| --- | --- | --- |
| V2 Onion layout + roots | `PRODUCTION_ONION_DB_PROOF_V2_PINS` | browser / WASM; local `db-proof verify` |
| V2 ORAM + producer identity | `PRODUCTION_ORAM_DB_PROOF_V2_PINS` + `verification/locks/generated-proofs.json` | same local v2 path; not `verify-live` |
| Builder SNP report | `web/public/proofs/oram-source/` | `pir-attested-builder verify-build-evidence` |
| DPF / Harmony roots | same V2 `bucket_super_root` | bound in this run's evidence; BitcoinPIR still *transports* them on the v1 opcode |

`proof_dir` vs `proof_v2_dir` is a BitcoinPIR packaging split, not a
second producer. The production UKI emits one V2 sidecar set. It does
not emit a parallel `BUILD_EVIDENCE_VERSION=1` directory. Live DPF and
Harmony clients still fetch `REQ_GET_DB_PROOF` and pin
`PRODUCTION_DB_PROOF_PINS` (no `proofVersion`); that table currently
names the retained mixed-provenance v1 sidecars. A new height therefore
has attested DPF/Harmony *bytes* in the V2 evidence, but no UKI-produced
v1 sidecar for that opcode. Do not invent a second producer to close
that packaging gap, and do not pair a `server-db` from one run with
evidence from another.

## Layout

| Path | Role |
| --- | --- |
| `coremuhash/` | Bitcoin Core MuHash3072 |
| `utxosnapshot/` | Core v2 `dumptxoutset` parser + MuHash gate |
| `dbpipeline/` | Deterministic INDEX/CHUNK/Onion/Merkle stages |
| `onionffi/` | Optional C++ OnionPIR preprocess (`--features ffi`) |
| `rootbundle/` | Canonical payload + optional Ed25519 wrapper |
| `builder/` | `pir-attested-builder` CLI |
| `scripts/build-snapshot-database.sh` | Snapshot orchestration |
| `scripts/build-delta-database.sh` | Delta orchestration |
| `scripts/local-regtest-e2e.sh` | Committed-fixture smoke |
| `scripts/local-mainnet-build.sh` | Owner-host wrapper; not a production authorization |
| `fixtures/` | Golden parser/MuHash vectors |

## Commands

```bash
cargo test --workspace
scripts/local-regtest-e2e.sh
```

Inspect or verify a finished output:

```bash
pir-attested-builder inspect-build-evidence OUT/build-evidence.bin
pir-attested-builder verify-build-evidence OUT/build-evidence.bin \
  --snapshot SNAPSHOT --builder-bin BIN \
  --payload OUT/root-bundle-payload.bin \
  --database-manifest OUT/database.manifest.sha256 \
  --all-artifacts-manifest OUT/all-artifacts.manifest.sha256 \
  --server-db-manifest OUT/server-db/MANIFEST.toml \
  --expected-muhash MUHASH \
  --expected-anchor-height HEIGHT \
  --sev-snp-report OUT/build-evidence.sev-snp-report.bin
```

`--expect-*` values come from the independently accepted generation
record, never from a live PIR server.

Wire-format changes to `rootbundle` follow
`rootbundle/COMPATIBILITY.md`.
