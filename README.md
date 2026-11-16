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

### Delta set-diff resources

`build-grouped-delta` externally sorts both flat UTXO sets by outpoint, merges
them, and sorts the changes by script before writing the existing grouped-delta
format. Sorting uses 64 MiB runs and at most 16 input runs per merge. Script
counts are spooled separately, so even a single large script group does not
have to fit in memory. Dust filtering, ordering and output bytes are unchanged.

This trades RAM for temporary disk I/O. Scratch files live beside the output
in `<output>.tmp-<pid>.sort/` and are removed when the operation returns, on
success or error; a forcibly terminated process can leave that directory.
The peak includes one sorted endpoint plus both the input and output of a
merge pass for the other endpoint. Each sorted endpoint record occupies 72
bytes, compared with 68 bytes in the flat input. This space is additional to
the two retained flat inputs and the final delta.

### Snapshot aggregation resources

Snapshot address aggregation (`build-utxo-chunks` and `build-onion-pack`) uses
the same bounded external sorter. It reads the flat UTXO set once, filters
dust, and visits one script group at a time. Whale groups are counted without
retaining their full entry lists. Partition order and the input order of
equal-height entries are preserved, so `PARTITIONS` remains a layout parameter,
not a memory-tuning knob. Sorting uses 77 bytes per non-dust UTXO on disk; a
merge can temporarily hold two copies. Scratch lives beside the output and is
removed when the operation returns.

### DPF cuckoo resources

`build-index-cuckoo` and `build-chunk-cuckoo` spool each input record into its
three existing groups, preserving input order. They then load and build one
group at a time rather than retaining the entire input, all group mappings,
and all tables. Hashing, insertion/kick order, anchor headers, and global
bin-count retries are unchanged. A retry rewrites every group at the new
common size. RAM scales with the largest group, not a fixed byte limit.

Spooling uses 75 bytes per index record or 132 bytes per input chunk: about
3.76 GiB and 9.96 GiB respectively at height 948454, additional to inputs and
outputs. These stages run separately, so the two scratch sizes are not added
together. Scratch uses the shared `<output>.tmp-<pid>.sort/` cleanup mechanism
and is removed on normal success/error. A forced termination can leave it.

Local macOS release comparisons on the retained 948454 inputs and snapshot
anchor reduced index peak RSS from 3.70 GiB to 101.5 MiB (45.2 to 34.5 seconds)
and chunk peak RSS from 5.33 GiB to 177.6 MiB (50.9 to 60.2 seconds). Both final
files and reports matched the full-memory implementation; file bytes also
matched the archived SHA-256 manifests. Tests additionally cover legacy,
snapshot and delta headers, empty inputs, global retry after earlier groups
were written, and scratch cleanup.

### Onion data NTT resources

`onionffi` transforms packed data entries using one reusable, bounded FFI
server and scatters each batch into the existing coefficient-major output.
The FFI server holds at most 4096 input entries; `push_batch_entries` controls
the smaller packing/push batches (default 256, limited by that server tile).
With the pinned 2048-coefficient/u64 parameters, the FFI table and headered
batch scratch file are each at most about 64 MiB. Packing buffers and FFI
working memory are additional. The final table
is still full-sized, but no second full-sized headered copy is needed.

The batch scratch directory lives beside the output and is removed on normal
success or error; errors also remove the partial output. Forced termination
can leave both. Shape-padding slots are explicitly zero: the pinned FFI's
allocator leaves them uninitialized, while the retained 948454 build contains
zeros. Empty input retains `params_info(0)`'s default output shape and produces
a zero-filled file without allocating that table in memory. Each full tile
writes 32 KiB at a time per coefficient row; storage latency can affect runtime.

Local macOS release comparison on the retained 948454 input (948640 entries,
default push batch) reduced peak RSS from 14.61 GiB to 80.3 MiB; elapsed time
was 51.6 seconds before and 111.0 seconds after. The 15544090624-byte output
matched both the old implementation and retained artifact byte-for-byte,
including its 96 zero-padding slots per row. Its archival SHA-256 is
`2f24fbf1c1dd5cd324141fa0c6a36cb5d1d1c739a66e5b2b53f53eae4040d07e`.

### Full-build disk budget

At retained height 948454, the top-level full-build artifacts total
70,742,253,197 bytes and the Core snapshot is another 9,422,874,286 bytes:
80.17 GB (74.66 GiB) together, before the OS, build tools, or other generations.
This assumes same-filesystem hardlinks for `server-db/` and Direct ORAM staging;
copy fallback needs more space.

Set `PRUNE_INTERMEDIATES=1` for a full snapshot build to release reproducible
files after their last successful consumer. The default is `0` for archival
builds. Roots-only builds keep their existing cleanup behavior.

| Intermediate | Release point | Rebuild source |
| --- | --- | --- |
| `utxo_set.bin` | After Onion packing (step 06) | Core snapshot, checked against MuHash |
| `onion_index.bin` | After root payload (step 11) | Re-materialized flat UTXOs, same Onion packing parameters |
| `merkle_onion_sib_rows_{index,data}.bin` | After root payload, if FFI completed | Retained Onion leaf-hash files |

The last three files contribute named hashes to the root payload, so they
stay through step 11. Their preprocessed serving files and the original
`onion_packed_entries.bin` / `onion_index_bins.bin` stay available for the final
v2 content scanner. Direct ORAM inputs and the source snapshot are retained.
`pruned-intermediates.tsv` records each released file's name, byte length,
SHA-256 and last consumer. It is included in the remaining-file manifests
bound by build evidence. Those manifests describe the smaller file inventory;
the root payload and serving bytes remain identical to an unpruned build.

At height 948454 this removes 12.784 GB: 11.209 GB early and 1.575 GB after
the root payload. The retained-file budget including the snapshot becomes
about **67.38 GB (62.75 GiB)**. The estimated file peak is **68.96 GB (64.22 GiB)**
before late pruning, accounting for the earlier sorter/group spools and FFI
scratch. These are byte-budget estimates from the retained generation, not a
full-pipeline measurement on the 80 GB host; OS/tools, filesystem overhead,
copy staging and newer chain growth need additional room.

```bash
# With the usual SNAPSHOT / EXPECTED_MUHASH / NETWORK_MAGIC / ANCHOR_HEIGHT:
PRUNE_INTERMEDIATES=1 RUN_ONION_FFI=1 BUILD_EVIDENCE_VERSION=2 \
  scripts/build-snapshot-database.sh

# Regenerate into a NEW directory outside OUT, without changing its manifests:
python3 scripts/rebuild-snapshot-intermediates.py OUT REBUILT --kind all
```

The rebuild tool also accepts `--kind flat`, `--kind onion-index` or
`--kind sibling-rows`, plus `--snapshot PATH` for a moved snapshot and
`--builder PATH` for the matching builder binary (default: this checkout's
release binary). It checks all requested lengths/hashes before publishing.
Rebuilding the Onion index also produces flat UTXOs and packed entries and
uses the packing sorter's scratch space. At height 948454, allow roughly
26 GB of additional working space for that reconstruction, beyond the
retained generation and source snapshot.
Sibling rows can be regenerated directly from the retained leaf hashes without
the snapshot. The tool's temporary products are cleaned on normal return/error.

The lifecycle integration test runs the real regtest pipeline both ways,
verifies v2 evidence, compares payload and serving bytes, checks failed-stage
retention, and regenerates the pruned files:

```bash
cargo build --locked --release -p pir-attested-builder -p onionffi --features onionffi/ffi
python3 scripts/test-snapshot-intermediates.py -v
```

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
