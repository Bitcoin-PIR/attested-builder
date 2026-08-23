#!/usr/bin/env bash
# Deterministic local end-to-end smoke for the tiny committed regtest fixture.
#
# This is intentionally a plain-host smoke. It exercises the same
# snapshot -> muhash gate -> deterministic DB artifacts -> root payload
# chain as a native full-build, then a test-only Ed25519 wrap. Production
# TEE trust is BuildEvidence v2 + SEV-SNP, not this test key.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

FIXTURE=${FIXTURE:-"$REPO_ROOT/fixtures/txoutset_regtest_111.dat"}
EXPECTED_MUHASH=${EXPECTED_MUHASH:-"5b93564046e31a3798231c767eb24e45dd818b77ae022cbe8861e2af9d4a8c09"}
NETWORK_MAGIC=${NETWORK_MAGIC:-"fabfb5da"}
ANCHOR_HEIGHT=${ANCHOR_HEIGHT:-"111"}
CORE_VERSION=${CORE_VERSION:-"Bitcoin Core v31.0.0"}
ONION_ENTRY_SIZE=${ONION_ENTRY_SIZE:-"3328"}
ISSUED_AT=${ISSUED_AT:-"1800000000"}
PARTITIONS=${PARTITIONS:-"4"}
KEEP_TMP=${KEEP_TMP:-"0"}

# Fixed test-only Ed25519 seed. Never use this key for production bundles.
TEST_BUILDER_SEED_HEX=${TEST_BUILDER_SEED_HEX:-"0707070707070707070707070707070707070707070707070707070707070707"}

# Stable golden values for the committed regtest fixture and fixed test key.
EXPECTED_BUCKET_ROOT=${EXPECTED_BUCKET_ROOT:-"d75ea9f795defe239a08f371a2954b0e2150ee72bc65612ecdfa27b0f8a5a280"}
EXPECTED_ONION_ROOT=${EXPECTED_ONION_ROOT:-"61aa94907bdeb13b3ff243c0e011ccf08d4c77cb78bbc6bb43cdec0c2eb9e64e"}
EXPECTED_PAYLOAD_SHA256=${EXPECTED_PAYLOAD_SHA256:-"a68844b221ebf5b0aa882b94af6ae39ea1144f033375af005df8bf6189ead789"}
EXPECTED_BUNDLE_SHA256=${EXPECTED_BUNDLE_SHA256:-"4696d334cd717715cdd34ca03a771b79e8470ee6327489976606a240427860f4"}
# The receipt and full output manifest include the temporary bundle path, so
# the script compares two runs byte-for-byte but does not pin cross-run hashes.
EXPECTED_RECEIPT_SHA256=${EXPECTED_RECEIPT_SHA256:-""}
EXPECTED_MANIFEST_SHA256=${EXPECTED_MANIFEST_SHA256:-""}

WORK=${WORK:-"$(mktemp -d /tmp/attested-builder-regtest-e2e.XXXXXX)"}
RUN_DIR="$WORK/run"
LOG_DIR="$WORK/logs"
KEY_FILE="$WORK/test-builder-key.txt"
MANIFEST_A="$WORK/manifest-a.sha256"
MANIFEST_B="$WORK/manifest-b.sha256"

cleanup() {
    if [[ "$KEEP_TMP" != "1" ]]; then
        rm -rf "$WORK"
    else
        printf 'kept_tmp=%s\n' "$WORK"
    fi
}
trap cleanup EXIT

hash_one() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

hex_file() {
    if command -v xxd >/dev/null 2>&1; then
        xxd -p -c 256 "$1"
    else
        od -An -tx1 -v "$1" | tr -d ' \n'
        printf '\n'
    fi
}

write_manifest() {
    local dir=$1
    local out=$2
    (
        cd "$dir"
        find . -type f -print | sed 's#^\./##' | LC_ALL=C sort |
            while IFS= read -r path; do
                printf '%s  %s\n' "$(hash_one "$path")" "$path"
            done
    ) > "$out"
}

kv() {
    local file=$1
    local key=$2
    awk -F= -v key="$key" '$1 == key {print substr($0, length(key) + 2); exit}' "$file"
}

assert_eq() {
    local name=$1
    local expected=$2
    local actual=$3
    if [[ -n "$expected" && "$actual" != "$expected" ]]; then
        printf 'error: %s mismatch\nexpected=%s\nactual=%s\n' "$name" "$expected" "$actual" >&2
        exit 1
    fi
}

run_builder() {
    "$BIN" "$@"
}

run_once() {
    local label=$1
    rm -rf "$RUN_DIR"
    mkdir -p "$RUN_DIR" "$LOG_DIR"

    run_builder verify-snapshot "$FIXTURE" "$EXPECTED_MUHASH" > "$LOG_DIR/$label.verify-snapshot.out"
    run_builder materialize-utxo-set \
        "$FIXTURE" \
        "$EXPECTED_MUHASH" \
        "$RUN_DIR/utxo_set.bin" \
        "$ANCHOR_HEIGHT" \
        "$RUN_DIR/chain_anchor.bin" \
        > "$LOG_DIR/$label.materialize.out"
    run_builder build-utxo-chunks "$RUN_DIR/utxo_set.bin" "$RUN_DIR" "$PARTITIONS" \
        > "$LOG_DIR/$label.build-utxo-chunks.out"

    run_builder build-index-cuckoo \
        "$RUN_DIR/utxo_chunks_index_nodust.bin" \
        "$RUN_DIR/batch_pir_cuckoo.bin" \
        --anchor "$RUN_DIR/chain_anchor.bin" \
        > "$LOG_DIR/$label.build-index-cuckoo.out"
    run_builder build-chunk-cuckoo \
        "$RUN_DIR/utxo_chunks_nodust.bin" \
        "$RUN_DIR/chunk_pir_cuckoo.bin" \
        --anchor "$RUN_DIR/chain_anchor.bin" \
        > "$LOG_DIR/$label.build-chunk-cuckoo.out"
    run_builder build-bucket-merkle \
        "$RUN_DIR/batch_pir_cuckoo.bin" \
        "$RUN_DIR/chunk_pir_cuckoo.bin" \
        "$RUN_DIR" \
        > "$LOG_DIR/$label.build-bucket-merkle.out"

    run_builder build-onion-pack "$RUN_DIR/utxo_set.bin" "$RUN_DIR" "$ONION_ENTRY_SIZE" \
        > "$LOG_DIR/$label.build-onion-pack.out"
    run_builder build-onion-data-cuckoo \
        "$RUN_DIR/onion_packed_entries.bin" \
        "$RUN_DIR" \
        "$ONION_ENTRY_SIZE" \
        --anchor "$RUN_DIR/chain_anchor.bin" \
        > "$LOG_DIR/$label.build-onion-data-cuckoo.out"
    run_builder build-onion-index-cuckoo \
        "$RUN_DIR/onion_index.bin" \
        "$RUN_DIR" \
        "$ONION_ENTRY_SIZE" \
        --anchor "$RUN_DIR/chain_anchor.bin" \
        > "$LOG_DIR/$label.build-onion-index-cuckoo.out"
    run_builder build-onion-merkle \
        "$RUN_DIR/onion_index_bin_hashes.bin" \
        "$RUN_DIR/onion_data_bin_hashes.bin" \
        "$RUN_DIR" \
        "$ONION_ENTRY_SIZE" \
        > "$LOG_DIR/$label.build-onion-merkle.out"

    local index_bins
    local chunk_bins
    index_bins=$(kv "$LOG_DIR/$label.build-index-cuckoo.out" "bins_per_table")
    chunk_bins=$(kv "$LOG_DIR/$label.build-chunk-cuckoo.out" "bins_per_table")

    run_builder build-root-bundle-payload \
        "$RUN_DIR" \
        "$NETWORK_MAGIC" \
        "$RUN_DIR/chain_anchor.bin" \
        "$EXPECTED_MUHASH" \
        "$index_bins" \
        "$chunk_bins" \
        "$ONION_ENTRY_SIZE" \
        "$ISSUED_AT" \
        "$RUN_DIR/root-bundle-payload.bin" \
        > "$LOG_DIR/$label.build-root-bundle-payload.out"
    run_builder sign-root-bundle \
        "$RUN_DIR/root-bundle-payload.bin" \
        "$KEY_FILE" \
        "$RUN_DIR/signed-root-bundle.bin" \
        > "$LOG_DIR/$label.sign-root-bundle.out"

    local pubkey
    pubkey=$(kv "$LOG_DIR/$label.sign-root-bundle.out" "signer_pubkey")
    run_builder verify-root-bundle "$RUN_DIR/signed-root-bundle.bin" 1 "$pubkey" \
        > "$LOG_DIR/$label.verify-root-bundle.out"
    run_builder write-build-receipt \
        "$RUN_DIR/signed-root-bundle.bin" \
        "$FIXTURE" \
        "$CORE_VERSION" \
        "$RUN_DIR/build-receipt.txt" \
        > "$LOG_DIR/$label.write-build-receipt.out"
}

cd "$REPO_ROOT"
cargo build -q -p pir-attested-builder
BIN=${BIN:-"$REPO_ROOT/target/debug/pir-attested-builder"}
cargo build -q -p onionffi --features ffi
ONIONFFI_BIN=${ONIONFFI_BIN:-"$REPO_ROOT/target/debug/onionffi"}

mkdir -p "$WORK" "$LOG_DIR"
printf '# deterministic local-regtest-e2e test key\nsecret_seed_hex=%s\n' "$TEST_BUILDER_SEED_HEX" > "$KEY_FILE"

run_once a
write_manifest "$RUN_DIR" "$MANIFEST_A"

bucket_root=$(hex_file "$RUN_DIR/merkle_bucket_root.bin")
onion_root=$(hex_file "$RUN_DIR/merkle_onion_root.bin")
payload_sha256=$(hash_one "$RUN_DIR/root-bundle-payload.bin")
bundle_sha256=$(hash_one "$RUN_DIR/signed-root-bundle.bin")
receipt_sha256=$(hash_one "$RUN_DIR/build-receipt.txt")
manifest_sha256=$(hash_one "$MANIFEST_A")

run_once b
write_manifest "$RUN_DIR" "$MANIFEST_B"

if ! diff -u "$MANIFEST_A" "$MANIFEST_B" > "$WORK/manifest.diff"; then
    printf 'error: run output manifests differ; diff follows\n' >&2
    sed -n '1,240p' "$WORK/manifest.diff" >&2
    exit 1
fi

assert_eq "bucket_super_root" "$EXPECTED_BUCKET_ROOT" "$bucket_root"
assert_eq "onion_super_root" "$EXPECTED_ONION_ROOT" "$onion_root"
assert_eq "payload_sha256" "$EXPECTED_PAYLOAD_SHA256" "$payload_sha256"
assert_eq "bundle_sha256" "$EXPECTED_BUNDLE_SHA256" "$bundle_sha256"
assert_eq "receipt_sha256" "$EXPECTED_RECEIPT_SHA256" "$receipt_sha256"
assert_eq "manifest_sha256" "$EXPECTED_MANIFEST_SHA256" "$manifest_sha256"

# Native full-build v2: exercise the snapshot wrapper rather than
# reattest-existing.  A host fixture has no SEV device, so this checks the
# complete staging layout and evidence binding up to (but not including) the
# platform quote generated in a measured builder.
V2_DIR="$WORK/full-build-v2"
SNAPSHOT="$FIXTURE" \
EXPECTED_MUHASH="$EXPECTED_MUHASH" \
NETWORK_MAGIC="$NETWORK_MAGIC" \
ANCHOR_HEIGHT="$ANCHOR_HEIGHT" \
CORE_VERSION="$CORE_VERSION" \
ONION_ENTRY_SIZE="$ONION_ENTRY_SIZE" \
ISSUED_AT="$ISSUED_AT" \
PARTITIONS="$PARTITIONS" \
OUT_DIR="$V2_DIR" \
BIN="$BIN" \
SKIP_CARGO_BUILD=1 \
RUN_ONION_FFI=1 \
ONIONFFI_BIN="$ONIONFFI_BIN" \
WRITE_RECEIPT=0 \
EMIT_SEV_SNP_QUOTE=0 \
BUILD_EVIDENCE_VERSION=2 \
"$REPO_ROOT/scripts/build-snapshot-database.sh" > "$LOG_DIR/full-build-v2.out"

for rel in \
    root-bundle-payload.bin \
    build-evidence.bin \
    build-evidence.report-data \
    database.manifest.sha256 \
    all-artifacts.manifest.sha256 \
    server-db/MANIFEST.toml \
    oram-direct-inputs/utxo_chunks_index_nodust.bin \
    oram-direct-inputs/utxo_chunks_nodust.bin \
    oram-direct-inputs/direct-inputs.sha256; do
    [[ -s "$V2_DIR/$rel" ]] || {
        printf 'error: native full-build v2 missing required staging artifact: %s\n' "$rel" >&2
        exit 1
    }
done

V2_EVIDENCE_LOG="$V2_DIR/logs/15-write-build-evidence.out"
grep -qx 'evidence_version=2' "$V2_EVIDENCE_LOG"
grep -qx 'evidence_mode=full_build' "$V2_EVIDENCE_LOG"
grep -qx 'predecessor_evidence_sha256=none' "$V2_EVIDENCE_LOG"
grep -qx 'predecessor_report_sha256=none' "$V2_EVIDENCE_LOG"

index_hash=$(hash_one "$V2_DIR/oram-direct-inputs/utxo_chunks_index_nodust.bin")
chunk_hash=$(hash_one "$V2_DIR/oram-direct-inputs/utxo_chunks_nodust.bin")
grep -qx "$index_hash  utxo_chunks_index_nodust.bin" "$V2_DIR/oram-direct-inputs/direct-inputs.sha256"
grep -qx "$chunk_hash  utxo_chunks_nodust.bin" "$V2_DIR/oram-direct-inputs/direct-inputs.sha256"
grep -qx "index_sha256 = \"$index_hash\"" "$V2_DIR/server-db/MANIFEST.toml"
grep -qx "chunk_sha256 = \"$chunk_hash\"" "$V2_DIR/server-db/MANIFEST.toml"
index_records=$(($(wc -c < "$V2_DIR/oram-direct-inputs/utxo_chunks_index_nodust.bin") / 25))
chunk_records=$(($(wc -c < "$V2_DIR/oram-direct-inputs/utxo_chunks_nodust.bin") / 40))
grep -qx "index_records = $index_records" "$V2_DIR/server-db/MANIFEST.toml"
grep -qx "chunk_records = $chunk_records" "$V2_DIR/server-db/MANIFEST.toml"

run_builder verify-build-evidence \
    "$V2_DIR/build-evidence.bin" \
    --snapshot "$FIXTURE" \
    --builder-bin "$BIN" \
    --payload "$V2_DIR/root-bundle-payload.bin" \
    --database-manifest "$V2_DIR/database.manifest.sha256" \
    --all-artifacts-manifest "$V2_DIR/all-artifacts.manifest.sha256" \
    --server-db-manifest "$V2_DIR/server-db/MANIFEST.toml" \
    > "$LOG_DIR/full-build-v2.verify-evidence.out"

if SNAPSHOT="$FIXTURE" \
    EXPECTED_MUHASH="$EXPECTED_MUHASH" \
    NETWORK_MAGIC="$NETWORK_MAGIC" \
    ANCHOR_HEIGHT="$ANCHOR_HEIGHT" \
    OUT_DIR="$WORK/rejected-roots-only-v2" \
    BIN="$BIN" \
    SKIP_CARGO_BUILD=1 \
    ROOTS_ONLY=1 \
    BUILD_EVIDENCE_VERSION=2 \
    "$REPO_ROOT/scripts/build-snapshot-database.sh" > "$LOG_DIR/rejected-roots-only-v2.out" 2>&1; then
    printf 'error: roots-only mode must not claim native full-build v2 evidence\n' >&2
    exit 1
fi
grep -q 'BUILD_EVIDENCE_VERSION=2 requires a full snapshot build' "$LOG_DIR/rejected-roots-only-v2.out"

# Derive a second, syntactically valid regtest snapshot deterministically from
# the committed fixture. The builder recomputes its MuHash below; this keeps a
# non-empty delta fixture local to the E2E rather than committing generated
# chain data.
DELTA_TO_SNAPSHOT="$WORK/txoutset_regtest_112-derived.dat"
node - "$FIXTURE" "$DELTA_TO_SNAPSHOT" <<'NODE'
const fs = require('fs');
const [from, to] = process.argv.slice(2);
const data = fs.readFileSync(from);
if (data.length < 84) throw new Error('snapshot is too short');
data[11] ^= 0x5a; // Base block hash: derive a distinct test-only anchor.
data[51] ^= 0xa5; // First outpoint txid: force a deterministic spent/created delta.
fs.writeFileSync(to, data);
NODE

DELTA_TO_MUHASH=$(run_builder compute-muhash "$DELTA_TO_SNAPSHOT" | awk -F= '$1 == "muhash" {print $2}')
DELTA_TO_ANCHOR_HASH=$(run_builder compute-muhash "$DELTA_TO_SNAPSHOT" | awk -F= '$1 == "base_hash" {print $2}')
[[ "$DELTA_TO_MUHASH" =~ ^[0-9a-f]{64}$ ]] || {
    printf 'error: derived snapshot did not produce a MuHash\n' >&2
    exit 1
}
[[ "$DELTA_TO_MUHASH" != "$EXPECTED_MUHASH" ]] || {
    printf 'error: derived snapshot MuHash must differ from from snapshot\n' >&2
    exit 1
}
[[ "$DELTA_TO_ANCHOR_HASH" != "4e4003e955a41b187ad32e26fc837a98ca284df84ca3bbea19e6d164b3ebb3e7" ]] || {
    printf 'error: derived snapshot anchor must differ from from snapshot\n' >&2
    exit 1
}

DELTA_DIR="$WORK/full-build-v2-delta"
FROM_SNAPSHOT="$FIXTURE" \
FROM_EXPECTED_MUHASH="$EXPECTED_MUHASH" \
FROM_ANCHOR_HEIGHT="$ANCHOR_HEIGHT" \
TO_SNAPSHOT="$DELTA_TO_SNAPSHOT" \
TO_EXPECTED_MUHASH="$DELTA_TO_MUHASH" \
TO_ANCHOR_HEIGHT="$((ANCHOR_HEIGHT + 1))" \
NETWORK_MAGIC="$NETWORK_MAGIC" \
CORE_VERSION="$CORE_VERSION" \
ONION_ENTRY_SIZE="$ONION_ENTRY_SIZE" \
ISSUED_AT="$ISSUED_AT" \
OUT_DIR="$DELTA_DIR" \
BIN="$BIN" \
SKIP_CARGO_BUILD=1 \
RUN_ONION_FFI=1 \
ONIONFFI_BIN="$ONIONFFI_BIN" \
WRITE_RECEIPT=0 \
EMIT_SEV_SNP_QUOTE=0 \
ROOTS_ONLY=0 \
BUILD_EVIDENCE_VERSION=2 \
"$REPO_ROOT/scripts/build-delta-database.sh" > "$LOG_DIR/full-build-v2-delta.out"

for rel in \
    root-bundle-payload.bin \
    build-evidence.bin \
    build-evidence.report-data \
    database.manifest.sha256 \
    all-artifacts.manifest.sha256 \
    server-db/MANIFEST.toml \
    oram-direct-inputs/utxo_chunks_index_nodust.bin \
    oram-direct-inputs/utxo_chunks_nodust.bin \
    oram-direct-inputs/direct-inputs.sha256; do
    [[ -s "$DELTA_DIR/$rel" ]] || {
        printf 'error: native full-build v2 delta missing staging artifact: %s\n' "$rel" >&2
        exit 1
    }
done

DELTA_PAYLOAD_LOG="$DELTA_DIR/logs/13-build-delta-root-bundle-payload.out"
DELTA_EVIDENCE_LOG="$DELTA_DIR/logs/17-write-build-evidence.out"
grep -qx 'build_kind=delta' "$DELTA_PAYLOAD_LOG"
grep -qx "from_anchor_height=$ANCHOR_HEIGHT" "$DELTA_PAYLOAD_LOG"
grep -qx "anchor_height=$((ANCHOR_HEIGHT + 1))" "$DELTA_PAYLOAD_LOG"
grep -qx "muhash=$DELTA_TO_MUHASH" "$DELTA_PAYLOAD_LOG"
FROM_MUHASH_INTERNAL=$(node -e 'process.stdout.write(Buffer.from(process.argv[1], "hex").reverse().toString("hex"))' "$EXPECTED_MUHASH")
grep -qx "root:input/from-utxo-muhash=$FROM_MUHASH_INTERNAL" "$DELTA_PAYLOAD_LOG"
grep -qx 'evidence_version=2' "$DELTA_EVIDENCE_LOG"
grep -qx 'build_kind=delta' "$DELTA_EVIDENCE_LOG"
grep -qx 'evidence_mode=full_build' "$DELTA_EVIDENCE_LOG"
grep -qx 'predecessor_evidence_sha256=none' "$DELTA_EVIDENCE_LOG"
grep -qx 'predecessor_report_sha256=none' "$DELTA_EVIDENCE_LOG"

delta_index_hash=$(hash_one "$DELTA_DIR/oram-direct-inputs/utxo_chunks_index_nodust.bin")
delta_chunk_hash=$(hash_one "$DELTA_DIR/oram-direct-inputs/utxo_chunks_nodust.bin")
delta_index_records=$(($(wc -c < "$DELTA_DIR/oram-direct-inputs/utxo_chunks_index_nodust.bin") / 25))
delta_chunk_records=$(($(wc -c < "$DELTA_DIR/oram-direct-inputs/utxo_chunks_nodust.bin") / 40))
((delta_index_records > 0 && delta_chunk_records > 0)) || {
    printf 'error: derived delta must produce non-empty Direct ORAM inputs\n' >&2
    exit 1
}
grep -qx "$delta_index_hash  utxo_chunks_index_nodust.bin" "$DELTA_DIR/oram-direct-inputs/direct-inputs.sha256"
grep -qx "$delta_chunk_hash  utxo_chunks_nodust.bin" "$DELTA_DIR/oram-direct-inputs/direct-inputs.sha256"
grep -qx "index_sha256 = \"$delta_index_hash\"" "$DELTA_DIR/server-db/MANIFEST.toml"
grep -qx "chunk_sha256 = \"$delta_chunk_hash\"" "$DELTA_DIR/server-db/MANIFEST.toml"
grep -qx "index_records = $delta_index_records" "$DELTA_DIR/server-db/MANIFEST.toml"
grep -qx "chunk_records = $delta_chunk_records" "$DELTA_DIR/server-db/MANIFEST.toml"

run_builder verify-build-evidence \
    "$DELTA_DIR/build-evidence.bin" \
    --snapshot "$DELTA_TO_SNAPSHOT" \
    --builder-bin "$BIN" \
    --payload "$DELTA_DIR/root-bundle-payload.bin" \
    --database-manifest "$DELTA_DIR/database.manifest.sha256" \
    --all-artifacts-manifest "$DELTA_DIR/all-artifacts.manifest.sha256" \
    --server-db-manifest "$DELTA_DIR/server-db/MANIFEST.toml" \
    --expected-muhash "$DELTA_TO_MUHASH" \
    --expected-anchor-height "$((ANCHOR_HEIGHT + 1))" \
    --expected-anchor-hash "$DELTA_TO_ANCHOR_HASH" \
    > "$LOG_DIR/full-build-v2-delta.verify-evidence.out"

if FROM_SNAPSHOT="$FIXTURE" \
    FROM_EXPECTED_MUHASH="$EXPECTED_MUHASH" \
    FROM_ANCHOR_HEIGHT="$ANCHOR_HEIGHT" \
    TO_SNAPSHOT="$DELTA_TO_SNAPSHOT" \
    TO_EXPECTED_MUHASH="$DELTA_TO_MUHASH" \
    TO_ANCHOR_HEIGHT="$((ANCHOR_HEIGHT + 1))" \
    NETWORK_MAGIC="$NETWORK_MAGIC" \
    OUT_DIR="$WORK/rejected-delta-roots-only-v2" \
    BIN="$BIN" \
    SKIP_CARGO_BUILD=1 \
    ROOTS_ONLY=1 \
    BUILD_EVIDENCE_VERSION=2 \
    "$REPO_ROOT/scripts/build-delta-database.sh" > "$LOG_DIR/rejected-delta-roots-only-v2.out" 2>&1; then
    printf 'error: roots-only delta mode must not claim native full-build v2 evidence\n' >&2
    exit 1
fi
grep -q 'BUILD_EVIDENCE_VERSION=2 requires a full delta build' "$LOG_DIR/rejected-delta-roots-only-v2.out"

printf 'status=ok\n'
printf 'fixture=%s\n' "$FIXTURE"
printf 'muhash=%s\n' "$EXPECTED_MUHASH"
printf 'anchor_height=%s\n' "$ANCHOR_HEIGHT"
printf 'core_version=%s\n' "$CORE_VERSION"
printf 'bucket_super_root=%s\n' "$bucket_root"
printf 'onion_super_root=%s\n' "$onion_root"
printf 'payload_sha256=%s\n' "$payload_sha256"
printf 'bundle_sha256=%s\n' "$bundle_sha256"
printf 'receipt_sha256=%s\n' "$receipt_sha256"
printf 'manifest_sha256=%s\n' "$manifest_sha256"
printf 'native_full_build_v2=%s\n' "$V2_DIR"
printf 'native_full_build_v2_delta=%s\n' "$DELTA_DIR"
