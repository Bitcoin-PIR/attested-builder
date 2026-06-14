#!/usr/bin/env bash
# Deterministic local end-to-end smoke for the tiny committed regtest fixture.
#
# This is intentionally a plain-host test. It exercises the same trust chain
# the TEE builder must run later:
#   snapshot -> muhash gate -> flat UTXO set -> deterministic DB artifacts
#   -> root bundle payload -> fixed-key signature -> quorum verify -> receipt.

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
