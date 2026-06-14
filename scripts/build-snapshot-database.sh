#!/usr/bin/env bash
# Build a deterministic BitcoinPIR database from one Core dumptxoutset snapshot.
#
# This is the host/TEE boundary script:
#   snapshot.dat + expected Core MuHash -> flat UTXO set -> PIR database files
#   -> root-bundle payload -> optional TEE/local signature -> manifests.
#
# Required environment:
#   SNAPSHOT          Core dumptxoutset v2 snapshot path.
#   EXPECTED_MUHASH   Core gettxoutsetinfo muhash display hex.
#   NETWORK_MAGIC     4-byte network magic hex, e.g. f9beb4d9.
#   ANCHOR_HEIGHT     Snapshot block height.
#
# Common optional environment:
#   OUT_DIR           Output directory. Must not exist, or must be empty.
#   CORE_VERSION      Receipt-only version string, default "unknown".
#   ONION_ENTRY_SIZE  Default 3328.
#   PARTITIONS        Default 4.
#   ISSUED_AT         Root payload issued-at unix time. Default 0 for byte-stable
#                     cross-builder payloads; set explicitly for production.
#   BUILDER_KEY       If set, sign root-bundle-payload.bin with this key file.
#   WRITE_RECEIPT     1/0/auto. auto writes a receipt only when BUILDER_KEY is set.
#   RUN_ONION_FFI     1 to build onionffi --features ffi and run preprocess-all.
#   BIN               Existing pir-attested-builder binary path.
#   SKIP_CARGO_BUILD  1 to skip cargo build and require BIN.
#   RELEASE           1 for target/release (default), 0 for target/debug.
#   REFERENCE_DATABASE_MANIFEST      Optional manifest to diff against.
#   REFERENCE_ALL_ARTIFACTS_MANIFEST Optional manifest to diff against.
#   STAGE_SERVER_DB   1 to hardlink/copy server-loadable files to server-db/
#                     and write server-db/MANIFEST.toml. Default 1.
#   SERVER_DB_DIR     Optional server DB staging dir. Default OUT_DIR/server-db.
#
# Subcommands:
#   stage-server-db <out-dir> [server-db-dir]
#     Hardlink/copy server-loadable files from an existing build output and
#     write MANIFEST.toml, without re-running the snapshot pipeline.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

usage() {
    sed -n '1,39p' "$0" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_env() {
    local name=$1
    if [[ -z "${!name:-}" ]]; then
        fail "$name is required"
    fi
}

hash_one() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

zero_hash() {
    printf '0000000000000000000000000000000000000000000000000000000000000000'
}

kv() {
    local file=$1
    local key=$2
    awk -F= -v key="$key" '$1 == key {print substr($0, length(key) + 2); exit}' "$file"
}

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|y|Y) return 0 ;;
        *) return 1 ;;
    esac
}

ensure_empty_or_absent_dir() {
    local dir=$1
    if [[ -e "$dir" && ! -d "$dir" ]]; then
        fail "OUT_DIR exists and is not a directory: $dir"
    fi
    if [[ -d "$dir" ]]; then
        local existing=()
        shopt -s nullglob dotglob
        existing=("$dir"/*)
        shopt -u nullglob dotglob
        if ((${#existing[@]} != 0)); then
            fail "OUT_DIR must be empty to avoid overwriting prior artifacts: $dir"
        fi
    else
        mkdir -p "$dir"
    fi
}

quote_command() {
    local first=1
    for arg in "$@"; do
        if ((first)); then
            first=0
        else
            printf ' '
        fi
        printf '%q' "$arg"
    done
    printf '\n'
}

run_step() {
    local label=$1
    shift
    local log="$LOG_DIR/$label.out"

    printf 'step=%s status=running log=%s\n' "$label" "$log" | tee -a "$SUMMARY"
    {
        printf 'started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'command='
        quote_command "$@"
    } > "$log"

    set +e
    "$@" >> "$log" 2>&1
    local status=$?
    set -e

    printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$log"
    printf 'exit_code=%s\n' "$status" >> "$log"
    if ((status != 0)); then
        printf 'step=%s status=failed log=%s\n' "$label" "$log" | tee -a "$SUMMARY" >&2
        sed -n '1,220p' "$log" >&2
        exit "$status"
    fi
    printf 'step=%s status=ok log=%s\n' "$label" "$log" | tee -a "$SUMMARY"
}

write_manifest() {
    local dir=$1
    local out=$2
    local mode=$3
    local exclude_rel=${4:-}
    (
        cd "$dir"
        find . -type f -print | LC_ALL=C sort |
            while IFS= read -r path; do
                case "$path" in
                    ./logs/*|./server-db/*|*.manifest.sha256|*.manifest.diff|./build-summary.txt|./build.env|./build-receipt.txt)
                        continue
                        ;;
                esac
                if [[ -n "$exclude_rel" ]]; then
                    case "$path" in
                        ./"$exclude_rel"|./"$exclude_rel"/*)
                            continue
                            ;;
                    esac
                fi
                if [[ "$mode" == "database" ]]; then
                    case "$path" in
                        ./root-bundle-payload.bin|./signed-root-bundle.bin)
                            continue
                            ;;
                    esac
                fi
                path=${path#./}
                printf '%s  %s\n' "$(hash_one "$path")" "$path"
            done
    ) > "$out"
}

link_or_copy() {
    local src=$1
    local dst=$2
    ln "$src" "$dst" 2>/dev/null || cp -p "$src" "$dst"
}

stage_server_db_file() {
    local out_dir=$1
    local server_dir=$2
    local rel=$3
    local src="$out_dir/$rel"
    if [[ ! -f "$src" ]]; then
        return
    fi
    mkdir -p "$server_dir/$(dirname "$rel")"
    link_or_copy "$src" "$server_dir/$rel"
}

write_server_db_manifest() {
    local dir=$1
    local out="$dir/MANIFEST.toml"
    local files_list
    files_list=$(mktemp)
    (
        cd "$dir"
        find . -type f ! -name MANIFEST.toml -print |
            sed 's#^\./##' |
            LC_ALL=C sort
    ) > "$files_list"

    local n
    n=$(wc -l < "$files_list" | tr -d ' ')
    if [[ "$n" == "0" ]]; then
        rm -f "$files_list"
        fail "server DB staging dir has no files: $dir"
    fi

    local tmp="$dir/.MANIFEST.toml.$$"
    {
        printf '# Auto-generated by attested-builder scripts/build-snapshot-database.sh; do not hand-edit.\n'
        printf '# Files:        %s\n' "$n"
        printf '\n'
        printf '[manifest]\n'
        printf 'version = 1\n'
        printf '\n'
        printf '[files]\n'
        while IFS= read -r rel; do
            case "$rel" in
                *_cuckoo.bin)
                    printf '"%s" = "%s"\n' "$rel" "$(zero_hash)"
                    ;;
                *)
                    printf '"%s" = "%s"\n' "$rel" "$(hash_one "$dir/$rel")"
                    ;;
            esac
        done < "$files_list"
    } > "$tmp"
    mv -f "$tmp" "$out"
    chmod 0644 "$out"
    rm -f "$files_list"
}

stage_server_db() {
    local out_dir=$1
    local server_dir=$2
    if [[ -e "$server_dir" ]]; then
        fail "server DB staging dir already exists: $server_dir"
    fi
    mkdir -p "$server_dir"

    local fixed_files=(
        chain_anchor.bin
        batch_pir_cuckoo.bin
        chunk_pir_cuckoo.bin
        merkle_bucket_root.bin
        merkle_bucket_roots.bin
        merkle_bucket_tree_tops.bin
        onion_chunk_cuckoo.bin
        onion_data_bin_hashes.bin
        onion_index_all.bin
        onion_index_bin_hashes.bin
        onion_index_meta.bin
        onion_shared_ntt.bin
        merkle_onion_root.bin
        merkle_onion_roots.bin
        merkle_onion_sib_data.bin
        merkle_onion_sib_index.bin
        merkle_onion_tree_tops.bin
    )

    local rel
    for rel in "${fixed_files[@]}"; do
        stage_server_db_file "$out_dir" "$server_dir" "$rel"
    done

    local path
    shopt -s nullglob
    for path in "$out_dir"/merkle_bucket_index_sib_L*.bin "$out_dir"/merkle_bucket_chunk_sib_L*.bin; do
        stage_server_db_file "$out_dir" "$server_dir" "$(basename "$path")"
    done
    shopt -u nullglob

    [[ -f "$server_dir/batch_pir_cuckoo.bin" ]] || fail "server DB missing batch_pir_cuckoo.bin"
    [[ -f "$server_dir/chunk_pir_cuckoo.bin" ]] || fail "server DB missing chunk_pir_cuckoo.bin"
    write_server_db_manifest "$server_dir"
}

diff_manifest_if_requested() {
    local label=$1
    local expected=${2:-}
    local actual=$3
    local diff_out=$4
    if [[ -z "$expected" ]]; then
        return
    fi
    if ! diff -u "$expected" "$actual" > "$diff_out"; then
        printf 'error: %s manifest differs; diff: %s\n' "$label" "$diff_out" >&2
        sed -n '1,240p' "$diff_out" >&2
        exit 1
    fi
    printf '%s_manifest_matches=%s\n' "$label" "$expected" | tee -a "$SUMMARY"
}

if [[ "${1:-}" == "stage-server-db" ]]; then
    if [[ $# -lt 2 || $# -gt 3 ]]; then
        fail "usage: $0 stage-server-db <out-dir> [server-db-dir]"
    fi
    OUT_DIR=$2
    SERVER_DB_DIR=${3:-"$OUT_DIR/server-db"}
    [[ -d "$OUT_DIR" ]] || fail "build output directory does not exist: $OUT_DIR"
    stage_server_db "$OUT_DIR" "$SERVER_DB_DIR"
    printf 'server_db_dir=%s\n' "$SERVER_DB_DIR"
    printf 'server_db_manifest=%s\n' "$SERVER_DB_DIR/MANIFEST.toml"
    printf 'server_db_manifest_sha256=%s\n' "$(hash_one "$SERVER_DB_DIR/MANIFEST.toml")"
    exit 0
fi

require_env SNAPSHOT
require_env EXPECTED_MUHASH
require_env NETWORK_MAGIC
require_env ANCHOR_HEIGHT

[[ -f "$SNAPSHOT" ]] || fail "snapshot does not exist: $SNAPSHOT"
[[ "$EXPECTED_MUHASH" =~ ^[0-9a-fA-F]{64}$ ]] || fail "EXPECTED_MUHASH must be 64 hex chars"
[[ "$NETWORK_MAGIC" =~ ^[0-9a-fA-F]{8}$ ]] || fail "NETWORK_MAGIC must be 8 hex chars"
[[ "$ANCHOR_HEIGHT" =~ ^[0-9]+$ ]] || fail "ANCHOR_HEIGHT must be an integer"

CORE_VERSION=${CORE_VERSION:-unknown}
ONION_ENTRY_SIZE=${ONION_ENTRY_SIZE:-3328}
PARTITIONS=${PARTITIONS:-4}
ISSUED_AT=${ISSUED_AT:-0}
RELEASE=${RELEASE:-1}
RUN_ONION_FFI=${RUN_ONION_FFI:-0}
SKIP_CARGO_BUILD=${SKIP_CARGO_BUILD:-0}
WRITE_RECEIPT=${WRITE_RECEIPT:-auto}
PUSH_BATCH_ENTRIES=${PUSH_BATCH_ENTRIES:-256}
STAGE_SERVER_DB=${STAGE_SERVER_DB:-1}
OUT_DIR=${OUT_DIR:-"/tmp/attested-builder-snapshot-$(date -u +%Y%m%dT%H%M%SZ)"}
SERVER_DB_DIR=${SERVER_DB_DIR:-"$OUT_DIR/server-db"}

[[ "$ONION_ENTRY_SIZE" =~ ^[1-9][0-9]*$ ]] || fail "ONION_ENTRY_SIZE must be positive"
[[ "$PARTITIONS" =~ ^[1-9][0-9]*$ ]] || fail "PARTITIONS must be positive"
[[ "$ISSUED_AT" =~ ^-?[0-9]+$ ]] || fail "ISSUED_AT must be an integer"
[[ "$PUSH_BATCH_ENTRIES" =~ ^[1-9][0-9]*$ ]] || fail "PUSH_BATCH_ENTRIES must be positive"

ensure_empty_or_absent_dir "$OUT_DIR"
LOG_DIR="$OUT_DIR/logs"
mkdir -p "$LOG_DIR"
SUMMARY="$OUT_DIR/build-summary.txt"
ENV_FILE="$OUT_DIR/build.env"

{
    printf 'repo_root=%s\n' "$REPO_ROOT"
    printf 'snapshot=%s\n' "$SNAPSHOT"
    printf 'expected_muhash=%s\n' "$EXPECTED_MUHASH"
    printf 'network_magic=%s\n' "$NETWORK_MAGIC"
    printf 'anchor_height=%s\n' "$ANCHOR_HEIGHT"
    printf 'core_version=%s\n' "$CORE_VERSION"
    printf 'onion_entry_size=%s\n' "$ONION_ENTRY_SIZE"
    printf 'partitions=%s\n' "$PARTITIONS"
    printf 'issued_at=%s\n' "$ISSUED_AT"
    printf 'run_onion_ffi=%s\n' "$RUN_ONION_FFI"
} > "$ENV_FILE"
cp "$ENV_FILE" "$SUMMARY"

cd "$REPO_ROOT"

if ! is_truthy "$SKIP_CARGO_BUILD"; then
    if is_truthy "$RELEASE"; then
        cargo build -q --release -p pir-attested-builder
        BIN=${BIN:-"$REPO_ROOT/target/release/pir-attested-builder"}
    else
        cargo build -q -p pir-attested-builder
        BIN=${BIN:-"$REPO_ROOT/target/debug/pir-attested-builder"}
    fi
else
    require_env BIN
fi
[[ -x "$BIN" ]] || fail "pir-attested-builder binary is not executable: $BIN"
printf 'builder_bin=%s\n' "$BIN" | tee -a "$SUMMARY"

if is_truthy "$RUN_ONION_FFI"; then
    if ! is_truthy "$SKIP_CARGO_BUILD"; then
        if is_truthy "$RELEASE"; then
            cargo build -q --release -p onionffi --features ffi
            ONIONFFI_BIN=${ONIONFFI_BIN:-"$REPO_ROOT/target/release/onionffi"}
        else
            cargo build -q -p onionffi --features ffi
            ONIONFFI_BIN=${ONIONFFI_BIN:-"$REPO_ROOT/target/debug/onionffi"}
        fi
    else
        require_env ONIONFFI_BIN
    fi
    [[ -x "$ONIONFFI_BIN" ]] || fail "onionffi binary is not executable: $ONIONFFI_BIN"
    printf 'onionffi_bin=%s\n' "$ONIONFFI_BIN" | tee -a "$SUMMARY"
fi

run_step 01-materialize-utxo-set \
    "$BIN" materialize-utxo-set \
    "$SNAPSHOT" \
    "$EXPECTED_MUHASH" \
    "$OUT_DIR/utxo_set.bin" \
    "$ANCHOR_HEIGHT" \
    "$OUT_DIR/chain_anchor.bin"

run_step 02-build-utxo-chunks \
    "$BIN" build-utxo-chunks "$OUT_DIR/utxo_set.bin" "$OUT_DIR" "$PARTITIONS"

run_step 03-build-index-cuckoo \
    "$BIN" build-index-cuckoo \
    "$OUT_DIR/utxo_chunks_index_nodust.bin" \
    "$OUT_DIR/batch_pir_cuckoo.bin" \
    --anchor "$OUT_DIR/chain_anchor.bin"

run_step 04-build-chunk-cuckoo \
    "$BIN" build-chunk-cuckoo \
    "$OUT_DIR/utxo_chunks_nodust.bin" \
    "$OUT_DIR/chunk_pir_cuckoo.bin" \
    --anchor "$OUT_DIR/chain_anchor.bin"

run_step 05-build-bucket-merkle \
    "$BIN" build-bucket-merkle \
    "$OUT_DIR/batch_pir_cuckoo.bin" \
    "$OUT_DIR/chunk_pir_cuckoo.bin" \
    "$OUT_DIR"

run_step 06-build-onion-pack \
    "$BIN" build-onion-pack "$OUT_DIR/utxo_set.bin" "$OUT_DIR" "$ONION_ENTRY_SIZE"

run_step 07-build-onion-data-cuckoo \
    "$BIN" build-onion-data-cuckoo \
    "$OUT_DIR/onion_packed_entries.bin" \
    "$OUT_DIR" \
    "$ONION_ENTRY_SIZE" \
    --anchor "$OUT_DIR/chain_anchor.bin"

run_step 08-build-onion-index-cuckoo \
    "$BIN" build-onion-index-cuckoo \
    "$OUT_DIR/onion_index.bin" \
    "$OUT_DIR" \
    "$ONION_ENTRY_SIZE" \
    --anchor "$OUT_DIR/chain_anchor.bin"

run_step 09-build-onion-merkle \
    "$BIN" build-onion-merkle \
    "$OUT_DIR/onion_index_bin_hashes.bin" \
    "$OUT_DIR/onion_data_bin_hashes.bin" \
    "$OUT_DIR" \
    "$ONION_ENTRY_SIZE"

if is_truthy "$RUN_ONION_FFI"; then
    run_step 10-onionffi-preprocess-all \
        "$ONIONFFI_BIN" preprocess-all "$OUT_DIR" "$PUSH_BATCH_ENTRIES"
fi

index_bins=$(kv "$LOG_DIR/03-build-index-cuckoo.out" "bins_per_table")
chunk_bins=$(kv "$LOG_DIR/04-build-chunk-cuckoo.out" "bins_per_table")
[[ -n "$index_bins" ]] || fail "could not parse index bins from 03-build-index-cuckoo.out"
[[ -n "$chunk_bins" ]] || fail "could not parse chunk bins from 04-build-chunk-cuckoo.out"

run_step 11-build-root-bundle-payload \
    "$BIN" build-root-bundle-payload \
    "$OUT_DIR" \
    "$NETWORK_MAGIC" \
    "$OUT_DIR/chain_anchor.bin" \
    "$EXPECTED_MUHASH" \
    "$index_bins" \
    "$chunk_bins" \
    "$ONION_ENTRY_SIZE" \
    "$ISSUED_AT" \
    "$OUT_DIR/root-bundle-payload.bin"

if [[ -n "${BUILDER_KEY:-}" ]]; then
    [[ -f "$BUILDER_KEY" ]] || fail "BUILDER_KEY does not exist: $BUILDER_KEY"
    run_step 12-sign-root-bundle \
        "$BIN" sign-root-bundle \
        "$OUT_DIR/root-bundle-payload.bin" \
        "$BUILDER_KEY" \
        "$OUT_DIR/signed-root-bundle.bin"

    signer_pubkey=$(kv "$LOG_DIR/12-sign-root-bundle.out" "signer_pubkey")
    [[ -n "$signer_pubkey" ]] || fail "could not parse signer_pubkey"
    BUNDLE_THRESHOLD=${BUNDLE_THRESHOLD:-1}
    if [[ -n "${TRUSTED_PUBKEYS:-}" ]]; then
        read -r -a trusted_pubkeys <<< "$TRUSTED_PUBKEYS"
    else
        trusted_pubkeys=("$signer_pubkey")
    fi
    run_step 13-verify-root-bundle \
        "$BIN" verify-root-bundle \
        "$OUT_DIR/signed-root-bundle.bin" \
        "$BUNDLE_THRESHOLD" \
        "${trusted_pubkeys[@]}"
fi

if [[ "$WRITE_RECEIPT" == "auto" ]]; then
    if [[ -n "${BUILDER_KEY:-}" ]]; then
        WRITE_RECEIPT=1
    else
        WRITE_RECEIPT=0
    fi
fi

if is_truthy "$WRITE_RECEIPT"; then
    [[ -f "$OUT_DIR/signed-root-bundle.bin" ]] ||
        fail "WRITE_RECEIPT=1 requires BUILDER_KEY / signed-root-bundle.bin"
    run_step 14-write-build-receipt \
        "$BIN" write-build-receipt \
        "$OUT_DIR/signed-root-bundle.bin" \
        "$SNAPSHOT" \
        "$CORE_VERSION" \
        "$OUT_DIR/build-receipt.txt"
fi

if is_truthy "$STAGE_SERVER_DB"; then
    stage_server_db "$OUT_DIR" "$SERVER_DB_DIR"
    printf 'server_db_dir=%s\n' "$SERVER_DB_DIR" | tee -a "$SUMMARY"
    printf 'server_db_manifest=%s\n' "$SERVER_DB_DIR/MANIFEST.toml" | tee -a "$SUMMARY"
    printf 'server_db_manifest_sha256=%s\n' "$(hash_one "$SERVER_DB_DIR/MANIFEST.toml")" | tee -a "$SUMMARY"
fi

DATABASE_MANIFEST="$OUT_DIR/database.manifest.sha256"
ALL_ARTIFACTS_MANIFEST="$OUT_DIR/all-artifacts.manifest.sha256"
server_db_exclude_rel=
case "$SERVER_DB_DIR/" in
    "$OUT_DIR"/*) server_db_exclude_rel=${SERVER_DB_DIR#"$OUT_DIR"/} ;;
esac
write_manifest "$OUT_DIR" "$DATABASE_MANIFEST" database "$server_db_exclude_rel"
write_manifest "$OUT_DIR" "$ALL_ARTIFACTS_MANIFEST" all "$server_db_exclude_rel"

diff_manifest_if_requested \
    database \
    "${REFERENCE_DATABASE_MANIFEST:-}" \
    "$DATABASE_MANIFEST" \
    "$OUT_DIR/database.manifest.diff"
diff_manifest_if_requested \
    all_artifacts \
    "${REFERENCE_ALL_ARTIFACTS_MANIFEST:-}" \
    "$ALL_ARTIFACTS_MANIFEST" \
    "$OUT_DIR/all-artifacts.manifest.diff"

bucket_root=$(kv "$LOG_DIR/05-build-bucket-merkle.out" "super_root")
onion_root=$(kv "$LOG_DIR/09-build-onion-merkle.out" "super_root")
payload_sha256=$(kv "$LOG_DIR/11-build-root-bundle-payload.out" "payload_sha256")

{
    printf 'status=ok\n'
    printf 'out_dir=%s\n' "$OUT_DIR"
    printf 'muhash=%s\n' "$EXPECTED_MUHASH"
    printf 'anchor_height=%s\n' "$ANCHOR_HEIGHT"
    printf 'index_bins_per_table=%s\n' "$index_bins"
    printf 'chunk_bins_per_table=%s\n' "$chunk_bins"
    printf 'bucket_super_root=%s\n' "$bucket_root"
    printf 'onion_super_root=%s\n' "$onion_root"
    printf 'payload_sha256=%s\n' "$payload_sha256"
    if [[ -f "$OUT_DIR/signed-root-bundle.bin" ]]; then
        printf 'bundle_sha256=%s\n' "$(hash_one "$OUT_DIR/signed-root-bundle.bin")"
    fi
    if [[ -f "$OUT_DIR/build-receipt.txt" ]]; then
        printf 'receipt_sha256=%s\n' "$(hash_one "$OUT_DIR/build-receipt.txt")"
    fi
    printf 'database_manifest=%s\n' "$DATABASE_MANIFEST"
    printf 'database_manifest_sha256=%s\n' "$(hash_one "$DATABASE_MANIFEST")"
    printf 'all_artifacts_manifest=%s\n' "$ALL_ARTIFACTS_MANIFEST"
    printf 'all_artifacts_manifest_sha256=%s\n' "$(hash_one "$ALL_ARTIFACTS_MANIFEST")"
} | tee -a "$SUMMARY"
