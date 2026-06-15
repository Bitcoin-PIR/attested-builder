#!/usr/bin/env bash
# Build a deterministic BitcoinPIR delta database from two Core dumptxoutset snapshots.
#
# Required environment:
#   FROM_SNAPSHOT          Core dumptxoutset v2 snapshot path at base height.
#   FROM_EXPECTED_MUHASH   Core gettxoutsetinfo muhash display hex at base height.
#   FROM_ANCHOR_HEIGHT     Base snapshot block height.
#   TO_SNAPSHOT            Core dumptxoutset v2 snapshot path at target height.
#   TO_EXPECTED_MUHASH     Core gettxoutsetinfo muhash display hex at target height.
#   TO_ANCHOR_HEIGHT       Target snapshot block height.
#   NETWORK_MAGIC          4-byte network magic hex, e.g. f9beb4d9.
#
# The trusted delta proof shape is:
#   verify FROM_SNAPSHOT MuHash -> materialize from_utxo_set.bin
#   verify TO_SNAPSHOT MuHash   -> materialize to_utxo_set.bin
#   deterministic set-diff inside this process -> delta_grouped.bin
#   delta_grouped.bin -> PIR DB Merkle roots -> root bundle/evidence.
#
# Common optional environment mirrors build-snapshot-database.sh:
#   OUT_DIR, CORE_VERSION, ONION_ENTRY_SIZE, ISSUED_AT, BUILDER_KEY,
#   WRITE_RECEIPT, BIN, SKIP_CARGO_BUILD, RELEASE, ROOTS_ONLY,
#   WRITE_BUILD_EVIDENCE, BUILDER_GIT_COMMIT, TEE_PLATFORM,
#   TEE_IMAGE_MEASUREMENT, EMIT_SEV_SNP_QUOTE.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

usage() {
    sed -n '1,33p' "$0" >&2
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

current_git_commit() {
    local rev
    rev=$(git -C "$REPO_ROOT" rev-parse --verify HEAD 2>/dev/null || printf unknown)
    if [[ "$rev" != "unknown" ]] &&
        { ! git -C "$REPO_ROOT" diff --quiet -- 2>/dev/null ||
          ! git -C "$REPO_ROOT" diff --cached --quiet -- 2>/dev/null; }; then
        printf '%s-dirty\n' "$rev"
    else
        printf '%s\n' "$rev"
    fi
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

remove_roots_only_files() {
    if ! is_truthy "$ROOTS_ONLY"; then
        return
    fi
    local path
    for path in "$@"; do
        if [[ -e "$path" ]]; then
            rm -f -- "$path"
        fi
    done
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
                        ./root-bundle-payload.bin|./signed-root-bundle.bin|./delta-inputs.txt)
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
        printf '# Auto-generated by attested-builder scripts/build-delta-database.sh; do not hand-edit.\n'
        printf '# Files:        %s\n\n' "$n"
        printf '[manifest]\n'
        printf 'version = 1\n'
        printf 'kind = "delta"\n\n'
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

write_roots_only_manifest() {
    local out_dir=$1
    local server_dir=$2
    mkdir -p "$server_dir"
    local out="$server_dir/MANIFEST.toml"
    local tmp="$server_dir/.MANIFEST.toml.$$"
    local bucket_root
    local onion_root
    bucket_root=$(kv "$LOG_DIR/08-build-bucket-merkle.out" "super_root")
    onion_root=$(kv "$LOG_DIR/12-build-onion-merkle.out" "super_root")
    [[ -n "$bucket_root" ]] || fail "could not parse bucket super root"
    [[ -n "$onion_root" ]] || fail "could not parse onion super root"
    {
        printf '# Auto-generated by attested-builder roots-only delta mode; do not hand-edit.\n'
        printf '# This is NOT a server-loadable database manifest.\n\n'
        printf '[manifest]\n'
        printf 'version = 1\n'
        printf 'kind = "delta-roots-only"\n'
        printf 'server_loadable = false\n\n'
        printf '[roots]\n'
        printf 'bucket_super_root = "%s"\n' "$bucket_root"
        printf 'onion_super_root = "%s"\n\n' "$onion_root"
        printf '[files]\n'
        for rel in \
            from_chain_anchor.bin \
            to_chain_anchor.bin \
            delta_anchor.bin \
            delta-inputs.txt \
            merkle_bucket_root.bin \
            merkle_onion_root.bin \
            root-bundle-payload.bin; do
            if [[ -f "$out_dir/$rel" ]]; then
                printf '"%s" = "%s"\n' "$rel" "$(hash_one "$out_dir/$rel")"
            fi
        done
    } > "$tmp"
    mv -f "$tmp" "$out"
    chmod 0644 "$out"
}

stage_server_db() {
    local out_dir=$1
    local server_dir=$2
    if [[ -e "$server_dir" ]]; then
        fail "server DB staging dir already exists: $server_dir"
    fi
    mkdir -p "$server_dir"

    local fixed_files=(
        delta_anchor.bin
        batch_pir_cuckoo.bin
        chunk_pir_cuckoo.bin
        merkle_bucket_root.bin
        merkle_bucket_roots.bin
        merkle_bucket_tree_tops.bin
        onion_chunk_cuckoo.bin
        onion_data_bin_hashes.bin
        onion_index_bin_hashes.bin
        onion_index_meta.bin
        merkle_onion_root.bin
        merkle_onion_roots.bin
        merkle_onion_tree_tops.bin
    )

    local rel
    for rel in "${fixed_files[@]}"; do
        stage_server_db_file "$out_dir" "$server_dir" "$rel"
    done

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

require_env FROM_SNAPSHOT
require_env FROM_EXPECTED_MUHASH
require_env FROM_ANCHOR_HEIGHT
require_env TO_SNAPSHOT
require_env TO_EXPECTED_MUHASH
require_env TO_ANCHOR_HEIGHT
require_env NETWORK_MAGIC

[[ -f "$FROM_SNAPSHOT" ]] || fail "FROM_SNAPSHOT does not exist: $FROM_SNAPSHOT"
[[ -f "$TO_SNAPSHOT" ]] || fail "TO_SNAPSHOT does not exist: $TO_SNAPSHOT"
[[ "$FROM_EXPECTED_MUHASH" =~ ^[0-9a-fA-F]{64}$ ]] || fail "FROM_EXPECTED_MUHASH must be 64 hex chars"
[[ "$TO_EXPECTED_MUHASH" =~ ^[0-9a-fA-F]{64}$ ]] || fail "TO_EXPECTED_MUHASH must be 64 hex chars"
[[ "$NETWORK_MAGIC" =~ ^[0-9a-fA-F]{8}$ ]] || fail "NETWORK_MAGIC must be 8 hex chars"
[[ "$FROM_ANCHOR_HEIGHT" =~ ^[0-9]+$ ]] || fail "FROM_ANCHOR_HEIGHT must be an integer"
[[ "$TO_ANCHOR_HEIGHT" =~ ^[0-9]+$ ]] || fail "TO_ANCHOR_HEIGHT must be an integer"
((FROM_ANCHOR_HEIGHT < TO_ANCHOR_HEIGHT)) || fail "FROM_ANCHOR_HEIGHT must be < TO_ANCHOR_HEIGHT"

CORE_VERSION=${CORE_VERSION:-unknown}
ONION_ENTRY_SIZE=${ONION_ENTRY_SIZE:-3328}
ISSUED_AT=${ISSUED_AT:-0}
RELEASE=${RELEASE:-1}
SKIP_CARGO_BUILD=${SKIP_CARGO_BUILD:-0}
WRITE_RECEIPT=${WRITE_RECEIPT:-auto}
ROOTS_ONLY=${ROOTS_ONLY:-1}
STAGE_SERVER_DB=${STAGE_SERVER_DB:-1}
if is_truthy "$ROOTS_ONLY"; then
    STAGE_SERVER_DB=0
fi
WRITE_BUILD_EVIDENCE=${WRITE_BUILD_EVIDENCE:-1}
BUILDER_GIT_COMMIT=${BUILDER_GIT_COMMIT:-$(current_git_commit)}
TEE_PLATFORM=${TEE_PLATFORM:-none}
TEE_IMAGE_MEASUREMENT=${TEE_IMAGE_MEASUREMENT:-none}
EMIT_SEV_SNP_QUOTE=${EMIT_SEV_SNP_QUOTE:-0}
OUT_DIR=${OUT_DIR:-"/tmp/attested-builder-delta-${FROM_ANCHOR_HEIGHT}-${TO_ANCHOR_HEIGHT}-$(date -u +%Y%m%dT%H%M%SZ)"}
SERVER_DB_DIR=${SERVER_DB_DIR:-"$OUT_DIR/server-db"}

[[ "$ONION_ENTRY_SIZE" =~ ^[1-9][0-9]*$ ]] || fail "ONION_ENTRY_SIZE must be positive"
[[ "$ISSUED_AT" =~ ^-?[0-9]+$ ]] || fail "ISSUED_AT must be an integer"

ensure_empty_or_absent_dir "$OUT_DIR"
LOG_DIR="$OUT_DIR/logs"
mkdir -p "$LOG_DIR"
SUMMARY="$OUT_DIR/build-summary.txt"
ENV_FILE="$OUT_DIR/build.env"

{
    printf 'repo_root=%s\n' "$REPO_ROOT"
    printf 'from_snapshot=%s\n' "$FROM_SNAPSHOT"
    printf 'from_expected_muhash=%s\n' "$FROM_EXPECTED_MUHASH"
    printf 'from_anchor_height=%s\n' "$FROM_ANCHOR_HEIGHT"
    printf 'to_snapshot=%s\n' "$TO_SNAPSHOT"
    printf 'to_expected_muhash=%s\n' "$TO_EXPECTED_MUHASH"
    printf 'to_anchor_height=%s\n' "$TO_ANCHOR_HEIGHT"
    printf 'network_magic=%s\n' "$NETWORK_MAGIC"
    printf 'core_version=%s\n' "$CORE_VERSION"
    printf 'onion_entry_size=%s\n' "$ONION_ENTRY_SIZE"
    printf 'issued_at=%s\n' "$ISSUED_AT"
    printf 'roots_only=%s\n' "$ROOTS_ONLY"
    printf 'builder_git_commit=%s\n' "$BUILDER_GIT_COMMIT"
    printf 'tee_platform=%s\n' "$TEE_PLATFORM"
    printf 'tee_image_measurement=%s\n' "$TEE_IMAGE_MEASUREMENT"
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

run_step 01-materialize-from-utxo-set \
    "$BIN" materialize-utxo-set \
    "$FROM_SNAPSHOT" \
    "$FROM_EXPECTED_MUHASH" \
    "$OUT_DIR/from_utxo_set.bin" \
    "$FROM_ANCHOR_HEIGHT" \
    "$OUT_DIR/from_chain_anchor.bin"

run_step 02-materialize-to-utxo-set \
    "$BIN" materialize-utxo-set \
    "$TO_SNAPSHOT" \
    "$TO_EXPECTED_MUHASH" \
    "$OUT_DIR/to_utxo_set.bin" \
    "$TO_ANCHOR_HEIGHT" \
    "$OUT_DIR/to_chain_anchor.bin"

run_step 03-write-delta-anchor \
    "$BIN" write-delta-anchor \
    "$OUT_DIR/from_chain_anchor.bin" \
    "$OUT_DIR/to_chain_anchor.bin" \
    "$OUT_DIR/delta_anchor.bin"

{
    printf 'from_snapshot=%s\n' "$FROM_SNAPSHOT"
    printf 'from_snapshot_sha256=%s\n' "$(hash_one "$FROM_SNAPSHOT")"
    printf 'from_snapshot_bytes=%s\n' "$(wc -c < "$FROM_SNAPSHOT" | tr -d ' ')"
    printf 'from_muhash=%s\n' "$FROM_EXPECTED_MUHASH"
    printf 'from_anchor_height=%s\n' "$FROM_ANCHOR_HEIGHT"
    printf 'from_anchor_hash=%s\n' "$(kv "$LOG_DIR/01-materialize-from-utxo-set.out" base_hash)"
    printf 'to_snapshot=%s\n' "$TO_SNAPSHOT"
    printf 'to_snapshot_sha256=%s\n' "$(hash_one "$TO_SNAPSHOT")"
    printf 'to_snapshot_bytes=%s\n' "$(wc -c < "$TO_SNAPSHOT" | tr -d ' ')"
    printf 'to_muhash=%s\n' "$TO_EXPECTED_MUHASH"
    printf 'to_anchor_height=%s\n' "$TO_ANCHOR_HEIGHT"
    printf 'to_anchor_hash=%s\n' "$(kv "$LOG_DIR/02-materialize-to-utxo-set.out" base_hash)"
    printf 'delta_anchor_sha256=%s\n' "$(hash_one "$OUT_DIR/delta_anchor.bin")"
} > "$OUT_DIR/delta-inputs.txt"

run_step 04-build-grouped-delta \
    "$BIN" build-grouped-delta \
    "$OUT_DIR/from_utxo_set.bin" \
    "$OUT_DIR/to_utxo_set.bin" \
    "$OUT_DIR/delta_grouped.bin"

run_step 05-build-delta-chunks \
    "$BIN" build-delta-chunks \
    "$OUT_DIR/delta_grouped.bin" \
    "$OUT_DIR/utxo_chunks_nodust.bin" \
    "$OUT_DIR/utxo_chunks_index_nodust.bin"

run_step 06-build-index-cuckoo \
    "$BIN" build-index-cuckoo \
    "$OUT_DIR/utxo_chunks_index_nodust.bin" \
    "$OUT_DIR/batch_pir_cuckoo.bin" \
    --anchor "$OUT_DIR/delta_anchor.bin"

run_step 07-build-chunk-cuckoo \
    "$BIN" build-chunk-cuckoo \
    "$OUT_DIR/utxo_chunks_nodust.bin" \
    "$OUT_DIR/chunk_pir_cuckoo.bin" \
    --anchor "$OUT_DIR/delta_anchor.bin"

bucket_merkle_args=(
    "$BIN" build-bucket-merkle
    "$OUT_DIR/batch_pir_cuckoo.bin"
    "$OUT_DIR/chunk_pir_cuckoo.bin"
    "$OUT_DIR"
)
if is_truthy "$ROOTS_ONLY"; then
    bucket_merkle_args+=(--root-only)
fi
run_step 08-build-bucket-merkle "${bucket_merkle_args[@]}"

run_step 09-build-delta-onion-pack \
    "$BIN" build-delta-onion-pack "$OUT_DIR/delta_grouped.bin" "$OUT_DIR" "$ONION_ENTRY_SIZE"

remove_roots_only_files \
    "$OUT_DIR/from_utxo_set.bin" \
    "$OUT_DIR/to_utxo_set.bin" \
    "$OUT_DIR/utxo_chunks_index_nodust.bin" \
    "$OUT_DIR/utxo_chunks_nodust.bin" \
    "$OUT_DIR/batch_pir_cuckoo.bin" \
    "$OUT_DIR/chunk_pir_cuckoo.bin" \
    "$OUT_DIR/merkle_bucket_tree_tops.bin" \
    "$OUT_DIR/merkle_bucket_roots.bin" \
    "$OUT_DIR"/merkle_bucket_index_sib_L*.bin \
    "$OUT_DIR"/merkle_bucket_chunk_sib_L*.bin

run_step 10-build-onion-data-cuckoo \
    "$BIN" build-onion-data-cuckoo \
    "$OUT_DIR/onion_packed_entries.bin" \
    "$OUT_DIR" \
    "$ONION_ENTRY_SIZE" \
    --anchor "$OUT_DIR/delta_anchor.bin"

remove_roots_only_files \
    "$OUT_DIR/onion_packed_entries.bin" \
    "$OUT_DIR/onion_chunk_cuckoo.bin"

run_step 11-build-onion-index-cuckoo \
    "$BIN" build-onion-index-cuckoo \
    "$OUT_DIR/onion_index.bin" \
    "$OUT_DIR" \
    "$ONION_ENTRY_SIZE" \
    --anchor "$OUT_DIR/delta_anchor.bin"

remove_roots_only_files \
    "$OUT_DIR/onion_index.bin" \
    "$OUT_DIR/onion_index_bins.bin" \
    "$OUT_DIR/onion_index_meta.bin"

onion_merkle_args=(
    "$BIN" build-onion-merkle
    "$OUT_DIR/onion_index_bin_hashes.bin"
    "$OUT_DIR/onion_data_bin_hashes.bin"
    "$OUT_DIR"
    "$ONION_ENTRY_SIZE"
)
if is_truthy "$ROOTS_ONLY"; then
    onion_merkle_args+=(--root-only)
fi
run_step 12-build-onion-merkle "${onion_merkle_args[@]}"

remove_roots_only_files \
    "$OUT_DIR/delta_grouped.bin" \
    "$OUT_DIR/onion_index_bin_hashes.bin" \
    "$OUT_DIR/onion_data_bin_hashes.bin" \
    "$OUT_DIR/merkle_onion_tree_tops.bin" \
    "$OUT_DIR/merkle_onion_roots.bin" \
    "$OUT_DIR/merkle_onion_sib_rows_index.bin" \
    "$OUT_DIR/merkle_onion_sib_rows_data.bin"

index_bins=$(kv "$LOG_DIR/06-build-index-cuckoo.out" "bins_per_table")
chunk_bins=$(kv "$LOG_DIR/07-build-chunk-cuckoo.out" "bins_per_table")
[[ -n "$index_bins" ]] || fail "could not parse index bins from 06-build-index-cuckoo.out"
[[ -n "$chunk_bins" ]] || fail "could not parse chunk bins from 07-build-chunk-cuckoo.out"

run_step 13-build-delta-root-bundle-payload \
    "$BIN" build-delta-root-bundle-payload \
    "$OUT_DIR" \
    "$NETWORK_MAGIC" \
    "$OUT_DIR/delta_anchor.bin" \
    "$FROM_EXPECTED_MUHASH" \
    "$TO_EXPECTED_MUHASH" \
    "$index_bins" \
    "$chunk_bins" \
    "$ONION_ENTRY_SIZE" \
    "$ISSUED_AT" \
    "$OUT_DIR/root-bundle-payload.bin"

if [[ -n "${BUILDER_KEY:-}" ]]; then
    [[ -f "$BUILDER_KEY" ]] || fail "BUILDER_KEY does not exist: $BUILDER_KEY"
    run_step 14-sign-root-bundle \
        "$BIN" sign-root-bundle \
        "$OUT_DIR/root-bundle-payload.bin" \
        "$BUILDER_KEY" \
        "$OUT_DIR/signed-root-bundle.bin"

    signer_pubkey=$(kv "$LOG_DIR/14-sign-root-bundle.out" "signer_pubkey")
    [[ -n "$signer_pubkey" ]] || fail "could not parse signer_pubkey"
    BUNDLE_THRESHOLD=${BUNDLE_THRESHOLD:-1}
    if [[ -n "${TRUSTED_PUBKEYS:-}" ]]; then
        read -r -a trusted_pubkeys <<< "$TRUSTED_PUBKEYS"
    else
        trusted_pubkeys=("$signer_pubkey")
    fi
    run_step 15-verify-root-bundle \
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
    run_step 16-write-build-receipt \
        "$BIN" write-build-receipt \
        "$OUT_DIR/signed-root-bundle.bin" \
        "$TO_SNAPSHOT" \
        "$CORE_VERSION" \
        "$OUT_DIR/build-receipt.txt"
fi

if is_truthy "$STAGE_SERVER_DB"; then
    stage_server_db "$OUT_DIR" "$SERVER_DB_DIR"
    printf 'server_db_dir=%s\n' "$SERVER_DB_DIR" | tee -a "$SUMMARY"
    printf 'server_db_manifest=%s\n' "$SERVER_DB_DIR/MANIFEST.toml" | tee -a "$SUMMARY"
    printf 'server_db_manifest_sha256=%s\n' "$(hash_one "$SERVER_DB_DIR/MANIFEST.toml")" | tee -a "$SUMMARY"
elif is_truthy "$ROOTS_ONLY"; then
    write_roots_only_manifest "$OUT_DIR" "$SERVER_DB_DIR"
    printf 'server_db_dir=%s\n' "$SERVER_DB_DIR" | tee -a "$SUMMARY"
    printf 'server_db_manifest=%s\n' "$SERVER_DB_DIR/MANIFEST.toml" | tee -a "$SUMMARY"
    printf 'server_db_manifest_kind=delta-roots-only\n' | tee -a "$SUMMARY"
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

if is_truthy "$WRITE_BUILD_EVIDENCE"; then
    run_step 17-write-build-evidence \
        "$BIN" write-build-evidence \
        "$OUT_DIR" \
        "$TO_SNAPSHOT" \
        "$CORE_VERSION" \
        "$BUILDER_GIT_COMMIT" \
        "$BIN" \
        "$TEE_PLATFORM" \
        "$TEE_IMAGE_MEASUREMENT" \
        "$OUT_DIR/build-evidence.bin"

    run_step 18-write-tee-report-data \
        "$BIN" write-tee-report-data \
        "$OUT_DIR/build-evidence.bin" \
        "$OUT_DIR/build-evidence.report-data"

    if is_truthy "$EMIT_SEV_SNP_QUOTE"; then
        run_step 19-emit-sev-snp-quote \
            "$BIN" emit-sev-snp-quote \
            "$OUT_DIR/build-evidence.bin" \
            "$OUT_DIR/build-evidence.sev-snp-report.bin" \
            "$OUT_DIR/build-evidence.report-data"
    fi
fi

bucket_root=$(kv "$LOG_DIR/08-build-bucket-merkle.out" "super_root")
onion_root=$(kv "$LOG_DIR/12-build-onion-merkle.out" "super_root")
payload_sha256=$(kv "$LOG_DIR/13-build-delta-root-bundle-payload.out" "payload_sha256")
evidence_file_sha256=
evidence_digest=
report_data=
sev_snp_report_sha256=
if [[ -f "$LOG_DIR/17-write-build-evidence.out" ]]; then
    evidence_file_sha256=$(kv "$LOG_DIR/17-write-build-evidence.out" "evidence_file_sha256")
    evidence_digest=$(kv "$LOG_DIR/17-write-build-evidence.out" "evidence_digest")
fi
if [[ -f "$LOG_DIR/18-write-tee-report-data.out" ]]; then
    report_data=$(kv "$LOG_DIR/18-write-tee-report-data.out" "report_data")
fi
if [[ -f "$LOG_DIR/19-emit-sev-snp-quote.out" ]]; then
    sev_snp_report_sha256=$(kv "$LOG_DIR/19-emit-sev-snp-quote.out" "sev_snp_report_sha256")
fi

{
    printf 'status=ok\n'
    printf 'out_dir=%s\n' "$OUT_DIR"
    printf 'roots_only=%s\n' "$ROOTS_ONLY"
    printf 'from_muhash=%s\n' "$FROM_EXPECTED_MUHASH"
    printf 'to_muhash=%s\n' "$TO_EXPECTED_MUHASH"
    printf 'from_anchor_height=%s\n' "$FROM_ANCHOR_HEIGHT"
    printf 'to_anchor_height=%s\n' "$TO_ANCHOR_HEIGHT"
    printf 'index_bins_per_table=%s\n' "$index_bins"
    printf 'chunk_bins_per_table=%s\n' "$chunk_bins"
    printf 'bucket_super_root=%s\n' "$bucket_root"
    printf 'onion_super_root=%s\n' "$onion_root"
    printf 'payload_sha256=%s\n' "$payload_sha256"
    if [[ -n "$evidence_digest" ]]; then
        printf 'build_evidence=%s\n' "$OUT_DIR/build-evidence.bin"
        printf 'build_evidence_file_sha256=%s\n' "$evidence_file_sha256"
        printf 'build_evidence_digest=%s\n' "$evidence_digest"
    fi
    if [[ -n "$report_data" ]]; then
        printf 'build_evidence_report_data=%s\n' "$report_data"
    fi
    if [[ -n "$sev_snp_report_sha256" ]]; then
        printf 'build_evidence_sev_snp_report=%s\n' "$OUT_DIR/build-evidence.sev-snp-report.bin"
        printf 'build_evidence_sev_snp_report_sha256=%s\n' "$sev_snp_report_sha256"
    fi
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
