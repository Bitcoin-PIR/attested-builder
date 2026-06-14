#!/usr/bin/env bash
# Local wrapper for the owner's mainnet anchor snapshot captured at height 953383.
#
# This intentionally writes to a fresh timestamped directory by default. It
# never deletes or overwrites existing files under /Volumes/Bitcoin.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

export SNAPSHOT=${SNAPSHOT:-"/Volumes/Bitcoin/data/archive/txoutset_953383.dat"}
export EXPECTED_MUHASH=${EXPECTED_MUHASH:-"adbbcf0147d6a651cae435bece956566c091a3eaa45a8ddd070bbf437fbe8880"}
export NETWORK_MAGIC=${NETWORK_MAGIC:-"f9beb4d9"}
export ANCHOR_HEIGHT=${ANCHOR_HEIGHT:-"953383"}
export CORE_VERSION=${CORE_VERSION:-"Bitcoin Core v31.0.0"}
export ONION_ENTRY_SIZE=${ONION_ENTRY_SIZE:-"3328"}
export PARTITIONS=${PARTITIONS:-"4"}

# Keep the root payload byte-stable across builders unless the operator
# explicitly coordinates a production issued-at value.
export ISSUED_AT=${ISSUED_AT:-"0"}

export OUT_DIR=${OUT_DIR:-"/Volumes/Bitcoin/data/attested-builder/mainnet_953383_$(date -u +%Y%m%dT%H%M%SZ)"}

exec "$SCRIPT_DIR/build-snapshot-database.sh" "$@"
