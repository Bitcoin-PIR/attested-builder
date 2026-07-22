//! Deterministic build-pipeline stages for attested BitcoinPIR roots.
//!
//! This crate starts by splitting the old `build/src/build_utxo_chunks.rs`
//! binaries into callable library functions. The output format is compatible
//! with the legacy DPF/HarmonyPIR stages, but group write order is made
//! deterministic by sorting script hashes inside each partition before
//! writing.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub const FLAT_UTXO_ENTRY_SIZE: usize = utxosnapshot::FLAT_UTXO_ENTRY_SIZE as usize;
pub const SCRIPT_HASH_SIZE: usize = 20;
pub const TXID_SIZE: usize = 32;
pub const CHUNK_SIZE: usize = 40;
pub const DUST_THRESHOLD_SATS: u64 = 576;
pub const MAX_UTXOS_PER_SPK: usize = 100;
pub const TOP_N: usize = 100;
pub const INDEX_RECORD_SIZE: usize = 20 + 4 + 1;

pub const UTXO_CHUNKS_FILENAME: &str = "utxo_chunks_nodust.bin";
pub const UTXO_CHUNKS_INDEX_FILENAME: &str = "utxo_chunks_index_nodust.bin";
pub const TOP100_FILENAME: &str = "top100_addresses.bin";
pub const WHALES_FILENAME: &str = "whale_addresses.txt";
pub const INDEX_CUCKOO_FILENAME: &str = "batch_pir_cuckoo.bin";
pub const CHUNK_CUCKOO_FILENAME: &str = "chunk_pir_cuckoo.bin";
pub const DELTA_GROUPED_FILENAME: &str = "delta_grouped.bin";
pub const DELTA_CHUNKS_FILENAME: &str = "delta_chunks.bin";
pub const DELTA_INDEX_FILENAME: &str = "delta_index.bin";

pub const INDEX_K: usize = 75;
pub const INDEX_PBC_HASHES: usize = 3;
pub const INDEX_SLOTS_PER_BIN: usize = 4;
pub const INDEX_CUCKOO_HASHES: usize = 2;
pub const INDEX_SLOT_SIZE: usize = 13;
pub const INDEX_CUCKOO_HEADER_SIZE: usize = 40;
pub const INDEX_CUCKOO_MAGIC: u64 = 0xBA7C_C000_C000_0004;
pub const LEGACY_INDEX_MASTER_SEED: u64 = 0x71a2ef38b4c90d15;
pub const LEGACY_INDEX_TAG_SEED: u64 = 0xd4e5f6a7b8c91023;

pub const CHUNK_K: usize = 80;
pub const CHUNK_PBC_HASHES: usize = 3;
pub const CHUNK_SLOTS_PER_BIN: usize = 3;
pub const CHUNK_CUCKOO_HASHES: usize = 2;
pub const CHUNK_SLOT_SIZE: usize = 4 + CHUNK_SIZE;
pub const CHUNK_CUCKOO_HEADER_SIZE: usize = 32;
pub const CHUNK_CUCKOO_MAGIC: u64 = 0xBA7C_C000_C000_0002;
pub const LEGACY_CHUNK_MASTER_SEED: u64 = 0xa3f7c2d918e4b065;
pub const CHAIN_ANCHOR_BYTES: usize = 36;
pub const ANCHOR_MAGIC_SNAPSHOT_XOR: u64 = 0x0000_0001_0000_0000;
pub const DELTA_ANCHOR_BYTES: usize = CHAIN_ANCHOR_BYTES * 2;
pub const ANCHOR_MAGIC_DELTA_XOR: u64 = 0x0000_0002_0000_0000;

pub const MERKLE_ARITY: usize = 8;
pub const MERKLE_HASH_SIZE: usize = 32;
pub const MERKLE_SIB_ROW_SIZE: usize = MERKLE_ARITY * MERKLE_HASH_SIZE;
pub const MERKLE_TREE_TOP_THRESHOLD: usize = 1024;
pub const MERKLE_BUCKET_TREE_TOPS_FILENAME: &str = "merkle_bucket_tree_tops.bin";
pub const MERKLE_BUCKET_ROOTS_FILENAME: &str = "merkle_bucket_roots.bin";
pub const MERKLE_BUCKET_ROOT_FILENAME: &str = "merkle_bucket_root.bin";

pub const ONION_PACKED_ENTRIES_FILENAME: &str = "onion_packed_entries.bin";
pub const ONION_INDEX_FILENAME: &str = "onion_index.bin";
pub const ONION_CHUNK_CUCKOO_FILENAME: &str = "onion_chunk_cuckoo.bin";
pub const ONION_DATA_BIN_HASHES_FILENAME: &str = "onion_data_bin_hashes.bin";
pub const ONION_INDEX_BINS_FILENAME: &str = "onion_index_bins.bin";
pub const ONION_INDEX_META_FILENAME: &str = "onion_index_meta.bin";
pub const ONION_INDEX_BIN_HASHES_FILENAME: &str = "onion_index_bin_hashes.bin";
pub const ONION_INDEX_RECORD_SIZE: usize = 20 + 4 + 2 + 1;
pub const DEFAULT_ONION_ENTRY_SIZE: usize = 3_328;
pub const ONION_WHALE_FLAG: u8 = 0x40;
pub const ONION_INDEX_SLOT_SIZE: usize = 8 + 4 + 2 + 1;
pub const ONION_INDEX_CUCKOO_HASHES: usize = 2;
pub const ONION_INDEX_META_HEADER_SIZE: usize = 44;
pub const ONION_INDEX_META_MAGIC: u64 = 0xBA7C_0010_0000_0002;
pub const ONION_DATA_CUCKOO_HASHES: usize = 6;
pub const ONION_DATA_CUCKOO_HEADER_SIZE: usize = 36;
pub const ONION_DATA_CUCKOO_MAGIC: u64 = 0xBA7C_0010_0000_0001;
pub const ONION_MERKLE_TREE_TOPS_FILENAME: &str = "merkle_onion_tree_tops.bin";
pub const ONION_MERKLE_ROOTS_FILENAME: &str = "merkle_onion_roots.bin";
pub const ONION_MERKLE_ROOT_FILENAME: &str = "merkle_onion_root.bin";
pub const ONION_MERKLE_SIB_ROWS_INDEX_FILENAME: &str = "merkle_onion_sib_rows_index.bin";
pub const ONION_MERKLE_SIB_ROWS_DATA_FILENAME: &str = "merkle_onion_sib_rows_data.bin";
pub const ONION_MERKLE_CACHE_FROM_LEVEL: usize = 1;
pub const ONION_MERKLE_SIB_ROWS_INDEX_MAGIC: u64 = 0xBA7C_0E52_0000_0000;
pub const ONION_MERKLE_SIB_ROWS_DATA_MAGIC: u64 = 0xBA7C_0E52_0000_0001;
pub const ONION_MERKLE_SIB_ROWS_HEADER_SIZE: usize = 24;

const ZERO_PAD: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];
const ZERO_HASH: Hash256 = [0u8; MERKLE_HASH_SIZE];
const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 10_000;
const EMPTY: u32 = u32::MAX;
const GOLDEN_RATIO: u64 = 0x9e3779b97f4a7c15;
const CUCKOO_KEY_MIX: u64 = 0x517cc1b727220a95;

type Hash256 = [u8; MERKLE_HASH_SIZE];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderAnchorBytes {
    Snapshot([u8; CHAIN_ANCHOR_BYTES]),
    Delta([u8; DELTA_ANCHOR_BYTES]),
}

impl HeaderAnchorBytes {
    fn len(&self) -> usize {
        match self {
            HeaderAnchorBytes::Snapshot(_) => CHAIN_ANCHOR_BYTES,
            HeaderAnchorBytes::Delta(_) => DELTA_ANCHOR_BYTES,
        }
    }

    fn magic(&self, legacy_magic: u64) -> u64 {
        match self {
            HeaderAnchorBytes::Snapshot(_) => legacy_magic ^ ANCHOR_MAGIC_SNAPSHOT_XOR,
            HeaderAnchorBytes::Delta(_) => legacy_magic ^ ANCHOR_MAGIC_DELTA_XOR,
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            HeaderAnchorBytes::Snapshot(bytes) => writer.write_all(bytes),
            HeaderAnchorBytes::Delta(bytes) => writer.write_all(bytes),
        }
    }
}

#[derive(Debug)]
pub enum PipelineError {
    Io(io::Error),
    InvalidFlatUtxoSize {
        bytes: u64,
    },
    InvalidPartitions(usize),
    OutputExists(PathBuf),
    ChunkIdOverflow(u64),
    ChunkCountOverflow {
        script_hash: [u8; 20],
        chunks: usize,
    },
    InvalidOnionEntrySize(usize),
    OnionEntryIdOverflow(u64),
    OnionSpanOverflow {
        script_hash: [u8; 20],
        bytes: usize,
        entries: usize,
    },
    InvalidOnionPackedSize {
        bytes: u64,
        entry_size: usize,
    },
    InvalidOnionIndexEntrySize {
        entry_size: usize,
        slot_size: usize,
    },
    InvalidOnionMerkleArity {
        entry_size: usize,
    },
    InvalidBinHashes {
        path: PathBuf,
        reason: String,
    },
    InvalidIndexSize {
        bytes: u64,
    },
    InvalidChunksSize {
        bytes: u64,
    },
    InvalidDeltaFormat {
        path: PathBuf,
        reason: String,
    },
    CuckooInsertFailed {
        group_id: usize,
        local_index: usize,
    },
    InvalidCuckooHeader {
        path: PathBuf,
        reason: String,
    },
    InvalidCuckooBody {
        path: PathBuf,
        expected_bytes: u64,
        actual_bytes: u64,
    },
    InvalidExistingOnionLayout(String),
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipelineError::Io(e) => write!(f, "I/O error: {e}"),
            PipelineError::InvalidFlatUtxoSize { bytes } => {
                write!(
                    f,
                    "flat UTXO file size {bytes} is not divisible by {FLAT_UTXO_ENTRY_SIZE}"
                )
            }
            PipelineError::InvalidPartitions(n) => write!(f, "partitions must be >= 1, got {n}"),
            PipelineError::OutputExists(path) => {
                write!(f, "output already exists: {}", path.display())
            }
            PipelineError::ChunkIdOverflow(id) => write!(f, "chunk id overflows u32: {id}"),
            PipelineError::ChunkCountOverflow {
                script_hash,
                chunks,
            } => write!(
                f,
                "serialized group {} needs {chunks} chunks, exceeds u8",
                hex::encode(script_hash)
            ),
            PipelineError::InvalidOnionEntrySize(size) => write!(
                f,
                "onion entry size must be in 1..={}; got {size}",
                u16::MAX
            ),
            PipelineError::OnionEntryIdOverflow(id) => {
                write!(f, "onion entry id overflows u32: {id}")
            }
            PipelineError::OnionSpanOverflow {
                script_hash,
                bytes,
                entries,
            } => write!(
                f,
                "serialized onion group {} is {bytes} bytes and needs {entries} entries, exceeds u8",
                hex::encode(script_hash)
            ),
            PipelineError::InvalidOnionPackedSize { bytes, entry_size } => write!(
                f,
                "packed Onion file size {bytes} is not divisible by entry size {entry_size}"
            ),
            PipelineError::InvalidOnionIndexEntrySize {
                entry_size,
                slot_size,
            } => write!(
                f,
                "onion index entry size {entry_size} cannot fit one {slot_size}-byte index slot"
            ),
            PipelineError::InvalidOnionMerkleArity { entry_size } => write!(
                f,
                "onion Merkle entry size {entry_size} must be a nonzero multiple of {MERKLE_HASH_SIZE}"
            ),
            PipelineError::InvalidBinHashes { path, reason } => {
                write!(f, "invalid bin hashes {}: {reason}", path.display())
            }
            PipelineError::InvalidIndexSize { bytes } => {
                write!(
                    f,
                    "index file size {bytes} is not divisible by {INDEX_RECORD_SIZE}"
                )
            }
            PipelineError::InvalidChunksSize { bytes } => {
                write!(
                    f,
                    "chunks file size {bytes} is not divisible by {CHUNK_SIZE}"
                )
            }
            PipelineError::InvalidDeltaFormat { path, reason } => {
                write!(f, "invalid delta file {}: {reason}", path.display())
            }
            PipelineError::CuckooInsertFailed {
                group_id,
                local_index,
            } => write!(
                f,
                "cuckoo insertion failed for local entry {local_index} in group {group_id}"
            ),
            PipelineError::InvalidCuckooHeader { path, reason } => {
                write!(f, "invalid cuckoo header {}: {reason}", path.display())
            }
            PipelineError::InvalidCuckooBody {
                path,
                expected_bytes,
                actual_bytes,
            } => write!(
                f,
                "invalid cuckoo body {}: expected {expected_bytes} bytes, got {actual_bytes}",
                path.display()
            ),
            PipelineError::InvalidExistingOnionLayout(reason) => {
                write!(f, "invalid existing OnionPIR layout: {reason}")
            }
        }
    }
}

impl std::error::Error for PipelineError {}

impl From<io::Error> for PipelineError {
    fn from(e: io::Error) -> Self {
        PipelineError::Io(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoChunkBuildOptions {
    pub partitions: usize,
    pub dust_threshold_sats: u64,
    pub max_utxos_per_spk: usize,
}

impl Default for UtxoChunkBuildOptions {
    fn default() -> Self {
        Self {
            partitions: 4,
            dust_threshold_sats: DUST_THRESHOLD_SATS,
            max_utxos_per_spk: MAX_UTXOS_PER_SPK,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoChunkBuildReport {
    pub input_entries: u64,
    pub dust_utxos_skipped: u64,
    pub whale_spks_excluded: u64,
    pub groups_written: u64,
    pub index_entries: u64,
    pub chunks_written: u64,
    pub chunks_file_bytes: u64,
    pub index_file_bytes: u64,
    pub data_bytes: u64,
    pub padding_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionPackOptions {
    pub partitions: usize,
    pub dust_threshold_sats: u64,
    pub max_utxos_per_spk: usize,
    pub entry_size: usize,
}

impl Default for OnionPackOptions {
    fn default() -> Self {
        Self {
            partitions: 4,
            dust_threshold_sats: DUST_THRESHOLD_SATS,
            max_utxos_per_spk: MAX_UTXOS_PER_SPK,
            entry_size: DEFAULT_ONION_ENTRY_SIZE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionPackReport {
    pub input_entries: u64,
    pub dust_utxos_skipped: u64,
    pub whale_spks_excluded: u64,
    pub groups_packed: u64,
    pub onion_entries: u64,
    pub packed_file_bytes: u64,
    pub index_file_bytes: u64,
    pub data_bytes: u64,
    pub padding_bytes: u64,
    pub max_serialized_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionDataCuckooOptions {
    pub master_seed: u64,
    pub snapshot_anchor: Option<[u8; CHAIN_ANCHOR_BYTES]>,
    pub delta_anchor: Option<[u8; DELTA_ANCHOR_BYTES]>,
    pub entry_size: usize,
}

impl Default for OnionDataCuckooOptions {
    fn default() -> Self {
        Self {
            master_seed: LEGACY_CHUNK_MASTER_SEED,
            snapshot_anchor: None,
            delta_anchor: None,
            entry_size: DEFAULT_ONION_ENTRY_SIZE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionDataCuckooBuildReport {
    pub packed_entries: u64,
    pub bins_per_table: u32,
    pub output_bytes: u64,
    pub bin_hashes_file_bytes: u64,
    pub total_placements: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionIndexCuckooOptions {
    pub master_seed: u64,
    pub tag_seed: u64,
    pub snapshot_anchor: Option<[u8; CHAIN_ANCHOR_BYTES]>,
    pub delta_anchor: Option<[u8; DELTA_ANCHOR_BYTES]>,
    pub entry_size: usize,
}

impl Default for OnionIndexCuckooOptions {
    fn default() -> Self {
        Self {
            master_seed: LEGACY_INDEX_MASTER_SEED,
            tag_seed: LEGACY_INDEX_TAG_SEED,
            snapshot_anchor: None,
            delta_anchor: None,
            entry_size: DEFAULT_ONION_ENTRY_SIZE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionIndexCuckooBuildReport {
    pub index_entries: u64,
    pub non_whale_entries: u64,
    pub bins_per_table: u32,
    pub slots_per_bin: u16,
    pub raw_bins_file_bytes: u64,
    pub meta_file_bytes: u64,
    pub bin_hashes_file_bytes: u64,
    pub total_placements: u64,
}

/// Layout recovered from, and cryptographically checked against, a completed
/// OnionPIR artifact directory. This is intentionally derived from final
/// files rather than build logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingOnionLayoutV2 {
    pub total_packed_entries: u32,
    pub entry_size: u32,
    pub index_bins_per_table: u32,
    pub chunk_bins_per_table: u32,
    pub index_master_seed: u64,
    pub index_tag_seed: u64,
    pub chunk_master_seed: u64,
    pub anchor_bytes: Vec<u8>,
    pub onion_super_root: [u8; MERKLE_HASH_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionMerkleOptions {
    pub entry_size: usize,
    pub root_only: bool,
}

impl Default for OnionMerkleOptions {
    fn default() -> Self {
        Self {
            entry_size: DEFAULT_ONION_ENTRY_SIZE,
            root_only: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionMerkleBuildReport {
    pub index_k: u32,
    pub data_k: u32,
    pub index_bins_per_table: u32,
    pub data_bins_per_table: u32,
    pub arity: u16,
    pub tree_count: u32,
    pub index_sibling_rows_per_group: u32,
    pub data_sibling_rows_per_group: u32,
    pub tree_tops_file_bytes: u64,
    pub roots_file_bytes: u64,
    pub index_sibling_rows_file_bytes: u64,
    pub data_sibling_rows_file_bytes: u64,
    pub super_root: [u8; MERKLE_HASH_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexCuckooOptions {
    pub master_seed: u64,
    pub tag_seed: u64,
    pub snapshot_anchor: Option<[u8; CHAIN_ANCHOR_BYTES]>,
    pub delta_anchor: Option<[u8; DELTA_ANCHOR_BYTES]>,
}

impl Default for IndexCuckooOptions {
    fn default() -> Self {
        Self {
            master_seed: LEGACY_INDEX_MASTER_SEED,
            tag_seed: LEGACY_INDEX_TAG_SEED,
            snapshot_anchor: None,
            delta_anchor: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexCuckooBuildReport {
    pub index_entries: u64,
    pub bins_per_table: u32,
    pub slots_per_table: u64,
    pub output_bytes: u64,
    pub total_placements: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkCuckooOptions {
    pub master_seed: u64,
    pub snapshot_anchor: Option<[u8; CHAIN_ANCHOR_BYTES]>,
    pub delta_anchor: Option<[u8; DELTA_ANCHOR_BYTES]>,
}

impl Default for ChunkCuckooOptions {
    fn default() -> Self {
        Self {
            master_seed: LEGACY_CHUNK_MASTER_SEED,
            snapshot_anchor: None,
            delta_anchor: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkCuckooBuildReport {
    pub chunks: u64,
    pub bins_per_table: u32,
    pub slots_per_table: u64,
    pub output_bytes: u64,
    pub total_placements: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaBuildOptions {
    pub dust_threshold_sats: u64,
}

impl Default for DeltaBuildOptions {
    fn default() -> Self {
        Self {
            dust_threshold_sats: DUST_THRESHOLD_SATS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaBuildReport {
    pub from_entries: u64,
    pub to_entries: u64,
    pub unchanged_entries: u64,
    pub spent_entries: u64,
    pub created_entries: u64,
    pub dust_created_skipped: u64,
    pub scripts_changed: u64,
    pub grouped_file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaChunkBuildReport {
    pub scripts: u64,
    pub chunks_written: u64,
    pub index_entries: u64,
    pub skipped_too_large: u64,
    pub chunks_file_bytes: u64,
    pub index_file_bytes: u64,
    pub data_bytes: u64,
    pub padding_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaOnionPackReport {
    pub scripts: u64,
    pub groups_packed: u64,
    pub whale_spks_excluded: u64,
    pub onion_entries: u64,
    pub packed_file_bytes: u64,
    pub index_file_bytes: u64,
    pub data_bytes: u64,
    pub padding_bytes: u64,
    pub max_serialized_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketMerkleBuildReport {
    pub index_bins_per_table: u32,
    pub chunk_bins_per_table: u32,
    pub index_sibling_levels: Vec<u32>,
    pub chunk_sibling_levels: Vec<u32>,
    pub tree_count: u32,
    pub tree_tops_file_bytes: u64,
    pub roots_file_bytes: u64,
    pub super_root: [u8; MERKLE_HASH_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BucketMerkleOptions {
    pub root_only: bool,
}

#[derive(Debug, Clone)]
struct FlatEntry {
    script_hash: [u8; SCRIPT_HASH_SIZE],
    txid: [u8; TXID_SIZE],
    vout: u32,
    amount: u64,
    height: u32,
}

#[derive(Clone)]
struct ShortenedEntry {
    txid: [u8; TXID_SIZE],
    vout: u32,
    amount: u64,
    height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct OutPointKey {
    txid: [u8; TXID_SIZE],
    vout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpentRef {
    txid: [u8; TXID_SIZE],
    vout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NewUtxo {
    txid: [u8; TXID_SIZE],
    vout: u32,
    amount: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ScriptDelta {
    spent: Vec<SpentRef>,
    new_utxos: Vec<NewUtxo>,
}

type TopEntry = (usize, [u8; SCRIPT_HASH_SIZE], [u8; TXID_SIZE], u32);

#[derive(Debug, Clone)]
struct CuckooTableMeta {
    bins_per_table: usize,
    header_size: usize,
}

#[derive(Debug, Clone)]
struct PerGroupTree {
    levels: Vec<Vec<Hash256>>,
    root: Hash256,
}

pub fn build_utxo_chunks(
    flat_utxo_path: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    options: &UtxoChunkBuildOptions,
) -> Result<UtxoChunkBuildReport, PipelineError> {
    if options.partitions == 0 {
        return Err(PipelineError::InvalidPartitions(options.partitions));
    }

    let flat_utxo_path = flat_utxo_path.as_ref();
    let out_dir = out_dir.as_ref();
    std::fs::create_dir_all(out_dir)?;

    let chunks_path = out_dir.join(UTXO_CHUNKS_FILENAME);
    let index_path = out_dir.join(UTXO_CHUNKS_INDEX_FILENAME);
    let top_path = out_dir.join(TOP100_FILENAME);
    let whales_path = out_dir.join(WHALES_FILENAME);
    for path in [&chunks_path, &index_path, &top_path, &whales_path] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
    }

    let chunks_tmp = temp_path(&chunks_path);
    let index_tmp = temp_path(&index_path);
    let top_tmp = temp_path(&top_path);
    let whales_tmp = temp_path(&whales_path);
    for path in [&chunks_tmp, &index_tmp, &top_tmp, &whales_tmp] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
    }

    let result = build_utxo_chunks_inner(
        flat_utxo_path,
        options,
        &chunks_tmp,
        &index_tmp,
        &top_tmp,
        &whales_tmp,
    );

    match result {
        Ok(report) => {
            std::fs::rename(&chunks_tmp, &chunks_path)?;
            std::fs::rename(&index_tmp, &index_path)?;
            std::fs::rename(&top_tmp, &top_path)?;
            std::fs::rename(&whales_tmp, &whales_path)?;
            Ok(report)
        }
        Err(e) => {
            for path in [&chunks_tmp, &index_tmp, &top_tmp, &whales_tmp] {
                let _ = std::fs::remove_file(path);
            }
            Err(e)
        }
    }
}

pub fn build_onion_pack(
    flat_utxo_path: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    options: &OnionPackOptions,
) -> Result<OnionPackReport, PipelineError> {
    if options.partitions == 0 {
        return Err(PipelineError::InvalidPartitions(options.partitions));
    }
    validate_onion_entry_size(options.entry_size)?;

    let flat_utxo_path = flat_utxo_path.as_ref();
    let out_dir = out_dir.as_ref();
    std::fs::create_dir_all(out_dir)?;

    let packed_path = out_dir.join(ONION_PACKED_ENTRIES_FILENAME);
    let index_path = out_dir.join(ONION_INDEX_FILENAME);
    for path in [&packed_path, &index_path] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
    }

    let packed_tmp = temp_path(&packed_path);
    let index_tmp = temp_path(&index_path);
    for path in [&packed_tmp, &index_tmp] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
    }

    let result = build_onion_pack_inner(flat_utxo_path, options, &packed_tmp, &index_tmp);
    match result {
        Ok(report) => {
            std::fs::rename(&packed_tmp, &packed_path)?;
            std::fs::rename(&index_tmp, &index_path)?;
            Ok(report)
        }
        Err(e) => {
            for path in [&packed_tmp, &index_tmp] {
                let _ = std::fs::remove_file(path);
            }
            Err(e)
        }
    }
}

pub fn build_onion_data_cuckoo(
    packed_path: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    options: &OnionDataCuckooOptions,
) -> Result<OnionDataCuckooBuildReport, PipelineError> {
    validate_onion_entry_size(options.entry_size)?;

    let packed_path = packed_path.as_ref();
    let out_dir = out_dir.as_ref();
    std::fs::create_dir_all(out_dir)?;

    let cuckoo_path = out_dir.join(ONION_CHUNK_CUCKOO_FILENAME);
    let bin_hashes_path = out_dir.join(ONION_DATA_BIN_HASHES_FILENAME);
    for path in [&cuckoo_path, &bin_hashes_path] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
    }

    let cuckoo_tmp = temp_path(&cuckoo_path);
    let bin_hashes_tmp = temp_path(&bin_hashes_path);
    for path in [&cuckoo_tmp, &bin_hashes_tmp] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
    }

    let result = build_onion_data_cuckoo_inner(packed_path, options, &cuckoo_tmp, &bin_hashes_tmp);
    match result {
        Ok(report) => {
            std::fs::rename(&cuckoo_tmp, &cuckoo_path)?;
            std::fs::rename(&bin_hashes_tmp, &bin_hashes_path)?;
            Ok(report)
        }
        Err(e) => {
            for path in [&cuckoo_tmp, &bin_hashes_tmp] {
                let _ = std::fs::remove_file(path);
            }
            Err(e)
        }
    }
}

pub fn build_onion_index_cuckoo(
    index_path: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    options: &OnionIndexCuckooOptions,
) -> Result<OnionIndexCuckooBuildReport, PipelineError> {
    validate_onion_entry_size(options.entry_size)?;
    onion_index_slots_per_bin(options.entry_size)?;

    let index_path = index_path.as_ref();
    let out_dir = out_dir.as_ref();
    std::fs::create_dir_all(out_dir)?;

    let bins_path = out_dir.join(ONION_INDEX_BINS_FILENAME);
    let meta_path = out_dir.join(ONION_INDEX_META_FILENAME);
    let bin_hashes_path = out_dir.join(ONION_INDEX_BIN_HASHES_FILENAME);
    for path in [&bins_path, &meta_path, &bin_hashes_path] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
    }

    let bins_tmp = temp_path(&bins_path);
    let meta_tmp = temp_path(&meta_path);
    let bin_hashes_tmp = temp_path(&bin_hashes_path);
    for path in [&bins_tmp, &meta_tmp, &bin_hashes_tmp] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
    }

    let result =
        build_onion_index_cuckoo_inner(index_path, options, &bins_tmp, &meta_tmp, &bin_hashes_tmp);
    match result {
        Ok(report) => {
            std::fs::rename(&bins_tmp, &bins_path)?;
            std::fs::rename(&meta_tmp, &meta_path)?;
            std::fs::rename(&bin_hashes_tmp, &bin_hashes_path)?;
            Ok(report)
        }
        Err(e) => {
            for path in [&bins_tmp, &meta_tmp, &bin_hashes_tmp] {
                let _ = std::fs::remove_file(path);
            }
            Err(e)
        }
    }
}

pub fn build_onion_merkle(
    index_bin_hashes_path: impl AsRef<Path>,
    data_bin_hashes_path: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    options: &OnionMerkleOptions,
) -> Result<OnionMerkleBuildReport, PipelineError> {
    validate_onion_entry_size(options.entry_size)?;
    onion_merkle_arity(options.entry_size)?;

    let index_bin_hashes_path = index_bin_hashes_path.as_ref();
    let data_bin_hashes_path = data_bin_hashes_path.as_ref();
    let out_dir = out_dir.as_ref();
    std::fs::create_dir_all(out_dir)?;

    let root_path = out_dir.join(ONION_MERKLE_ROOT_FILENAME);
    let mut output_paths = vec![root_path.clone()];
    let tree_tops_path = out_dir.join(ONION_MERKLE_TREE_TOPS_FILENAME);
    let roots_path = out_dir.join(ONION_MERKLE_ROOTS_FILENAME);
    let index_sibling_rows_path = out_dir.join(ONION_MERKLE_SIB_ROWS_INDEX_FILENAME);
    let data_sibling_rows_path = out_dir.join(ONION_MERKLE_SIB_ROWS_DATA_FILENAME);
    if !options.root_only {
        output_paths.extend([
            tree_tops_path.clone(),
            roots_path.clone(),
            index_sibling_rows_path.clone(),
            data_sibling_rows_path.clone(),
        ]);
    }
    for path in &output_paths {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
        let tmp = temp_path(path);
        if tmp.exists() {
            return Err(PipelineError::OutputExists(tmp));
        }
    }

    let result = build_onion_merkle_inner(
        index_bin_hashes_path,
        data_bin_hashes_path,
        options,
        &temp_path(&tree_tops_path),
        &temp_path(&roots_path),
        &temp_path(&root_path),
        &temp_path(&index_sibling_rows_path),
        &temp_path(&data_sibling_rows_path),
    );
    match result {
        Ok(report) => {
            for path in output_paths {
                std::fs::rename(temp_path(&path), path)?;
            }
            Ok(report)
        }
        Err(e) => {
            for path in output_paths {
                let _ = std::fs::remove_file(temp_path(&path));
            }
            Err(e)
        }
    }
}

pub fn build_grouped_delta_from_flat_sets(
    from_flat_utxo_path: impl AsRef<Path>,
    to_flat_utxo_path: impl AsRef<Path>,
    out_grouped_delta_path: impl AsRef<Path>,
    options: &DeltaBuildOptions,
) -> Result<DeltaBuildReport, PipelineError> {
    let from_flat_utxo_path = from_flat_utxo_path.as_ref();
    let to_flat_utxo_path = to_flat_utxo_path.as_ref();
    let out_grouped_delta_path = out_grouped_delta_path.as_ref();
    if out_grouped_delta_path.exists() {
        return Err(PipelineError::OutputExists(
            out_grouped_delta_path.to_path_buf(),
        ));
    }
    let tmp = temp_path(out_grouped_delta_path);
    if tmp.exists() {
        return Err(PipelineError::OutputExists(tmp));
    }

    let result = build_grouped_delta_from_flat_sets_inner(
        from_flat_utxo_path,
        to_flat_utxo_path,
        &tmp,
        options,
    );

    match result {
        Ok(report) => {
            std::fs::rename(&tmp, out_grouped_delta_path)?;
            Ok(report)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub fn build_delta_chunks(
    grouped_delta_path: impl AsRef<Path>,
    chunks_path: impl AsRef<Path>,
    index_path: impl AsRef<Path>,
) -> Result<DeltaChunkBuildReport, PipelineError> {
    let grouped_delta_path = grouped_delta_path.as_ref();
    let chunks_path = chunks_path.as_ref();
    let index_path = index_path.as_ref();
    for path in [chunks_path, index_path] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.to_path_buf()));
        }
    }
    let chunks_tmp = temp_path(chunks_path);
    let index_tmp = temp_path(index_path);
    for path in [&chunks_tmp, &index_tmp] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
    }

    let result = build_delta_chunks_inner(grouped_delta_path, &chunks_tmp, &index_tmp);
    match result {
        Ok(report) => {
            std::fs::rename(&chunks_tmp, chunks_path)?;
            std::fs::rename(&index_tmp, index_path)?;
            Ok(report)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&chunks_tmp);
            let _ = std::fs::remove_file(&index_tmp);
            Err(e)
        }
    }
}

pub fn build_delta_onion_pack(
    grouped_delta_path: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    options: &OnionPackOptions,
) -> Result<DeltaOnionPackReport, PipelineError> {
    validate_onion_entry_size(options.entry_size)?;

    let grouped_delta_path = grouped_delta_path.as_ref();
    let out_dir = out_dir.as_ref();
    std::fs::create_dir_all(out_dir)?;

    let packed_path = out_dir.join(ONION_PACKED_ENTRIES_FILENAME);
    let index_path = out_dir.join(ONION_INDEX_FILENAME);
    for path in [&packed_path, &index_path] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
    }
    let packed_tmp = temp_path(&packed_path);
    let index_tmp = temp_path(&index_path);
    for path in [&packed_tmp, &index_tmp] {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
    }

    let result = build_delta_onion_pack_inner(grouped_delta_path, &packed_tmp, &index_tmp, options);
    match result {
        Ok(report) => {
            std::fs::rename(&packed_tmp, packed_path)?;
            std::fs::rename(&index_tmp, index_path)?;
            Ok(report)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&packed_tmp);
            let _ = std::fs::remove_file(&index_tmp);
            Err(e)
        }
    }
}

pub fn build_index_cuckoo(
    index_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    options: &IndexCuckooOptions,
) -> Result<IndexCuckooBuildReport, PipelineError> {
    let index_path = index_path.as_ref();
    let output_path = output_path.as_ref();
    if output_path.exists() {
        return Err(PipelineError::OutputExists(output_path.to_path_buf()));
    }
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = temp_path(output_path);
    if tmp_path.exists() {
        return Err(PipelineError::OutputExists(tmp_path));
    }

    let result = build_index_cuckoo_inner(index_path, &tmp_path, options);
    match result {
        Ok(report) => {
            std::fs::rename(&tmp_path, output_path)?;
            Ok(report)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

pub fn build_chunk_cuckoo(
    chunks_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    options: &ChunkCuckooOptions,
) -> Result<ChunkCuckooBuildReport, PipelineError> {
    let chunks_path = chunks_path.as_ref();
    let output_path = output_path.as_ref();
    if output_path.exists() {
        return Err(PipelineError::OutputExists(output_path.to_path_buf()));
    }
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = temp_path(output_path);
    if tmp_path.exists() {
        return Err(PipelineError::OutputExists(tmp_path));
    }

    let result = build_chunk_cuckoo_inner(chunks_path, &tmp_path, options);
    match result {
        Ok(report) => {
            std::fs::rename(&tmp_path, output_path)?;
            Ok(report)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

pub fn build_bucket_merkle(
    index_cuckoo_path: impl AsRef<Path>,
    chunk_cuckoo_path: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
) -> Result<BucketMerkleBuildReport, PipelineError> {
    build_bucket_merkle_with_options(
        index_cuckoo_path,
        chunk_cuckoo_path,
        out_dir,
        &BucketMerkleOptions::default(),
    )
}

pub fn build_bucket_merkle_with_options(
    index_cuckoo_path: impl AsRef<Path>,
    chunk_cuckoo_path: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    options: &BucketMerkleOptions,
) -> Result<BucketMerkleBuildReport, PipelineError> {
    let index_cuckoo_path = index_cuckoo_path.as_ref();
    let chunk_cuckoo_path = chunk_cuckoo_path.as_ref();
    let out_dir = out_dir.as_ref();
    std::fs::create_dir_all(out_dir)?;

    let index_data = std::fs::read(index_cuckoo_path)?;
    let chunk_data = std::fs::read(chunk_cuckoo_path)?;
    let index_meta = parse_cuckoo_meta(
        index_cuckoo_path,
        &index_data,
        INDEX_CUCKOO_MAGIC,
        INDEX_CUCKOO_HEADER_SIZE,
        INDEX_K,
        INDEX_SLOTS_PER_BIN,
        INDEX_PBC_HASHES,
    )?;
    let chunk_meta = parse_cuckoo_meta(
        chunk_cuckoo_path,
        &chunk_data,
        CHUNK_CUCKOO_MAGIC,
        CHUNK_CUCKOO_HEADER_SIZE,
        CHUNK_K,
        CHUNK_SLOTS_PER_BIN,
        CHUNK_PBC_HASHES,
    )?;
    validate_cuckoo_body(
        index_cuckoo_path,
        index_data.len(),
        &index_meta,
        INDEX_K,
        INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE,
    )?;
    validate_cuckoo_body(
        chunk_cuckoo_path,
        chunk_data.len(),
        &chunk_meta,
        CHUNK_K,
        CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE,
    )?;

    let index_sibling_levels = compute_sibling_levels(index_meta.bins_per_table);
    let chunk_sibling_levels = compute_sibling_levels(chunk_meta.bins_per_table);
    let mut output_paths = vec![out_dir.join(MERKLE_BUCKET_ROOT_FILENAME)];
    if !options.root_only {
        output_paths.push(out_dir.join(MERKLE_BUCKET_TREE_TOPS_FILENAME));
        output_paths.push(out_dir.join(MERKLE_BUCKET_ROOTS_FILENAME));
        for level in 0..index_sibling_levels.len() {
            output_paths.push(out_dir.join(merkle_index_sibling_filename(level)));
        }
        for level in 0..chunk_sibling_levels.len() {
            output_paths.push(out_dir.join(merkle_chunk_sibling_filename(level)));
        }
    }
    for path in &output_paths {
        if path.exists() {
            return Err(PipelineError::OutputExists(path.clone()));
        }
        let tmp = temp_path(path);
        if tmp.exists() {
            return Err(PipelineError::OutputExists(tmp));
        }
    }

    let result = build_bucket_merkle_inner(
        &index_data,
        &chunk_data,
        &index_meta,
        &chunk_meta,
        out_dir,
        &index_sibling_levels,
        &chunk_sibling_levels,
        options,
    );

    match result {
        Ok(report) => {
            for path in output_paths {
                std::fs::rename(temp_path(&path), path)?;
            }
            Ok(report)
        }
        Err(e) => {
            for path in output_paths {
                let _ = std::fs::remove_file(temp_path(&path));
            }
            Err(e)
        }
    }
}

fn build_index_cuckoo_inner(
    index_path: &Path,
    output_path: &Path,
    options: &IndexCuckooOptions,
) -> Result<IndexCuckooBuildReport, PipelineError> {
    let data = std::fs::read(index_path)?;
    if data.len() as u64 % INDEX_RECORD_SIZE as u64 != 0 {
        return Err(PipelineError::InvalidIndexSize {
            bytes: data.len() as u64,
        });
    }
    let n = data.len() / INDEX_RECORD_SIZE;
    let mut group_entries: Vec<Vec<usize>> = vec![Vec::new(); INDEX_K];
    for i in 0..n {
        let script_hash = &data[i * INDEX_RECORD_SIZE..i * INDEX_RECORD_SIZE + SCRIPT_HASH_SIZE];
        for group in derive_groups_3(script_hash, INDEX_K) {
            group_entries[group].push(i);
        }
    }

    let max_load = group_entries.iter().map(Vec::len).max().unwrap_or(0);
    let mut bins_per_table = compute_bins_per_table(max_load, INDEX_SLOTS_PER_BIN);
    let max_retry_bins = max_retry_bins(bins_per_table);
    let tables = 'retry: loop {
        let mut tables = Vec::with_capacity(INDEX_K);
        for (group_id, entries) in group_entries.iter().enumerate() {
            match build_index_cuckoo_table(
                &data,
                entries,
                group_id,
                bins_per_table,
                options.master_seed,
            ) {
                Ok(table) => tables.push(table),
                Err(PipelineError::CuckooInsertFailed { .. })
                    if bins_per_table < max_retry_bins =>
                {
                    bins_per_table += 1;
                    continue 'retry;
                }
                Err(e) => return Err(e),
            }
        }
        break tables;
    };
    let slots_per_table = bins_per_table * INDEX_SLOTS_PER_BIN;

    let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, File::create_new(output_path)?);
    write_index_cuckoo_header(&mut writer, bins_per_table as u32, options)?;
    for group_id in 0..INDEX_K {
        let entries = &group_entries[group_id];
        let table = &tables[group_id];
        for &local in table {
            if local == EMPTY {
                writer.write_all(&[0u8; INDEX_SLOT_SIZE])?;
            } else {
                let global_idx = entries[local as usize];
                let offset = global_idx * INDEX_RECORD_SIZE;
                let script_hash = &data[offset..offset + SCRIPT_HASH_SIZE];
                let tag = compute_tag(options.tag_seed, script_hash);
                writer.write_all(&tag.to_le_bytes())?;
                writer.write_all(&data[offset + SCRIPT_HASH_SIZE..offset + INDEX_RECORD_SIZE])?;
            }
        }
    }
    writer.flush()?;

    let output_bytes = index_cuckoo_header_size(options) as u64
        + (INDEX_K * slots_per_table * INDEX_SLOT_SIZE) as u64;
    Ok(IndexCuckooBuildReport {
        index_entries: n as u64,
        bins_per_table: bins_per_table as u32,
        slots_per_table: slots_per_table as u64,
        output_bytes,
        total_placements: (n * INDEX_PBC_HASHES) as u64,
    })
}

fn build_index_cuckoo_table(
    index_data: &[u8],
    entries: &[usize],
    group_id: usize,
    bins_per_table: usize,
    master_seed: u64,
) -> Result<Vec<u32>, PipelineError> {
    let mut table = vec![EMPTY; bins_per_table * INDEX_SLOTS_PER_BIN];
    let keys = [
        derive_cuckoo_key(master_seed, group_id, 0),
        derive_cuckoo_key(master_seed, group_id, 1),
    ];
    for local_index in 0..entries.len() {
        if !cuckoo_insert_index(
            &mut table,
            index_data,
            entries,
            local_index,
            &keys,
            bins_per_table,
        ) {
            return Err(PipelineError::CuckooInsertFailed {
                group_id,
                local_index,
            });
        }
    }
    Ok(table)
}

fn build_chunk_cuckoo_inner(
    chunks_path: &Path,
    output_path: &Path,
    options: &ChunkCuckooOptions,
) -> Result<ChunkCuckooBuildReport, PipelineError> {
    let chunks = std::fs::read(chunks_path)?;
    if chunks.len() as u64 % CHUNK_SIZE as u64 != 0 {
        return Err(PipelineError::InvalidChunksSize {
            bytes: chunks.len() as u64,
        });
    }
    let n = chunks.len() / CHUNK_SIZE;
    if n > u32::MAX as usize {
        return Err(PipelineError::ChunkIdOverflow(n as u64));
    }

    let mut group_chunks: Vec<Vec<u32>> = vec![Vec::new(); CHUNK_K];
    for chunk_id in 0..n as u32 {
        for group in derive_int_groups_3(chunk_id, CHUNK_K) {
            group_chunks[group].push(chunk_id);
        }
    }

    let max_load = group_chunks.iter().map(Vec::len).max().unwrap_or(0);
    let mut bins_per_table = compute_bins_per_table(max_load, CHUNK_SLOTS_PER_BIN);
    let max_retry_bins = max_retry_bins(bins_per_table);
    let tables = 'retry: loop {
        let mut tables = Vec::with_capacity(CHUNK_K);
        for (group_id, chunk_ids) in group_chunks.iter().enumerate() {
            match build_chunk_cuckoo_table(chunk_ids, group_id, bins_per_table, options.master_seed)
            {
                Ok(table) => tables.push(table),
                Err(PipelineError::CuckooInsertFailed { .. })
                    if bins_per_table < max_retry_bins =>
                {
                    bins_per_table += 1;
                    continue 'retry;
                }
                Err(e) => return Err(e),
            }
        }
        break tables;
    };
    let slots_per_table = bins_per_table * CHUNK_SLOTS_PER_BIN;

    let mut writer = BufWriter::with_capacity(16 * 1024 * 1024, File::create_new(output_path)?);
    write_chunk_cuckoo_header(&mut writer, bins_per_table as u32, options)?;
    for group_id in 0..CHUNK_K {
        let chunk_ids = &group_chunks[group_id];
        let table = &tables[group_id];
        for &local in table {
            if local == EMPTY {
                writer.write_all(&[0u8; CHUNK_SLOT_SIZE])?;
            } else {
                let chunk_id = chunk_ids[local as usize];
                let offset = chunk_id as usize * CHUNK_SIZE;
                writer.write_all(&chunk_id.to_le_bytes())?;
                writer.write_all(&chunks[offset..offset + CHUNK_SIZE])?;
            }
        }
    }
    writer.flush()?;

    let output_bytes = chunk_cuckoo_header_size(options) as u64
        + (CHUNK_K * slots_per_table * CHUNK_SLOT_SIZE) as u64;
    Ok(ChunkCuckooBuildReport {
        chunks: n as u64,
        bins_per_table: bins_per_table as u32,
        slots_per_table: slots_per_table as u64,
        output_bytes,
        total_placements: (n * CHUNK_PBC_HASHES) as u64,
    })
}

fn build_chunk_cuckoo_table(
    chunk_ids: &[u32],
    group_id: usize,
    bins_per_table: usize,
    master_seed: u64,
) -> Result<Vec<u32>, PipelineError> {
    let mut table = vec![EMPTY; bins_per_table * CHUNK_SLOTS_PER_BIN];
    let keys = [
        derive_cuckoo_key(master_seed, group_id, 0),
        derive_cuckoo_key(master_seed, group_id, 1),
    ];
    for local_index in 0..chunk_ids.len() {
        if !cuckoo_insert_chunk(&mut table, chunk_ids, local_index, &keys, bins_per_table) {
            return Err(PipelineError::CuckooInsertFailed {
                group_id,
                local_index,
            });
        }
    }
    Ok(table)
}

fn build_bucket_merkle_inner(
    index_data: &[u8],
    chunk_data: &[u8],
    index_meta: &CuckooTableMeta,
    chunk_meta: &CuckooTableMeta,
    out_dir: &Path,
    index_sibling_levels: &[usize],
    chunk_sibling_levels: &[usize],
    options: &BucketMerkleOptions,
) -> Result<BucketMerkleBuildReport, PipelineError> {
    let index_bin_size = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;
    let chunk_bin_size = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE;

    let index_trees: Vec<PerGroupTree> = (0..INDEX_K)
        .map(|group_id| {
            build_group_tree(
                index_data,
                index_meta.header_size,
                group_id,
                index_meta.bins_per_table,
                index_bin_size,
            )
        })
        .collect();
    let chunk_trees: Vec<PerGroupTree> = (0..CHUNK_K)
        .map(|group_id| {
            build_group_tree(
                chunk_data,
                chunk_meta.header_size,
                group_id,
                chunk_meta.bins_per_table,
                chunk_bin_size,
            )
        })
        .collect();

    let tree_tops_file_bytes = if options.root_only {
        0
    } else {
        for (level_idx, &num_groups) in index_sibling_levels.iter().enumerate() {
            write_flat_sibling_table(
                &temp_path(&out_dir.join(merkle_index_sibling_filename(level_idx))),
                &index_trees,
                level_idx,
                num_groups,
                INDEX_K,
                bucket_sib_magic(0, level_idx as u8),
            )?;
        }
        for (level_idx, &num_groups) in chunk_sibling_levels.iter().enumerate() {
            write_flat_sibling_table(
                &temp_path(&out_dir.join(merkle_chunk_sibling_filename(level_idx))),
                &chunk_trees,
                level_idx,
                num_groups,
                CHUNK_K,
                bucket_sib_magic(1, level_idx as u8),
            )?;
        }

        let tree_tops_path = temp_path(&out_dir.join(MERKLE_BUCKET_TREE_TOPS_FILENAME));
        write_tree_tops(
            &tree_tops_path,
            &index_trees,
            &chunk_trees,
            index_sibling_levels,
            chunk_sibling_levels,
        )?;
        std::fs::metadata(&tree_tops_path)?.len()
    };

    let mut roots = Vec::with_capacity(INDEX_K + CHUNK_K);
    roots.extend(index_trees.iter().map(|tree| tree.root));
    roots.extend(chunk_trees.iter().map(|tree| tree.root));

    let roots_file_bytes = if options.root_only {
        0
    } else {
        let roots_path = temp_path(&out_dir.join(MERKLE_BUCKET_ROOTS_FILENAME));
        write_roots(&roots_path, &roots)?;
        std::fs::metadata(&roots_path)?.len()
    };

    let mut super_preimage = Vec::with_capacity(roots.len() * MERKLE_HASH_SIZE);
    for root in &roots {
        super_preimage.extend_from_slice(root);
    }
    let super_root = sha256(&super_preimage);
    let super_root_path = temp_path(&out_dir.join(MERKLE_BUCKET_ROOT_FILENAME));
    std::fs::write(&super_root_path, super_root)?;

    Ok(BucketMerkleBuildReport {
        index_bins_per_table: index_meta.bins_per_table as u32,
        chunk_bins_per_table: chunk_meta.bins_per_table as u32,
        index_sibling_levels: index_sibling_levels.iter().map(|&n| n as u32).collect(),
        chunk_sibling_levels: chunk_sibling_levels.iter().map(|&n| n as u32).collect(),
        tree_count: (INDEX_K + CHUNK_K) as u32,
        tree_tops_file_bytes,
        roots_file_bytes,
        super_root,
    })
}

fn parse_cuckoo_meta(
    path: &Path,
    data: &[u8],
    expected_magic: u64,
    legacy_header_size: usize,
    expected_k: usize,
    expected_slots_per_bin: usize,
    expected_num_hashes: usize,
) -> Result<CuckooTableMeta, PipelineError> {
    if data.len() < legacy_header_size {
        return Err(PipelineError::InvalidCuckooHeader {
            path: path.to_path_buf(),
            reason: format!("file too small for {legacy_header_size}-byte header"),
        });
    }
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let legacy_magic = expected_magic;
    let snapshot_magic = expected_magic ^ ANCHOR_MAGIC_SNAPSHOT_XOR;
    let delta_magic = expected_magic ^ ANCHOR_MAGIC_DELTA_XOR;
    let anchor_len = if magic == legacy_magic {
        0
    } else if magic == snapshot_magic {
        CHAIN_ANCHOR_BYTES
    } else if magic == delta_magic {
        DELTA_ANCHOR_BYTES
    } else {
        return Err(PipelineError::InvalidCuckooHeader {
            path: path.to_path_buf(),
            reason: format!(
                "bad magic 0x{magic:016x}; expected legacy 0x{legacy_magic:016x}, snapshot v2 0x{snapshot_magic:016x}, or delta v2 0x{delta_magic:016x}"
            ),
        });
    };
    let header_size = legacy_header_size + anchor_len;
    if data.len() < header_size {
        return Err(PipelineError::InvalidCuckooHeader {
            path: path.to_path_buf(),
            reason: format!("truncated v2 header: need {header_size} bytes"),
        });
    }
    let k = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let slots_per_bin = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
    let bins_per_table = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    let num_hashes = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;
    if k != expected_k {
        return Err(PipelineError::InvalidCuckooHeader {
            path: path.to_path_buf(),
            reason: format!("k={k}, expected {expected_k}"),
        });
    }
    if slots_per_bin != expected_slots_per_bin {
        return Err(PipelineError::InvalidCuckooHeader {
            path: path.to_path_buf(),
            reason: format!("slots_per_bin={slots_per_bin}, expected {expected_slots_per_bin}"),
        });
    }
    if num_hashes != expected_num_hashes {
        return Err(PipelineError::InvalidCuckooHeader {
            path: path.to_path_buf(),
            reason: format!("num_hashes={num_hashes}, expected {expected_num_hashes}"),
        });
    }
    if bins_per_table == 0 {
        return Err(PipelineError::InvalidCuckooHeader {
            path: path.to_path_buf(),
            reason: "bins_per_table must be nonzero".into(),
        });
    }
    Ok(CuckooTableMeta {
        bins_per_table,
        header_size,
    })
}

fn validate_cuckoo_body(
    path: &Path,
    actual_bytes: usize,
    meta: &CuckooTableMeta,
    k: usize,
    bin_size: usize,
) -> Result<(), PipelineError> {
    let expected_bytes = meta.header_size + k * meta.bins_per_table * bin_size;
    if actual_bytes != expected_bytes {
        return Err(PipelineError::InvalidCuckooBody {
            path: path.to_path_buf(),
            expected_bytes: expected_bytes as u64,
            actual_bytes: actual_bytes as u64,
        });
    }
    Ok(())
}

fn build_group_tree(
    table_data: &[u8],
    data_offset: usize,
    group_id: usize,
    bins_per_table: usize,
    bin_size: usize,
) -> PerGroupTree {
    let table_byte_size = bins_per_table * bin_size;
    let group_offset = data_offset + group_id * table_byte_size;
    let group_data = &table_data[group_offset..group_offset + table_byte_size];

    let mut levels = Vec::new();
    let leaves: Vec<Hash256> = (0..bins_per_table)
        .map(|i| {
            let bin_start = i * bin_size;
            compute_bin_leaf_hash(i as u32, &group_data[bin_start..bin_start + bin_size])
        })
        .collect();
    levels.push(leaves);

    loop {
        let prev = levels.last().unwrap();
        if prev.len() <= 1 {
            break;
        }
        let mut next = Vec::with_capacity(prev.len().div_ceil(MERKLE_ARITY));
        for i in 0..prev.len().div_ceil(MERKLE_ARITY) {
            let start = i * MERKLE_ARITY;
            let end = (start + MERKLE_ARITY).min(prev.len());
            let mut children = prev[start..end].to_vec();
            children.resize(MERKLE_ARITY, ZERO_HASH);
            next.push(compute_parent_n(&children));
        }
        levels.push(next);
    }

    let root = levels.last().unwrap()[0];
    PerGroupTree { levels, root }
}

fn compute_sibling_levels(bins_per_table: usize) -> Vec<usize> {
    let mut levels = Vec::new();
    let mut nodes_at_level = bins_per_table;
    loop {
        let num_groups = nodes_at_level.div_ceil(MERKLE_ARITY);
        if num_groups <= MERKLE_TREE_TOP_THRESHOLD {
            break;
        }
        levels.push(num_groups);
        nodes_at_level = num_groups;
    }
    levels
}

fn write_flat_sibling_table(
    path: &Path,
    trees: &[PerGroupTree],
    level_idx: usize,
    num_groups: usize,
    k: usize,
    magic: u64,
) -> Result<(), PipelineError> {
    let mut writer = BufWriter::with_capacity(16 * 1024 * 1024, File::create_new(path)?);
    writer.write_all(&magic.to_le_bytes())?;
    writer.write_all(&(k as u32).to_le_bytes())?;
    writer.write_all(&1u32.to_le_bytes())?;
    writer.write_all(&(num_groups as u32).to_le_bytes())?;
    writer.write_all(&0u32.to_le_bytes())?;
    writer.write_all(&0u64.to_le_bytes())?;

    for tree in trees.iter().take(k) {
        let children_level = &tree.levels[level_idx];
        for row in 0..num_groups {
            let start = row * MERKLE_ARITY;
            for child in 0..MERKLE_ARITY {
                let idx = start + child;
                if idx < children_level.len() {
                    writer.write_all(&children_level[idx])?;
                } else {
                    writer.write_all(&ZERO_HASH)?;
                }
            }
        }
    }
    writer.flush()?;
    Ok(())
}

fn write_tree_tops(
    path: &Path,
    index_trees: &[PerGroupTree],
    chunk_trees: &[PerGroupTree],
    index_sibling_levels: &[usize],
    chunk_sibling_levels: &[usize],
) -> Result<(), PipelineError> {
    let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, File::create_new(path)?);
    writer.write_all(&((index_trees.len() + chunk_trees.len()) as u32).to_le_bytes())?;
    for tree in index_trees {
        write_one_tree_top(&mut writer, tree, index_sibling_levels.len())?;
    }
    for tree in chunk_trees {
        write_one_tree_top(&mut writer, tree, chunk_sibling_levels.len())?;
    }
    writer.flush()?;
    Ok(())
}

fn write_one_tree_top<W: Write>(
    writer: &mut W,
    tree: &PerGroupTree,
    cache_from_level: usize,
) -> Result<(), PipelineError> {
    let num_cached_levels = tree.levels.len().saturating_sub(cache_from_level);
    let total_nodes: usize = tree.levels[cache_from_level..].iter().map(Vec::len).sum();
    writer.write_all(&[cache_from_level as u8])?;
    writer.write_all(&(total_nodes as u32).to_le_bytes())?;
    writer.write_all(&(MERKLE_ARITY as u16).to_le_bytes())?;
    writer.write_all(&[num_cached_levels as u8])?;
    for level in &tree.levels[cache_from_level..] {
        writer.write_all(&(level.len() as u32).to_le_bytes())?;
        for hash in level {
            writer.write_all(hash)?;
        }
    }
    Ok(())
}

fn write_roots(path: &Path, roots: &[Hash256]) -> Result<(), PipelineError> {
    let mut writer = BufWriter::new(File::create_new(path)?);
    for root in roots {
        writer.write_all(root)?;
    }
    writer.flush()?;
    Ok(())
}

fn bucket_sib_magic(table_type: u8, level: u8) -> u64 {
    0xBA7C_B000_0000_0000u64 | ((table_type as u64) << 40) | ((level as u64) << 16)
}

fn merkle_index_sibling_filename(level: usize) -> String {
    format!("merkle_bucket_index_sib_L{level}.bin")
}

fn merkle_chunk_sibling_filename(level: usize) -> String {
    format!("merkle_bucket_chunk_sib_L{level}.bin")
}

fn compute_bin_leaf_hash(bin_index: u32, bin_content: &[u8]) -> Hash256 {
    let mut preimage = Vec::with_capacity(4 + bin_content.len());
    preimage.extend_from_slice(&bin_index.to_le_bytes());
    preimage.extend_from_slice(bin_content);
    sha256(&preimage)
}

fn compute_parent_n(children: &[Hash256]) -> Hash256 {
    let mut preimage = Vec::with_capacity(children.len() * MERKLE_HASH_SIZE);
    for child in children {
        preimage.extend_from_slice(child);
    }
    sha256(&preimage)
}

fn sha256(data: &[u8]) -> Hash256 {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn build_utxo_chunks_inner(
    flat_utxo_path: &Path,
    options: &UtxoChunkBuildOptions,
    chunks_path: &Path,
    index_path: &Path,
    top_path: &Path,
    whales_path: &Path,
) -> Result<UtxoChunkBuildReport, PipelineError> {
    let bytes = std::fs::metadata(flat_utxo_path)?.len();
    if bytes % FLAT_UTXO_ENTRY_SIZE as u64 != 0 {
        return Err(PipelineError::InvalidFlatUtxoSize { bytes });
    }
    let input_entries = bytes / FLAT_UTXO_ENTRY_SIZE as u64;

    let mut chunks_writer = BufWriter::with_capacity(1024 * 1024, File::create_new(chunks_path)?);
    let mut index_writer = BufWriter::with_capacity(1024 * 1024, File::create_new(index_path)?);

    let mut current_offset = 0u64;
    let mut report = UtxoChunkBuildReport {
        input_entries,
        dust_utxos_skipped: 0,
        whale_spks_excluded: 0,
        groups_written: 0,
        index_entries: 0,
        chunks_written: 0,
        chunks_file_bytes: 0,
        index_file_bytes: 0,
        data_bytes: 0,
        padding_bytes: 0,
    };
    let mut whale_entries: Vec<([u8; SCRIPT_HASH_SIZE], usize)> = Vec::new();
    let mut top_heap: BinaryHeap<Reverse<TopEntry>> = BinaryHeap::new();

    for partition in 0..options.partitions {
        let mut map: HashMap<[u8; SCRIPT_HASH_SIZE], Vec<ShortenedEntry>> = HashMap::new();
        for entry in FlatEntryIter::open(flat_utxo_path)? {
            let entry = entry?;
            if entry.script_hash[0] as usize % options.partitions != partition {
                continue;
            }
            if entry.amount <= options.dust_threshold_sats {
                report.dust_utxos_skipped += 1;
                continue;
            }
            map.entry(entry.script_hash)
                .or_default()
                .push(ShortenedEntry {
                    txid: entry.txid,
                    vout: entry.vout,
                    amount: entry.amount,
                    height: entry.height,
                });
        }

        let mut groups: Vec<([u8; SCRIPT_HASH_SIZE], Vec<ShortenedEntry>)> =
            map.into_iter().collect();
        groups.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        for (script_hash, mut entries) in groups {
            if entries.len() > options.max_utxos_per_spk {
                write_index_entry(&mut index_writer, &script_hash, 0, 0)?;
                whale_entries.push((script_hash, entries.len()));
                report.whale_spks_excluded += 1;
                report.index_entries += 1;
                continue;
            }

            entries.sort_unstable_by(|a, b| b.height.cmp(&a.height));
            let first_txid = entries[0].txid;
            let first_vout = entries[0].vout;
            let data = serialize_group_sorted(&entries);
            let data_len = data.len();
            push_top_entry(
                &mut top_heap,
                (data_len, script_hash, first_txid, first_vout),
            );

            let num_chunks = data_len.div_ceil(CHUNK_SIZE);
            if num_chunks > u8::MAX as usize {
                return Err(PipelineError::ChunkCountOverflow {
                    script_hash,
                    chunks: num_chunks,
                });
            }
            let padded_len = num_chunks * CHUNK_SIZE;
            let padding = padded_len - data_len;
            let start_chunk_id = current_offset / CHUNK_SIZE as u64;
            if start_chunk_id > u32::MAX as u64 {
                return Err(PipelineError::ChunkIdOverflow(start_chunk_id));
            }

            write_index_entry(
                &mut index_writer,
                &script_hash,
                start_chunk_id as u32,
                num_chunks as u8,
            )?;
            chunks_writer.write_all(&data)?;
            if padding > 0 {
                chunks_writer.write_all(&ZERO_PAD[..padding])?;
            }

            current_offset += padded_len as u64;
            report.groups_written += 1;
            report.index_entries += 1;
            report.chunks_written += num_chunks as u64;
            report.data_bytes += data_len as u64;
            report.padding_bytes += padding as u64;
        }
    }

    chunks_writer.flush()?;
    index_writer.flush()?;
    report.chunks_file_bytes = current_offset;
    report.index_file_bytes = report.index_entries * INDEX_RECORD_SIZE as u64;

    write_top100(top_path, top_heap)?;
    write_whales(whales_path, &mut whale_entries, options.max_utxos_per_spk)?;

    Ok(report)
}

fn build_onion_pack_inner(
    flat_utxo_path: &Path,
    options: &OnionPackOptions,
    packed_path: &Path,
    index_path: &Path,
) -> Result<OnionPackReport, PipelineError> {
    let bytes = std::fs::metadata(flat_utxo_path)?.len();
    if bytes % FLAT_UTXO_ENTRY_SIZE as u64 != 0 {
        return Err(PipelineError::InvalidFlatUtxoSize { bytes });
    }
    let input_entries = bytes / FLAT_UTXO_ENTRY_SIZE as u64;

    let packed_writer = BufWriter::with_capacity(1024 * 1024, File::create_new(packed_path)?);
    let mut packer = OnionPacker::new(packed_writer, options.entry_size);
    let mut index_writer = BufWriter::with_capacity(1024 * 1024, File::create_new(index_path)?);

    let mut report = OnionPackReport {
        input_entries,
        dust_utxos_skipped: 0,
        whale_spks_excluded: 0,
        groups_packed: 0,
        onion_entries: 0,
        packed_file_bytes: 0,
        index_file_bytes: 0,
        data_bytes: 0,
        padding_bytes: 0,
        max_serialized_len: 0,
    };

    for partition in 0..options.partitions {
        let mut map: HashMap<[u8; SCRIPT_HASH_SIZE], Vec<ShortenedEntry>> = HashMap::new();
        for entry in FlatEntryIter::open(flat_utxo_path)? {
            let entry = entry?;
            if entry.script_hash[0] as usize % options.partitions != partition {
                continue;
            }
            if entry.amount <= options.dust_threshold_sats {
                report.dust_utxos_skipped += 1;
                continue;
            }
            map.entry(entry.script_hash)
                .or_default()
                .push(ShortenedEntry {
                    txid: entry.txid,
                    vout: entry.vout,
                    amount: entry.amount,
                    height: entry.height,
                });
        }

        let mut groups: Vec<([u8; SCRIPT_HASH_SIZE], Vec<ShortenedEntry>)> =
            map.into_iter().collect();
        groups.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        for (script_hash, mut entries) in groups {
            if entries.len() > options.max_utxos_per_spk {
                write_onion_index_entry(&mut index_writer, &script_hash, 0, 0, ONION_WHALE_FLAG)?;
                report.whale_spks_excluded += 1;
                continue;
            }

            entries.sort_unstable_by(|a, b| b.height.cmp(&a.height));
            let data = serialize_group_sorted(&entries);
            report.max_serialized_len = report.max_serialized_len.max(data.len());
            let (entry_id, byte_offset, num_entries) = packer.pack(&script_hash, &data)?;
            write_onion_index_entry(
                &mut index_writer,
                &script_hash,
                entry_id,
                byte_offset,
                num_entries,
            )?;
            report.groups_packed += 1;
        }
    }

    packer.finish()?;
    index_writer.flush()?;

    report.onion_entries = packer.entry_count;
    report.packed_file_bytes = packer.entry_count * options.entry_size as u64;
    report.index_file_bytes =
        (report.groups_packed + report.whale_spks_excluded) * ONION_INDEX_RECORD_SIZE as u64;
    report.data_bytes = packer.total_data;
    report.padding_bytes = packer.total_padding;

    Ok(report)
}

fn build_grouped_delta_from_flat_sets_inner(
    from_flat_utxo_path: &Path,
    to_flat_utxo_path: &Path,
    grouped_delta_path: &Path,
    options: &DeltaBuildOptions,
) -> Result<DeltaBuildReport, PipelineError> {
    let from_bytes = std::fs::metadata(from_flat_utxo_path)?.len();
    if from_bytes % FLAT_UTXO_ENTRY_SIZE as u64 != 0 {
        return Err(PipelineError::InvalidFlatUtxoSize { bytes: from_bytes });
    }
    let to_bytes = std::fs::metadata(to_flat_utxo_path)?.len();
    if to_bytes % FLAT_UTXO_ENTRY_SIZE as u64 != 0 {
        return Err(PipelineError::InvalidFlatUtxoSize { bytes: to_bytes });
    }
    let from_entries = from_bytes / FLAT_UTXO_ENTRY_SIZE as u64;
    let to_entries = to_bytes / FLAT_UTXO_ENTRY_SIZE as u64;

    let mut from_map: HashMap<OutPointKey, [u8; SCRIPT_HASH_SIZE]> =
        HashMap::with_capacity(from_entries as usize);
    for entry in FlatEntryIter::open(from_flat_utxo_path)? {
        let entry = entry?;
        let key = OutPointKey {
            txid: entry.txid,
            vout: entry.vout,
        };
        if from_map.insert(key, entry.script_hash).is_some() {
            return Err(PipelineError::InvalidDeltaFormat {
                path: from_flat_utxo_path.to_path_buf(),
                reason: format!("duplicate outpoint {}:{}", hex::encode(key.txid), key.vout),
            });
        }
    }

    let mut deltas: HashMap<[u8; SCRIPT_HASH_SIZE], ScriptDelta> = HashMap::new();
    let mut unchanged_entries = 0u64;
    let mut created_entries = 0u64;
    let mut dust_created_skipped = 0u64;

    for entry in FlatEntryIter::open(to_flat_utxo_path)? {
        let entry = entry?;
        let key = OutPointKey {
            txid: entry.txid,
            vout: entry.vout,
        };
        if from_map.remove(&key).is_some() {
            unchanged_entries += 1;
            continue;
        }
        if entry.amount <= options.dust_threshold_sats {
            dust_created_skipped += 1;
            continue;
        }
        deltas
            .entry(entry.script_hash)
            .or_default()
            .new_utxos
            .push(NewUtxo {
                txid: entry.txid,
                vout: entry.vout,
                amount: entry.amount,
            });
        created_entries += 1;
    }

    let spent_entries = from_map.len() as u64;
    let mut spent: Vec<(OutPointKey, [u8; SCRIPT_HASH_SIZE])> = from_map.into_iter().collect();
    spent.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    for (key, script_hash) in spent {
        deltas.entry(script_hash).or_default().spent.push(SpentRef {
            txid: key.txid,
            vout: key.vout,
        });
    }

    let mut delta_groups: Vec<_> = deltas.into_iter().collect();
    delta_groups.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    for (_script_hash, delta) in &mut delta_groups {
        delta
            .spent
            .sort_unstable_by(|a, b| a.txid.cmp(&b.txid).then_with(|| a.vout.cmp(&b.vout)));
        delta.new_utxos.sort_unstable_by(|a, b| {
            a.txid
                .cmp(&b.txid)
                .then_with(|| a.vout.cmp(&b.vout))
                .then_with(|| a.amount.cmp(&b.amount))
        });
    }

    let mut writer =
        BufWriter::with_capacity(4 * 1024 * 1024, File::create_new(grouped_delta_path)?);
    if delta_groups.len() > u32::MAX as usize {
        return Err(PipelineError::InvalidDeltaFormat {
            path: grouped_delta_path.to_path_buf(),
            reason: format!("too many changed scripts: {}", delta_groups.len()),
        });
    }
    writer.write_all(&(delta_groups.len() as u32).to_le_bytes())?;
    for (script_hash, delta) in &delta_groups {
        writer.write_all(script_hash)?;
        write_varint_to_writer(&mut writer, delta.spent.len() as u64)?;
        for spent in &delta.spent {
            writer.write_all(&spent.txid)?;
            write_varint_to_writer(&mut writer, spent.vout as u64)?;
        }
        write_varint_to_writer(&mut writer, delta.new_utxos.len() as u64)?;
        for new_utxo in &delta.new_utxos {
            writer.write_all(&new_utxo.txid)?;
            write_varint_to_writer(&mut writer, new_utxo.vout as u64)?;
            write_varint_to_writer(&mut writer, new_utxo.amount)?;
        }
    }
    writer.flush()?;
    let grouped_file_bytes = std::fs::metadata(grouped_delta_path)?.len();

    Ok(DeltaBuildReport {
        from_entries,
        to_entries,
        unchanged_entries,
        spent_entries,
        created_entries,
        dust_created_skipped,
        scripts_changed: delta_groups.len() as u64,
        grouped_file_bytes,
    })
}

fn build_delta_chunks_inner(
    grouped_delta_path: &Path,
    chunks_path: &Path,
    index_path: &Path,
) -> Result<DeltaChunkBuildReport, PipelineError> {
    let data = std::fs::read(grouped_delta_path)?;
    let mut chunks_writer = BufWriter::with_capacity(1024 * 1024, File::create_new(chunks_path)?);
    let mut index_writer = BufWriter::with_capacity(1024 * 1024, File::create_new(index_path)?);
    let mut pos = 0usize;
    let num_scripts = read_delta_u32(&data, &mut pos, grouped_delta_path)? as usize;
    let mut next_chunk_id = 0u64;
    let mut report = DeltaChunkBuildReport {
        scripts: num_scripts as u64,
        chunks_written: 0,
        index_entries: 0,
        skipped_too_large: 0,
        chunks_file_bytes: 0,
        index_file_bytes: 0,
        data_bytes: 0,
        padding_bytes: 0,
    };

    for _ in 0..num_scripts {
        let (script_hash, delta_bytes) =
            read_delta_group_body(&data, &mut pos, grouped_delta_path)?;
        let num_chunks = delta_bytes.len().div_ceil(CHUNK_SIZE);
        report.index_entries += 1;

        if num_chunks > u8::MAX as usize {
            write_index_entry(&mut index_writer, &script_hash, 0, 0)?;
            report.skipped_too_large += 1;
            continue;
        }
        if next_chunk_id > u32::MAX as u64 {
            return Err(PipelineError::ChunkIdOverflow(next_chunk_id));
        }

        chunks_writer.write_all(delta_bytes)?;
        let padding = num_chunks * CHUNK_SIZE - delta_bytes.len();
        if padding > 0 {
            chunks_writer.write_all(&ZERO_PAD[..padding])?;
        }
        write_index_entry(
            &mut index_writer,
            &script_hash,
            next_chunk_id as u32,
            num_chunks as u8,
        )?;

        next_chunk_id += num_chunks as u64;
        report.chunks_written += num_chunks as u64;
        report.data_bytes += delta_bytes.len() as u64;
        report.padding_bytes += padding as u64;
    }
    if pos != data.len() {
        return Err(PipelineError::InvalidDeltaFormat {
            path: grouped_delta_path.to_path_buf(),
            reason: format!("{} trailing bytes after grouped delta", data.len() - pos),
        });
    }
    chunks_writer.flush()?;
    index_writer.flush()?;
    report.chunks_file_bytes = next_chunk_id * CHUNK_SIZE as u64;
    report.index_file_bytes = report.index_entries * INDEX_RECORD_SIZE as u64;
    Ok(report)
}

fn build_delta_onion_pack_inner(
    grouped_delta_path: &Path,
    packed_path: &Path,
    index_path: &Path,
    options: &OnionPackOptions,
) -> Result<DeltaOnionPackReport, PipelineError> {
    let data = std::fs::read(grouped_delta_path)?;
    let packed_writer = BufWriter::with_capacity(1024 * 1024, File::create_new(packed_path)?);
    let mut packer = OnionPacker::new(packed_writer, options.entry_size);
    let mut index_writer = BufWriter::with_capacity(1024 * 1024, File::create_new(index_path)?);
    let mut pos = 0usize;
    let num_scripts = read_delta_u32(&data, &mut pos, grouped_delta_path)? as usize;
    let mut report = DeltaOnionPackReport {
        scripts: num_scripts as u64,
        groups_packed: 0,
        whale_spks_excluded: 0,
        onion_entries: 0,
        packed_file_bytes: 0,
        index_file_bytes: 0,
        data_bytes: 0,
        padding_bytes: 0,
        max_serialized_len: 0,
    };

    for _ in 0..num_scripts {
        let (script_hash, delta_bytes) =
            read_delta_group_body(&data, &mut pos, grouped_delta_path)?;
        report.max_serialized_len = report.max_serialized_len.max(delta_bytes.len());
        if delta_bytes.len().div_ceil(options.entry_size) > u8::MAX as usize {
            write_onion_index_entry(&mut index_writer, &script_hash, 0, 0, ONION_WHALE_FLAG)?;
            report.whale_spks_excluded += 1;
            continue;
        }

        let (entry_id, byte_offset, num_entries) = packer.pack(&script_hash, delta_bytes)?;
        write_onion_index_entry(
            &mut index_writer,
            &script_hash,
            entry_id,
            byte_offset,
            num_entries,
        )?;
        report.groups_packed += 1;
    }
    if pos != data.len() {
        return Err(PipelineError::InvalidDeltaFormat {
            path: grouped_delta_path.to_path_buf(),
            reason: format!("{} trailing bytes after grouped delta", data.len() - pos),
        });
    }

    packer.finish()?;
    index_writer.flush()?;
    report.onion_entries = packer.entry_count;
    report.packed_file_bytes = packer.entry_count * options.entry_size as u64;
    report.index_file_bytes =
        (report.groups_packed + report.whale_spks_excluded) * ONION_INDEX_RECORD_SIZE as u64;
    report.data_bytes = packer.total_data;
    report.padding_bytes = packer.total_padding;
    Ok(report)
}

fn build_onion_data_cuckoo_inner(
    packed_path: &Path,
    options: &OnionDataCuckooOptions,
    cuckoo_path: &Path,
    bin_hashes_path: &Path,
) -> Result<OnionDataCuckooBuildReport, PipelineError> {
    let bytes = std::fs::metadata(packed_path)?.len();
    if bytes % options.entry_size as u64 != 0 {
        return Err(PipelineError::InvalidOnionPackedSize {
            bytes,
            entry_size: options.entry_size,
        });
    }
    let packed_entries = bytes / options.entry_size as u64;
    if packed_entries > u32::MAX as u64 {
        return Err(PipelineError::OnionEntryIdOverflow(packed_entries));
    }

    let mut groups: Vec<Vec<u32>> = (0..CHUNK_K).map(|_| Vec::new()).collect();
    for entry_id in 0..packed_entries as u32 {
        for group in derive_int_groups_3(entry_id, CHUNK_K) {
            groups[group].push(entry_id);
        }
    }

    let max_group = groups.iter().map(Vec::len).max().unwrap_or(0);
    let mut bins_per_table = ((max_group as f64 / CUCKOO_LOAD_FACTOR).ceil() as usize).max(1);
    let max_retry_bins = max_retry_bins(bins_per_table);
    let tables = 'retry: loop {
        let mut tables = Vec::with_capacity(CHUNK_K);
        for (group_id, entries) in groups.iter().enumerate() {
            let mut sorted = entries.clone();
            sorted.sort_unstable();
            let mut keys = [0u64; ONION_DATA_CUCKOO_HASHES];
            for (h, key) in keys.iter_mut().enumerate() {
                *key = derive_cuckoo_key(options.master_seed, group_id, h);
            }
            match build_onion_data_cuckoo_table(&sorted, &keys, bins_per_table) {
                Some(table) => tables.push(table),
                None if bins_per_table < max_retry_bins => {
                    bins_per_table += 1;
                    continue 'retry;
                }
                None => {
                    return Err(PipelineError::CuckooInsertFailed {
                        group_id,
                        local_index: sorted.len(),
                    });
                }
            }
        }
        break tables;
    };

    let bins_per_table_u32 = bins_per_table as u32;
    write_onion_data_cuckoo_file(
        cuckoo_path,
        &tables,
        bins_per_table_u32,
        packed_entries,
        options,
    )?;
    let bin_hashes_file_bytes = write_onion_data_bin_hashes(
        bin_hashes_path,
        packed_path,
        &tables,
        bins_per_table,
        options,
    )?;

    let header_size = ONION_DATA_CUCKOO_HEADER_SIZE
        + header_anchor(options.snapshot_anchor, options.delta_anchor).map_or(0, |a| a.len());
    Ok(OnionDataCuckooBuildReport {
        packed_entries,
        bins_per_table: bins_per_table_u32,
        output_bytes: header_size as u64 + CHUNK_K as u64 * bins_per_table as u64 * 4,
        bin_hashes_file_bytes,
        total_placements: packed_entries * CHUNK_PBC_HASHES as u64,
    })
}

fn build_onion_index_cuckoo_inner(
    index_path: &Path,
    options: &OnionIndexCuckooOptions,
    bins_path: &Path,
    meta_path: &Path,
    bin_hashes_path: &Path,
) -> Result<OnionIndexCuckooBuildReport, PipelineError> {
    let index_data = std::fs::read(index_path)?;
    if index_data.len() as u64 % ONION_INDEX_RECORD_SIZE as u64 != 0 {
        return Err(PipelineError::InvalidIndexSize {
            bytes: index_data.len() as u64,
        });
    }
    let index_entries = index_data.len() / ONION_INDEX_RECORD_SIZE;
    if index_entries > u32::MAX as usize {
        return Err(PipelineError::OnionEntryIdOverflow(index_entries as u64));
    }
    let slots_per_bin = onion_index_slots_per_bin(options.entry_size)?;

    let mut non_whale_entries = 0u64;
    let mut groups: Vec<Vec<u32>> = (0..INDEX_K).map(|_| Vec::new()).collect();
    for i in 0..index_entries {
        let base = i * ONION_INDEX_RECORD_SIZE;
        let script_hash = &index_data[base..base + SCRIPT_HASH_SIZE];
        if index_data[base + ONION_INDEX_RECORD_SIZE - 1] != ONION_WHALE_FLAG {
            non_whale_entries += 1;
        }
        for group in derive_groups_3(script_hash, INDEX_K) {
            groups[group].push(i as u32);
        }
    }

    let max_group = groups.iter().map(Vec::len).max().unwrap_or(0);
    let mut bins_per_table = compute_bins_per_table(max_group, slots_per_bin).max(1);
    let max_retry_bins = max_retry_bins(bins_per_table);
    let tables = 'retry: loop {
        let mut tables = Vec::with_capacity(INDEX_K);
        for (group_id, entries) in groups.iter().enumerate() {
            let mut sorted = entries.clone();
            sorted.sort_unstable();
            match build_onion_index_cuckoo_table(
                group_id,
                &sorted,
                &index_data,
                bins_per_table,
                slots_per_bin,
                options.master_seed,
            ) {
                Some(table) => tables.push(table),
                None if bins_per_table < max_retry_bins => {
                    bins_per_table += 1;
                    continue 'retry;
                }
                None => {
                    return Err(PipelineError::CuckooInsertFailed {
                        group_id,
                        local_index: sorted.len(),
                    });
                }
            }
        }
        break tables;
    };

    write_onion_index_bins_and_hashes(
        bins_path,
        bin_hashes_path,
        &tables,
        &index_data,
        bins_per_table,
        slots_per_bin,
        options,
    )?;
    write_onion_index_meta(meta_path, bins_per_table as u32, slots_per_bin, options)?;

    let raw_bins_file_bytes = INDEX_K as u64 * bins_per_table as u64 * options.entry_size as u64;
    let meta_file_bytes = ONION_INDEX_META_HEADER_SIZE as u64
        + header_anchor(options.snapshot_anchor, options.delta_anchor).map_or(0, |a| a.len())
            as u64;
    let bin_hashes_file_bytes =
        8 + INDEX_K as u64 * bins_per_table as u64 * MERKLE_HASH_SIZE as u64;

    Ok(OnionIndexCuckooBuildReport {
        index_entries: index_entries as u64,
        non_whale_entries,
        bins_per_table: bins_per_table as u32,
        slots_per_bin: slots_per_bin as u16,
        raw_bins_file_bytes,
        meta_file_bytes,
        bin_hashes_file_bytes,
        total_placements: index_entries as u64 * INDEX_PBC_HASHES as u64,
    })
}

fn build_onion_merkle_inner(
    index_bin_hashes_path: &Path,
    data_bin_hashes_path: &Path,
    options: &OnionMerkleOptions,
    tree_tops_path: &Path,
    roots_path: &Path,
    root_path: &Path,
    index_sibling_rows_path: &Path,
    data_sibling_rows_path: &Path,
) -> Result<OnionMerkleBuildReport, PipelineError> {
    let arity = onion_merkle_arity(options.entry_size)?;
    let index_hashes = read_onion_bin_hashes(index_bin_hashes_path)?;
    let data_hashes = read_onion_bin_hashes(data_bin_hashes_path)?;

    let index_trees = build_onion_tree_kind(
        index_hashes.k,
        index_hashes.bins_per_table,
        &index_hashes.hashes,
        arity,
    );
    let data_trees = build_onion_tree_kind(
        data_hashes.k,
        data_hashes.bins_per_table,
        &data_hashes.hashes,
        arity,
    );

    let index_sibling_rows_per_group = onion_sibling_rows_per_group(&index_trees);
    let data_sibling_rows_per_group = onion_sibling_rows_per_group(&data_trees);
    let (tree_tops_file_bytes, index_sibling_rows_file_bytes, data_sibling_rows_file_bytes) =
        if options.root_only {
            (0, 0, 0)
        } else {
            write_onion_tree_tops(tree_tops_path, &index_trees, &data_trees, arity)?;
            let index_bytes = write_onion_sibling_rows(
                index_sibling_rows_path,
                &index_trees,
                arity,
                options.entry_size,
                ONION_MERKLE_SIB_ROWS_INDEX_MAGIC,
            )?;
            let data_bytes = write_onion_sibling_rows(
                data_sibling_rows_path,
                &data_trees,
                arity,
                options.entry_size,
                ONION_MERKLE_SIB_ROWS_DATA_MAGIC,
            )?;
            (
                std::fs::metadata(tree_tops_path)?.len(),
                index_bytes,
                data_bytes,
            )
        };

    let mut roots = Vec::with_capacity(index_trees.len() + data_trees.len());
    roots.extend(index_trees.iter().map(|tree| tree.root));
    roots.extend(data_trees.iter().map(|tree| tree.root));
    let roots_file_bytes = if options.root_only {
        0
    } else {
        write_roots(roots_path, &roots)?;
        std::fs::metadata(roots_path)?.len()
    };

    let mut super_preimage = Vec::with_capacity(roots.len() * MERKLE_HASH_SIZE);
    for root in &roots {
        super_preimage.extend_from_slice(root);
    }
    let super_root = sha256(&super_preimage);
    std::fs::write(root_path, super_root)?;

    Ok(OnionMerkleBuildReport {
        index_k: index_hashes.k as u32,
        data_k: data_hashes.k as u32,
        index_bins_per_table: index_hashes.bins_per_table as u32,
        data_bins_per_table: data_hashes.bins_per_table as u32,
        arity: arity as u16,
        tree_count: (index_hashes.k + data_hashes.k) as u32,
        index_sibling_rows_per_group: index_sibling_rows_per_group as u32,
        data_sibling_rows_per_group: data_sibling_rows_per_group as u32,
        tree_tops_file_bytes,
        roots_file_bytes,
        index_sibling_rows_file_bytes,
        data_sibling_rows_file_bytes,
        super_root,
    })
}

/// Verify a completed OnionPIR directory and recover the three v2-only query
/// dimensions. The large table files are scanned against their stored leaf
/// hashes; the ordered roots and tree-top cache are then checked against the
/// proof-bound super-root. No build log is trusted.
pub fn inspect_existing_onion_layout_v2(
    dir: impl AsRef<Path>,
) -> Result<ExistingOnionLayoutV2, PipelineError> {
    let dir = dir.as_ref();
    let invalid = |message: String| PipelineError::InvalidExistingOnionLayout(message);

    let index_meta_path = dir.join(ONION_INDEX_META_FILENAME);
    let index_meta = std::fs::read(&index_meta_path)?;
    if index_meta.len() < ONION_INDEX_META_HEADER_SIZE {
        return Err(invalid(format!(
            "{} is truncated",
            index_meta_path.display()
        )));
    }
    let index_anchor_len = onion_anchor_len(
        u64::from_le_bytes(index_meta[0..8].try_into().unwrap()),
        ONION_INDEX_META_MAGIC,
    )?;
    if index_meta.len() != ONION_INDEX_META_HEADER_SIZE + index_anchor_len {
        return Err(invalid(format!(
            "{} has wrong length: expected {}, got {}",
            index_meta_path.display(),
            ONION_INDEX_META_HEADER_SIZE + index_anchor_len,
            index_meta.len()
        )));
    }
    let index_k = u32::from_le_bytes(index_meta[8..12].try_into().unwrap());
    let index_hashes = u32::from_le_bytes(index_meta[12..16].try_into().unwrap());
    let index_slots = u32::from_le_bytes(index_meta[16..20].try_into().unwrap());
    let index_bins = u32::from_le_bytes(index_meta[20..24].try_into().unwrap());
    let index_master_seed = u64::from_le_bytes(index_meta[24..32].try_into().unwrap());
    let index_tag_seed = u64::from_le_bytes(index_meta[32..40].try_into().unwrap());
    let index_slot_size = u32::from_le_bytes(index_meta[40..44].try_into().unwrap());
    if index_k != INDEX_K as u32
        || index_hashes != ONION_INDEX_CUCKOO_HASHES as u32
        || index_slot_size != ONION_INDEX_SLOT_SIZE as u32
        || index_slots == 0
        || index_bins == 0
    {
        return Err(invalid(format!(
            "bad index geometry: k={index_k} hashes={index_hashes} slots={index_slots} bins={index_bins} slot_size={index_slot_size}"
        )));
    }
    let anchor_bytes = index_meta[ONION_INDEX_META_HEADER_SIZE..].to_vec();

    let chunk_path = dir.join(ONION_CHUNK_CUCKOO_FILENAME);
    let mut chunk_header = [0u8; ONION_DATA_CUCKOO_HEADER_SIZE];
    let chunk_file = File::open(&chunk_path)?;
    chunk_file.read_exact_at(&mut chunk_header, 0)?;
    let chunk_anchor_len = onion_anchor_len(
        u64::from_le_bytes(chunk_header[0..8].try_into().unwrap()),
        ONION_DATA_CUCKOO_MAGIC,
    )?;
    let chunk_k = u32::from_le_bytes(chunk_header[8..12].try_into().unwrap());
    let chunk_hashes = u32::from_le_bytes(chunk_header[12..16].try_into().unwrap());
    let chunk_bins = u32::from_le_bytes(chunk_header[16..20].try_into().unwrap());
    let chunk_master_seed = u64::from_le_bytes(chunk_header[20..28].try_into().unwrap());
    let total_packed_entries = u32::from_le_bytes(chunk_header[28..32].try_into().unwrap());
    if chunk_k != CHUNK_K as u32
        || chunk_hashes != ONION_DATA_CUCKOO_HASHES as u32
        || chunk_bins == 0
        || chunk_header[32..36] != [0u8; 4]
    {
        return Err(invalid(format!(
            "bad chunk geometry: k={chunk_k} hashes={chunk_hashes} bins={chunk_bins} reserved={:?}",
            &chunk_header[32..36]
        )));
    }
    let chunk_header_size = ONION_DATA_CUCKOO_HEADER_SIZE + chunk_anchor_len;
    let expected_chunk_bytes = (chunk_header_size as u64)
        .checked_add(CHUNK_K as u64 * chunk_bins as u64 * 4)
        .ok_or_else(|| invalid("chunk file length overflow".into()))?;
    let actual_chunk_bytes = chunk_file.metadata()?.len();
    if actual_chunk_bytes != expected_chunk_bytes {
        return Err(invalid(format!(
            "{} has wrong length: expected {expected_chunk_bytes}, got {actual_chunk_bytes}",
            chunk_path.display()
        )));
    }
    let mut chunk_anchor = vec![0u8; chunk_anchor_len];
    chunk_file.read_exact_at(&mut chunk_anchor, ONION_DATA_CUCKOO_HEADER_SIZE as u64)?;
    if chunk_anchor != anchor_bytes {
        return Err(invalid("index and chunk anchors differ".into()));
    }

    let entry_size = inspect_onion_sibling_entry_size(dir)?;
    if index_slots
        .checked_mul(index_slot_size)
        .ok_or_else(|| invalid("index slot geometry overflow".into()))?
        > entry_size
    {
        return Err(invalid("index slots exceed Onion entry size".into()));
    }
    if entry_size == 0 || entry_size % MERKLE_HASH_SIZE as u32 != 0 {
        return Err(invalid(format!("invalid Onion entry size {entry_size}")));
    }

    let packed_path = dir.join(ONION_PACKED_ENTRIES_FILENAME);
    let packed_file = File::open(&packed_path)?;
    let expected_packed_bytes = total_packed_entries as u64 * entry_size as u64;
    if packed_file.metadata()?.len() != expected_packed_bytes {
        return Err(invalid(format!(
            "{} length does not match total_packed_entries * entry_size",
            packed_path.display()
        )));
    }
    let index_bins_path = dir.join(ONION_INDEX_BINS_FILENAME);
    let index_bins_file = File::open(&index_bins_path)?;
    let expected_index_bytes = INDEX_K as u64 * index_bins as u64 * entry_size as u64;
    if index_bins_file.metadata()?.len() != expected_index_bytes {
        return Err(invalid(format!(
            "{} length does not match index geometry",
            index_bins_path.display()
        )));
    }

    let index_roots = verify_existing_index_leaf_hashes(
        &index_bins_file,
        &dir.join(ONION_INDEX_BIN_HASHES_FILENAME),
        index_bins,
        entry_size,
    )?;
    let chunk_roots = verify_existing_chunk_leaf_hashes(
        &chunk_file,
        chunk_header_size,
        &packed_file,
        &dir.join(ONION_DATA_BIN_HASHES_FILENAME),
        chunk_bins,
        entry_size,
    )?;
    let roots: Vec<Hash256> = index_roots.into_iter().chain(chunk_roots).collect();
    let roots_path = dir.join(ONION_MERKLE_ROOTS_FILENAME);
    let roots_bytes = std::fs::read(&roots_path)?;
    let computed_roots: Vec<u8> = roots.iter().flatten().copied().collect();
    if roots_bytes != computed_roots {
        return Err(invalid(format!(
            "{} does not match roots recomputed from actual tables",
            roots_path.display()
        )));
    }
    let onion_super_root = sha256(&computed_roots);
    let root_path = dir.join(ONION_MERKLE_ROOT_FILENAME);
    if std::fs::read(&root_path)? != onion_super_root {
        return Err(invalid(format!(
            "{} does not match ordered Onion roots",
            root_path.display()
        )));
    }
    verify_existing_tree_tops(
        &dir.join(ONION_MERKLE_TREE_TOPS_FILENAME),
        &roots,
        index_bins,
        chunk_bins,
        entry_size / MERKLE_HASH_SIZE as u32,
    )?;

    Ok(ExistingOnionLayoutV2 {
        total_packed_entries,
        entry_size,
        index_bins_per_table: index_bins,
        chunk_bins_per_table: chunk_bins,
        index_master_seed,
        index_tag_seed,
        chunk_master_seed,
        anchor_bytes,
        onion_super_root,
    })
}

fn onion_anchor_len(magic: u64, base: u64) -> Result<usize, PipelineError> {
    if magic == base {
        Ok(0)
    } else if magic == base ^ ANCHOR_MAGIC_SNAPSHOT_XOR {
        Ok(CHAIN_ANCHOR_BYTES)
    } else if magic == base ^ ANCHOR_MAGIC_DELTA_XOR {
        Ok(DELTA_ANCHOR_BYTES)
    } else {
        Err(PipelineError::InvalidExistingOnionLayout(format!(
            "unknown Onion header magic 0x{magic:016x}"
        )))
    }
}

fn inspect_onion_sibling_entry_size(dir: &Path) -> Result<u32, PipelineError> {
    let mut sizes = Vec::new();
    for (filename, magic, k) in [
        (
            ONION_MERKLE_SIB_ROWS_INDEX_FILENAME,
            ONION_MERKLE_SIB_ROWS_INDEX_MAGIC,
            INDEX_K as u32,
        ),
        (
            ONION_MERKLE_SIB_ROWS_DATA_FILENAME,
            ONION_MERKLE_SIB_ROWS_DATA_MAGIC,
            CHUNK_K as u32,
        ),
    ] {
        let path = dir.join(filename);
        let bytes = std::fs::read(&path)?;
        if bytes.len() < ONION_MERKLE_SIB_ROWS_HEADER_SIZE {
            return Err(PipelineError::InvalidExistingOnionLayout(format!(
                "{} is truncated",
                path.display()
            )));
        }
        let actual_magic = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let actual_k = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let arity = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let rows = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let row_bytes = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let expected = ONION_MERKLE_SIB_ROWS_HEADER_SIZE as u64
            + actual_k as u64 * rows as u64 * row_bytes as u64;
        if actual_magic != magic
            || actual_k != k
            || arity == 0
            || row_bytes != arity * MERKLE_HASH_SIZE as u32
            || bytes.len() as u64 != expected
        {
            return Err(PipelineError::InvalidExistingOnionLayout(format!(
                "bad sibling rows header or length in {}",
                path.display()
            )));
        }
        sizes.push(row_bytes);
    }
    if sizes[0] != sizes[1] {
        return Err(PipelineError::InvalidExistingOnionLayout(
            "index and chunk sibling row sizes differ".into(),
        ));
    }
    Ok(sizes[0])
}

fn verify_existing_index_leaf_hashes(
    bins: &File,
    hashes_path: &Path,
    bins_per_table: u32,
    entry_size: u32,
) -> Result<Vec<Hash256>, PipelineError> {
    let mut hashes = BufReader::new(File::open(hashes_path)?);
    verify_hash_header(&mut hashes, hashes_path, INDEX_K as u32, bins_per_table)?;
    let mut entry = vec![0u8; entry_size as usize];
    let mut expected = [0u8; MERKLE_HASH_SIZE];
    let mut roots = Vec::with_capacity(INDEX_K);
    for group in 0..INDEX_K {
        let mut leaves = Vec::with_capacity(bins_per_table as usize);
        for bin in 0..bins_per_table as usize {
            let offset = ((group * bins_per_table as usize + bin) * entry_size as usize) as u64;
            bins.read_exact_at(&mut entry, offset)?;
            hashes.read_exact(&mut expected)?;
            let actual = sha256(&entry);
            if actual != expected {
                return Err(PipelineError::InvalidExistingOnionLayout(format!(
                    "index leaf hash mismatch at group {group}, bin {bin}"
                )));
            }
            leaves.push(actual);
        }
        roots.push(build_onion_group_tree(leaves, entry_size as usize / MERKLE_HASH_SIZE).root);
    }
    ensure_reader_eof(&mut hashes, hashes_path)?;
    Ok(roots)
}

fn verify_existing_chunk_leaf_hashes(
    cuckoo: &File,
    header_size: usize,
    packed: &File,
    hashes_path: &Path,
    bins_per_table: u32,
    entry_size: u32,
) -> Result<Vec<Hash256>, PipelineError> {
    let mut hashes = BufReader::new(File::open(hashes_path)?);
    verify_hash_header(&mut hashes, hashes_path, CHUNK_K as u32, bins_per_table)?;
    let mut entry = vec![0u8; entry_size as usize];
    let zero_hash = sha256(&entry);
    let mut expected = [0u8; MERKLE_HASH_SIZE];
    let mut id_bytes = [0u8; 4];
    let mut roots = Vec::with_capacity(CHUNK_K);
    for group in 0..CHUNK_K {
        let mut leaves = Vec::with_capacity(bins_per_table as usize);
        for bin in 0..bins_per_table as usize {
            let ordinal = group * bins_per_table as usize + bin;
            cuckoo.read_exact_at(&mut id_bytes, (header_size + ordinal * 4) as u64)?;
            let entry_id = u32::from_le_bytes(id_bytes);
            let actual = if entry_id == EMPTY {
                zero_hash
            } else {
                packed.read_exact_at(&mut entry, entry_id as u64 * entry_size as u64)?;
                sha256(&entry)
            };
            hashes.read_exact(&mut expected)?;
            if actual != expected {
                return Err(PipelineError::InvalidExistingOnionLayout(format!(
                    "chunk leaf hash mismatch at group {group}, bin {bin}"
                )));
            }
            leaves.push(actual);
        }
        roots.push(build_onion_group_tree(leaves, entry_size as usize / MERKLE_HASH_SIZE).root);
    }
    ensure_reader_eof(&mut hashes, hashes_path)?;
    Ok(roots)
}

fn verify_hash_header(
    reader: &mut impl Read,
    path: &Path,
    expected_k: u32,
    expected_bins: u32,
) -> Result<(), PipelineError> {
    let mut header = [0u8; 8];
    reader.read_exact(&mut header)?;
    let k = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let bins = u32::from_le_bytes(header[4..8].try_into().unwrap());
    if k != expected_k || bins != expected_bins {
        return Err(PipelineError::InvalidBinHashes {
            path: path.to_path_buf(),
            reason: format!("k={k}, bins={bins}; expected k={expected_k}, bins={expected_bins}"),
        });
    }
    Ok(())
}

fn ensure_reader_eof(reader: &mut impl Read, path: &Path) -> Result<(), PipelineError> {
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(PipelineError::InvalidBinHashes {
            path: path.to_path_buf(),
            reason: "trailing bytes".into(),
        });
    }
    Ok(())
}

fn verify_existing_tree_tops(
    path: &Path,
    roots: &[Hash256],
    index_bins: u32,
    chunk_bins: u32,
    arity: u32,
) -> Result<(), PipelineError> {
    let data = std::fs::read(path)?;
    if data.len() < 4 {
        return Err(PipelineError::InvalidExistingOnionLayout(format!(
            "{} is truncated",
            path.display()
        )));
    }
    let tree_count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if tree_count != roots.len() {
        return Err(PipelineError::InvalidExistingOnionLayout(format!(
            "tree-top count {tree_count} does not equal root count {}",
            roots.len()
        )));
    }
    let mut pos = 4usize;
    for (tree, root) in roots.iter().enumerate() {
        if pos + 8 > data.len() {
            return Err(PipelineError::InvalidExistingOnionLayout(format!(
                "tree-top record {tree} is truncated"
            )));
        }
        let cache_from = data[pos];
        let total_nodes = u32::from_le_bytes(data[pos + 1..pos + 5].try_into().unwrap());
        let record_arity = u16::from_le_bytes(data[pos + 5..pos + 7].try_into().unwrap()) as u32;
        let levels = data[pos + 7] as usize;
        pos += 8;
        let bins = if tree < INDEX_K {
            index_bins
        } else {
            chunk_bins
        };
        let mut expected_count = bins.div_ceil(arity);
        let mut seen_nodes = 0u32;
        let mut last_root = None;
        if cache_from != ONION_MERKLE_CACHE_FROM_LEVEL as u8 || record_arity != arity {
            return Err(PipelineError::InvalidExistingOnionLayout(format!(
                "tree-top record {tree} has wrong cache level or arity"
            )));
        }
        for level in 0..levels {
            if pos + 4 > data.len() {
                return Err(PipelineError::InvalidExistingOnionLayout(format!(
                    "tree-top record {tree} level header is truncated"
                )));
            }
            let count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            pos += 4;
            if count != expected_count {
                return Err(PipelineError::InvalidExistingOnionLayout(format!(
                    "tree-top record {tree} level {level} has {count} nodes, expected {expected_count}"
                )));
            }
            let bytes = count as usize * MERKLE_HASH_SIZE;
            if pos + bytes > data.len() {
                return Err(PipelineError::InvalidExistingOnionLayout(format!(
                    "tree-top record {tree} level {level} body is truncated"
                )));
            }
            if count == 1 {
                last_root = Some(data[pos..pos + MERKLE_HASH_SIZE].try_into().unwrap());
            }
            pos += bytes;
            seen_nodes += count;
            expected_count = count.div_ceil(arity);
        }
        if seen_nodes != total_nodes || last_root.as_ref() != Some(root) || expected_count != 1 {
            return Err(PipelineError::InvalidExistingOnionLayout(format!(
                "tree-top record {tree} totals or root mismatch"
            )));
        }
    }
    if pos != data.len() {
        return Err(PipelineError::InvalidExistingOnionLayout(
            "tree-top file has trailing bytes".into(),
        ));
    }
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("out");
    path.with_file_name(format!("{file_name}.tmp-{}", std::process::id()))
}

fn write_index_cuckoo_header<W: Write>(
    writer: &mut W,
    bins_per_table: u32,
    options: &IndexCuckooOptions,
) -> Result<(), PipelineError> {
    let anchor = header_anchor(options.snapshot_anchor, options.delta_anchor);
    let magic = cuckoo_magic(INDEX_CUCKOO_MAGIC, anchor.as_ref());
    writer.write_all(&magic.to_le_bytes())?;
    writer.write_all(&(INDEX_K as u32).to_le_bytes())?;
    writer.write_all(&(INDEX_SLOTS_PER_BIN as u32).to_le_bytes())?;
    writer.write_all(&bins_per_table.to_le_bytes())?;
    writer.write_all(&(INDEX_PBC_HASHES as u32).to_le_bytes())?;
    writer.write_all(&options.master_seed.to_le_bytes())?;
    writer.write_all(&options.tag_seed.to_le_bytes())?;
    if let Some(anchor) = anchor {
        anchor.write_to(writer)?;
    }
    Ok(())
}

fn write_chunk_cuckoo_header<W: Write>(
    writer: &mut W,
    bins_per_table: u32,
    options: &ChunkCuckooOptions,
) -> Result<(), PipelineError> {
    let anchor = header_anchor(options.snapshot_anchor, options.delta_anchor);
    let magic = cuckoo_magic(CHUNK_CUCKOO_MAGIC, anchor.as_ref());
    writer.write_all(&magic.to_le_bytes())?;
    writer.write_all(&(CHUNK_K as u32).to_le_bytes())?;
    writer.write_all(&(CHUNK_SLOTS_PER_BIN as u32).to_le_bytes())?;
    writer.write_all(&bins_per_table.to_le_bytes())?;
    writer.write_all(&(CHUNK_PBC_HASHES as u32).to_le_bytes())?;
    writer.write_all(&options.master_seed.to_le_bytes())?;
    if let Some(anchor) = anchor {
        anchor.write_to(writer)?;
    }
    Ok(())
}

fn index_cuckoo_header_size(options: &IndexCuckooOptions) -> usize {
    INDEX_CUCKOO_HEADER_SIZE
        + header_anchor(options.snapshot_anchor, options.delta_anchor).map_or(0, |a| a.len())
}

fn chunk_cuckoo_header_size(options: &ChunkCuckooOptions) -> usize {
    CHUNK_CUCKOO_HEADER_SIZE
        + header_anchor(options.snapshot_anchor, options.delta_anchor).map_or(0, |a| a.len())
}

fn header_anchor(
    snapshot_anchor: Option<[u8; CHAIN_ANCHOR_BYTES]>,
    delta_anchor: Option<[u8; DELTA_ANCHOR_BYTES]>,
) -> Option<HeaderAnchorBytes> {
    match (snapshot_anchor, delta_anchor) {
        (Some(_), Some(_)) => {
            panic!("snapshot_anchor and delta_anchor are mutually exclusive")
        }
        (Some(anchor), None) => Some(HeaderAnchorBytes::Snapshot(anchor)),
        (None, Some(anchor)) => Some(HeaderAnchorBytes::Delta(anchor)),
        (None, None) => None,
    }
}

fn cuckoo_magic(legacy_magic: u64, anchor: Option<&HeaderAnchorBytes>) -> u64 {
    anchor.map_or(legacy_magic, |anchor| anchor.magic(legacy_magic))
}

fn write_index_entry<W: Write>(
    writer: &mut W,
    script_hash: &[u8; SCRIPT_HASH_SIZE],
    start_chunk_id: u32,
    num_chunks: u8,
) -> Result<(), PipelineError> {
    writer.write_all(script_hash)?;
    writer.write_all(&start_chunk_id.to_le_bytes())?;
    writer.write_all(&[num_chunks])?;
    Ok(())
}

fn validate_onion_entry_size(entry_size: usize) -> Result<(), PipelineError> {
    if entry_size == 0 || entry_size > u16::MAX as usize {
        return Err(PipelineError::InvalidOnionEntrySize(entry_size));
    }
    Ok(())
}

fn onion_index_slots_per_bin(entry_size: usize) -> Result<usize, PipelineError> {
    let slots_per_bin = entry_size / ONION_INDEX_SLOT_SIZE;
    if slots_per_bin == 0 || slots_per_bin > u16::MAX as usize {
        return Err(PipelineError::InvalidOnionIndexEntrySize {
            entry_size,
            slot_size: ONION_INDEX_SLOT_SIZE,
        });
    }
    Ok(slots_per_bin)
}

fn onion_merkle_arity(entry_size: usize) -> Result<usize, PipelineError> {
    if entry_size == 0 || entry_size % MERKLE_HASH_SIZE != 0 {
        return Err(PipelineError::InvalidOnionMerkleArity { entry_size });
    }
    Ok(entry_size / MERKLE_HASH_SIZE)
}

struct OnionBinHashes {
    k: usize,
    bins_per_table: usize,
    hashes: Vec<Hash256>,
}

fn read_onion_bin_hashes(path: &Path) -> Result<OnionBinHashes, PipelineError> {
    let data = std::fs::read(path)?;
    if data.len() < 8 {
        return Err(PipelineError::InvalidBinHashes {
            path: path.to_path_buf(),
            reason: "file too small for 8-byte header".into(),
        });
    }
    let k = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let bins_per_table = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    if k == 0 || bins_per_table == 0 {
        return Err(PipelineError::InvalidBinHashes {
            path: path.to_path_buf(),
            reason: format!("k={k}, bins_per_table={bins_per_table}; both must be nonzero"),
        });
    }
    let total_bins =
        k.checked_mul(bins_per_table)
            .ok_or_else(|| PipelineError::InvalidBinHashes {
                path: path.to_path_buf(),
                reason: "k * bins_per_table overflow".into(),
            })?;
    let expected = 8 + total_bins * MERKLE_HASH_SIZE;
    if data.len() != expected {
        return Err(PipelineError::InvalidBinHashes {
            path: path.to_path_buf(),
            reason: format!("expected {expected} bytes, got {}", data.len()),
        });
    }

    let mut hashes = Vec::with_capacity(total_bins);
    for i in 0..total_bins {
        let off = 8 + i * MERKLE_HASH_SIZE;
        let mut h = [0u8; MERKLE_HASH_SIZE];
        h.copy_from_slice(&data[off..off + MERKLE_HASH_SIZE]);
        hashes.push(h);
    }
    Ok(OnionBinHashes {
        k,
        bins_per_table,
        hashes,
    })
}

fn build_onion_tree_kind(
    k: usize,
    bins_per_table: usize,
    hashes: &[Hash256],
    arity: usize,
) -> Vec<PerGroupTree> {
    (0..k)
        .map(|group_id| {
            let start = group_id * bins_per_table;
            build_onion_group_tree(hashes[start..start + bins_per_table].to_vec(), arity)
        })
        .collect()
}

fn build_onion_group_tree(leaf_hashes: Vec<Hash256>, arity: usize) -> PerGroupTree {
    let mut levels = vec![leaf_hashes];
    loop {
        let prev = levels.last().unwrap();
        if prev.len() <= 1 {
            break;
        }
        let mut next = Vec::with_capacity(prev.len().div_ceil(arity));
        for i in 0..prev.len().div_ceil(arity) {
            let start = i * arity;
            let end = (start + arity).min(prev.len());
            let mut children = prev[start..end].to_vec();
            children.resize(arity, ZERO_HASH);
            next.push(compute_parent_n(&children));
        }
        levels.push(next);
    }
    let root = levels.last().unwrap()[0];
    PerGroupTree { levels, root }
}

fn write_onion_tree_tops(
    path: &Path,
    index_trees: &[PerGroupTree],
    data_trees: &[PerGroupTree],
    arity: usize,
) -> Result<(), PipelineError> {
    let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, File::create_new(path)?);
    writer.write_all(&((index_trees.len() + data_trees.len()) as u32).to_le_bytes())?;
    for tree in index_trees.iter().chain(data_trees.iter()) {
        write_one_tree_top_with_arity(&mut writer, tree, ONION_MERKLE_CACHE_FROM_LEVEL, arity)?;
    }
    writer.flush()?;
    Ok(())
}

fn onion_sibling_rows_per_group(trees: &[PerGroupTree]) -> usize {
    trees
        .first()
        .and_then(|tree| tree.levels.get(ONION_MERKLE_CACHE_FROM_LEVEL))
        .map_or(0, Vec::len)
}

fn write_onion_sibling_rows(
    path: &Path,
    trees: &[PerGroupTree],
    arity: usize,
    row_bytes: usize,
    magic: u64,
) -> Result<u64, PipelineError> {
    let rows_per_group = onion_sibling_rows_per_group(trees);
    let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, File::create_new(path)?);
    writer.write_all(&magic.to_le_bytes())?;
    writer.write_all(&(trees.len() as u32).to_le_bytes())?;
    writer.write_all(&(arity as u32).to_le_bytes())?;
    writer.write_all(&(rows_per_group as u32).to_le_bytes())?;
    writer.write_all(&(row_bytes as u32).to_le_bytes())?;

    let mut row = vec![0u8; row_bytes];
    for tree in trees {
        let group_rows = tree
            .levels
            .get(ONION_MERKLE_CACHE_FROM_LEVEL)
            .map_or(0, Vec::len);
        debug_assert_eq!(group_rows, rows_per_group);
        let leaves = &tree.levels[0];
        for r in 0..rows_per_group {
            row.fill(0);
            for c in 0..arity {
                let leaf_idx = r * arity + c;
                if leaf_idx >= leaves.len() {
                    break;
                }
                let dst = c * MERKLE_HASH_SIZE;
                row[dst..dst + MERKLE_HASH_SIZE].copy_from_slice(&leaves[leaf_idx]);
            }
            writer.write_all(&row)?;
        }
    }
    writer.flush()?;
    Ok(ONION_MERKLE_SIB_ROWS_HEADER_SIZE as u64
        + trees.len() as u64 * rows_per_group as u64 * row_bytes as u64)
}

fn write_one_tree_top_with_arity<W: Write>(
    writer: &mut W,
    tree: &PerGroupTree,
    cache_from_level: usize,
    arity: usize,
) -> Result<(), PipelineError> {
    let num_cached_levels = tree.levels.len().saturating_sub(cache_from_level);
    let total_nodes: usize = tree.levels[cache_from_level..].iter().map(Vec::len).sum();
    writer.write_all(&[cache_from_level as u8])?;
    writer.write_all(&(total_nodes as u32).to_le_bytes())?;
    writer.write_all(&(arity as u16).to_le_bytes())?;
    writer.write_all(&[num_cached_levels as u8])?;
    for level in &tree.levels[cache_from_level..] {
        writer.write_all(&(level.len() as u32).to_le_bytes())?;
        for hash in level {
            writer.write_all(hash)?;
        }
    }
    Ok(())
}

fn write_onion_index_entry<W: Write>(
    writer: &mut W,
    script_hash: &[u8; SCRIPT_HASH_SIZE],
    entry_id: u32,
    byte_offset: u16,
    num_entries: u8,
) -> Result<(), PipelineError> {
    writer.write_all(script_hash)?;
    writer.write_all(&entry_id.to_le_bytes())?;
    writer.write_all(&byte_offset.to_le_bytes())?;
    writer.write_all(&[num_entries])?;
    Ok(())
}

struct OnionPacker<W: Write> {
    writer: W,
    current_entry: Vec<u8>,
    current_pos: usize,
    entry_count: u64,
    total_padding: u64,
    total_data: u64,
    entry_size: usize,
}

impl<W: Write> OnionPacker<W> {
    fn new(writer: W, entry_size: usize) -> Self {
        Self {
            writer,
            current_entry: vec![0u8; entry_size],
            current_pos: 0,
            entry_count: 0,
            total_padding: 0,
            total_data: 0,
            entry_size,
        }
    }

    fn pack(
        &mut self,
        script_hash: &[u8; SCRIPT_HASH_SIZE],
        data: &[u8],
    ) -> Result<(u32, u16, u8), PipelineError> {
        let data_len = data.len();
        self.total_data += data_len as u64;

        if data_len == 0 {
            return Ok((self.current_entry_id()?, self.current_pos as u16, 1));
        }

        let remaining = self.entry_size - self.current_pos;
        if data_len <= remaining {
            let entry_id = self.current_entry_id()?;
            let offset = self.current_pos;
            self.current_entry[self.current_pos..self.current_pos + data_len].copy_from_slice(data);
            self.current_pos += data_len;
            if self.current_pos == self.entry_size {
                self.write_full_current_entry()?;
            }
            return Ok((entry_id, offset as u16, 1));
        }

        self.flush_partial_entry()?;
        let entry_id_u64 = self.entry_count;
        let entry_id = self.current_entry_id()?;

        if data_len <= self.entry_size {
            self.current_entry[..data_len].copy_from_slice(data);
            self.current_pos = data_len;
            if self.current_pos == self.entry_size {
                self.write_full_current_entry()?;
            }
            return Ok((entry_id, 0, 1));
        }

        let num_entries = data_len.div_ceil(self.entry_size);
        if num_entries > u8::MAX as usize {
            return Err(PipelineError::OnionSpanOverflow {
                script_hash: *script_hash,
                bytes: data_len,
                entries: num_entries,
            });
        }
        if entry_id_u64 + num_entries as u64 - 1 > u32::MAX as u64 {
            return Err(PipelineError::OnionEntryIdOverflow(
                entry_id_u64 + num_entries as u64 - 1,
            ));
        }

        let mut written = 0;
        for i in 0..num_entries {
            let chunk_len = (data_len - written).min(self.entry_size);
            self.current_entry[..chunk_len].copy_from_slice(&data[written..written + chunk_len]);
            written += chunk_len;

            if i < num_entries - 1 {
                self.write_full_current_entry()?;
            } else {
                self.current_pos = chunk_len;
                if self.current_pos == self.entry_size {
                    self.write_full_current_entry()?;
                }
            }
        }

        Ok((entry_id, 0, num_entries as u8))
    }

    fn finish(&mut self) -> Result<(), PipelineError> {
        self.flush_partial_entry()?;
        self.writer.flush()?;
        Ok(())
    }

    fn current_entry_id(&self) -> Result<u32, PipelineError> {
        if self.entry_count > u32::MAX as u64 {
            return Err(PipelineError::OnionEntryIdOverflow(self.entry_count));
        }
        Ok(self.entry_count as u32)
    }

    fn flush_partial_entry(&mut self) -> Result<(), PipelineError> {
        if self.current_pos > 0 {
            self.writer.write_all(&self.current_entry)?;
            self.total_padding += (self.entry_size - self.current_pos) as u64;
            self.entry_count += 1;
            self.current_entry.fill(0);
            self.current_pos = 0;
        }
        Ok(())
    }

    fn write_full_current_entry(&mut self) -> Result<(), PipelineError> {
        self.writer.write_all(&self.current_entry)?;
        self.entry_count += 1;
        self.current_entry.fill(0);
        self.current_pos = 0;
        Ok(())
    }
}

fn build_onion_index_cuckoo_table(
    group_id: usize,
    entries: &[u32],
    index_data: &[u8],
    bins_per_table: usize,
    slots_per_bin: usize,
    master_seed: u64,
) -> Option<Vec<u32>> {
    let total_slots = bins_per_table * slots_per_bin;
    let mut table = vec![EMPTY; total_slots];
    let mut bin_occupancy = vec![0usize; bins_per_table];
    let key0 = derive_cuckoo_key(master_seed, group_id, 0);
    let key1 = derive_cuckoo_key(master_seed, group_id, 1);

    for &idx in entries {
        let script_hash = onion_index_script_hash(index_data, idx);
        let bin0 = cuckoo_hash(script_hash, key0, bins_per_table);
        let bin1 = cuckoo_hash(script_hash, key1, bins_per_table);
        let (first, second) = if bin_occupancy[bin0] <= bin_occupancy[bin1] {
            (bin0, bin1)
        } else {
            (bin1, bin0)
        };

        if place_onion_index_slot(&mut table, &mut bin_occupancy, slots_per_bin, first, idx)
            || place_onion_index_slot(&mut table, &mut bin_occupancy, slots_per_bin, second, idx)
        {
            continue;
        }

        let mut current_idx = idx;
        let mut current_bin = first;
        let mut success = false;
        for kick in 0..CUCKOO_MAX_KICKS {
            let occ = bin_occupancy[current_bin];
            let evict_slot = kick % occ;
            let slot_index = current_bin * slots_per_bin + evict_slot;
            let evicted = table[slot_index];
            table[slot_index] = current_idx;

            let ev_script_hash = onion_index_script_hash(index_data, evicted);
            let ev_bin0 = cuckoo_hash(ev_script_hash, key0, bins_per_table);
            let ev_bin1 = cuckoo_hash(ev_script_hash, key1, bins_per_table);
            let alt_bin = if ev_bin0 == current_bin {
                ev_bin1
            } else {
                ev_bin0
            };

            if place_onion_index_slot(
                &mut table,
                &mut bin_occupancy,
                slots_per_bin,
                alt_bin,
                evicted,
            ) {
                success = true;
                break;
            }

            current_idx = evicted;
            current_bin = alt_bin;
        }

        if !success {
            return None;
        }
    }

    Some(table)
}

fn place_onion_index_slot(
    table: &mut [u32],
    bin_occupancy: &mut [usize],
    slots_per_bin: usize,
    bin: usize,
    idx: u32,
) -> bool {
    let occ = bin_occupancy[bin];
    if occ >= slots_per_bin {
        return false;
    }
    table[bin * slots_per_bin + occ] = idx;
    bin_occupancy[bin] += 1;
    true
}

fn onion_index_script_hash(index_data: &[u8], idx: u32) -> &[u8] {
    let base = idx as usize * ONION_INDEX_RECORD_SIZE;
    &index_data[base..base + SCRIPT_HASH_SIZE]
}

fn write_onion_index_bins_and_hashes(
    bins_path: &Path,
    bin_hashes_path: &Path,
    tables: &[Vec<u32>],
    index_data: &[u8],
    bins_per_table: usize,
    slots_per_bin: usize,
    options: &OnionIndexCuckooOptions,
) -> Result<(), PipelineError> {
    let mut bins_writer = BufWriter::with_capacity(1024 * 1024, File::create_new(bins_path)?);
    let mut hashes_writer =
        BufWriter::with_capacity(1024 * 1024, File::create_new(bin_hashes_path)?);
    hashes_writer.write_all(&(INDEX_K as u32).to_le_bytes())?;
    hashes_writer.write_all(&(bins_per_table as u32).to_le_bytes())?;

    let mut bin = vec![0u8; options.entry_size];
    for table in tables {
        for bin_index in 0..bins_per_table {
            serialize_onion_index_bin(
                &mut bin,
                table,
                bin_index,
                index_data,
                slots_per_bin,
                options.tag_seed,
            );
            bins_writer.write_all(&bin)?;
            let hash = sha256(&bin);
            hashes_writer.write_all(&hash)?;
        }
    }
    bins_writer.flush()?;
    hashes_writer.flush()?;
    Ok(())
}

fn serialize_onion_index_bin(
    out: &mut [u8],
    table: &[u32],
    bin: usize,
    index_data: &[u8],
    slots_per_bin: usize,
    tag_seed: u64,
) {
    out.fill(0);
    let base = bin * slots_per_bin;
    for slot in 0..slots_per_bin {
        let idx = table[base + slot];
        if idx == EMPTY {
            continue;
        }

        let record_base = idx as usize * ONION_INDEX_RECORD_SIZE;
        let script_hash = &index_data[record_base..record_base + SCRIPT_HASH_SIZE];
        let tag = compute_tag(tag_seed, script_hash);
        let slot_offset = slot * ONION_INDEX_SLOT_SIZE;
        out[slot_offset..slot_offset + 8].copy_from_slice(&tag.to_le_bytes());
        out[slot_offset + 8..slot_offset + ONION_INDEX_SLOT_SIZE].copy_from_slice(
            &index_data[record_base + SCRIPT_HASH_SIZE..record_base + ONION_INDEX_RECORD_SIZE],
        );
    }
}

fn write_onion_index_meta(
    path: &Path,
    bins_per_table: u32,
    slots_per_bin: usize,
    options: &OnionIndexCuckooOptions,
) -> Result<(), PipelineError> {
    let mut writer = BufWriter::new(File::create_new(path)?);
    let anchor = header_anchor(options.snapshot_anchor, options.delta_anchor);
    let magic = cuckoo_magic(ONION_INDEX_META_MAGIC, anchor.as_ref());
    writer.write_all(&magic.to_le_bytes())?;
    writer.write_all(&(INDEX_K as u32).to_le_bytes())?;
    writer.write_all(&(ONION_INDEX_CUCKOO_HASHES as u32).to_le_bytes())?;
    writer.write_all(&(slots_per_bin as u32).to_le_bytes())?;
    writer.write_all(&bins_per_table.to_le_bytes())?;
    writer.write_all(&options.master_seed.to_le_bytes())?;
    writer.write_all(&options.tag_seed.to_le_bytes())?;
    writer.write_all(&(ONION_INDEX_SLOT_SIZE as u32).to_le_bytes())?;
    if let Some(anchor) = anchor {
        anchor.write_to(&mut writer)?;
    }
    writer.flush()?;
    Ok(())
}

fn build_onion_data_cuckoo_table(
    entries: &[u32],
    keys: &[u64; ONION_DATA_CUCKOO_HASHES],
    bins_per_table: usize,
) -> Option<Vec<u32>> {
    let mut table = vec![EMPTY; bins_per_table];

    for &entry_id in entries {
        let mut placed = false;
        for &key in keys {
            let bin = cuckoo_hash_int(entry_id, key, bins_per_table);
            if table[bin] == EMPTY {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if placed {
            continue;
        }

        let mut current_id = entry_id;
        let mut current_hash_fn = 0;
        let mut current_bin = cuckoo_hash_int(entry_id, keys[0], bins_per_table);
        let mut success = false;

        for kick in 0..CUCKOO_MAX_KICKS {
            let evicted = table[current_bin];
            table[current_bin] = current_id;

            let mut found_empty = false;
            for h in 0..ONION_DATA_CUCKOO_HASHES {
                let try_h = (current_hash_fn + 1 + h) % ONION_DATA_CUCKOO_HASHES;
                let bin = cuckoo_hash_int(evicted, keys[try_h], bins_per_table);
                if bin == current_bin {
                    continue;
                }
                if table[bin] == EMPTY {
                    table[bin] = evicted;
                    found_empty = true;
                    success = true;
                    break;
                }
            }
            if found_empty {
                break;
            }

            let alt_h = (current_hash_fn + 1 + kick % (ONION_DATA_CUCKOO_HASHES - 1))
                % ONION_DATA_CUCKOO_HASHES;
            let alt_bin = cuckoo_hash_int(evicted, keys[alt_h], bins_per_table);
            let final_bin = if alt_bin == current_bin {
                cuckoo_hash_int(
                    evicted,
                    keys[(alt_h + 1) % ONION_DATA_CUCKOO_HASHES],
                    bins_per_table,
                )
            } else {
                alt_bin
            };

            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }

        if !success {
            return None;
        }
    }

    Some(table)
}

fn write_onion_data_cuckoo_file(
    path: &Path,
    tables: &[Vec<u32>],
    bins_per_table: u32,
    packed_entries: u64,
    options: &OnionDataCuckooOptions,
) -> Result<(), PipelineError> {
    let mut writer = BufWriter::with_capacity(1024 * 1024, File::create_new(path)?);
    let anchor = header_anchor(options.snapshot_anchor, options.delta_anchor);
    let magic = cuckoo_magic(ONION_DATA_CUCKOO_MAGIC, anchor.as_ref());
    writer.write_all(&magic.to_le_bytes())?;
    writer.write_all(&(CHUNK_K as u32).to_le_bytes())?;
    writer.write_all(&(ONION_DATA_CUCKOO_HASHES as u32).to_le_bytes())?;
    writer.write_all(&bins_per_table.to_le_bytes())?;
    writer.write_all(&options.master_seed.to_le_bytes())?;
    writer.write_all(&(packed_entries as u32).to_le_bytes())?;
    writer.write_all(&[0u8; 4])?;
    if let Some(anchor) = anchor {
        anchor.write_to(&mut writer)?;
    }

    for table in tables {
        for &entry_id in table {
            writer.write_all(&entry_id.to_le_bytes())?;
        }
    }
    writer.flush()?;
    Ok(())
}

fn write_onion_data_bin_hashes(
    path: &Path,
    packed_path: &Path,
    tables: &[Vec<u32>],
    bins_per_table: usize,
    options: &OnionDataCuckooOptions,
) -> Result<u64, PipelineError> {
    let packed_file = File::open(packed_path)?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, File::create_new(path)?);
    writer.write_all(&(CHUNK_K as u32).to_le_bytes())?;
    writer.write_all(&(bins_per_table as u32).to_le_bytes())?;

    let zero_entry = vec![0u8; options.entry_size];
    let zero_hash = sha256(&zero_entry);
    let mut entry = vec![0u8; options.entry_size];
    for table in tables {
        for &entry_id in table.iter().take(bins_per_table) {
            let hash = if entry_id == EMPTY {
                zero_hash
            } else {
                read_packed_entry_at(&packed_file, options.entry_size, entry_id, &mut entry)?;
                sha256(&entry)
            };
            writer.write_all(&hash)?;
        }
    }
    writer.flush()?;
    Ok(8 + CHUNK_K as u64 * bins_per_table as u64 * MERKLE_HASH_SIZE as u64)
}

fn read_packed_entry_at(
    file: &File,
    entry_size: usize,
    entry_id: u32,
    buf: &mut [u8],
) -> Result<(), PipelineError> {
    debug_assert_eq!(buf.len(), entry_size);
    let mut read = 0usize;
    let offset = entry_id as u64 * entry_size as u64;
    while read < entry_size {
        let n = file.read_at(&mut buf[read..], offset + read as u64)?;
        if n == 0 {
            return Err(PipelineError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("short read for packed onion entry {entry_id}"),
            )));
        }
        read += n;
    }
    Ok(())
}

fn compute_bins_per_table(max_load: usize, slots_per_bin: usize) -> usize {
    (max_load as f64 / (slots_per_bin as f64 * CUCKOO_LOAD_FACTOR)).ceil() as usize
}

fn max_retry_bins(initial_bins: usize) -> usize {
    initial_bins.saturating_add(1024).max(initial_bins * 2)
}

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

#[inline]
fn sh_a(script_hash: &[u8]) -> u64 {
    u64::from_le_bytes(script_hash[0..8].try_into().unwrap())
}

#[inline]
fn sh_b(script_hash: &[u8]) -> u64 {
    u64::from_le_bytes(script_hash[8..16].try_into().unwrap())
}

#[inline]
fn sh_c(script_hash: &[u8]) -> u64 {
    u32::from_le_bytes(script_hash[16..20].try_into().unwrap()) as u64
}

#[inline]
fn hash_for_group(script_hash: &[u8], nonce: u64) -> u64 {
    let mut h = sh_a(script_hash).wrapping_add(nonce.wrapping_mul(GOLDEN_RATIO));
    h ^= sh_b(script_hash);
    splitmix64(h ^ sh_c(script_hash))
}

#[inline]
fn hash_int_for_group(id: u32, nonce: u64) -> u64 {
    splitmix64((id as u64).wrapping_add(nonce.wrapping_mul(GOLDEN_RATIO)))
}

fn derive_groups_3(script_hash: &[u8], k: usize) -> [usize; INDEX_PBC_HASHES] {
    let mut groups = [0usize; INDEX_PBC_HASHES];
    let mut nonce = 0u64;
    let mut count = 0;
    while count < INDEX_PBC_HASHES {
        let group = (hash_for_group(script_hash, nonce) % k as u64) as usize;
        nonce += 1;
        if groups.iter().take(count).any(|&g| g == group) {
            continue;
        }
        groups[count] = group;
        count += 1;
    }
    groups
}

fn derive_int_groups_3(id: u32, k: usize) -> [usize; CHUNK_PBC_HASHES] {
    let mut groups = [0usize; CHUNK_PBC_HASHES];
    let mut nonce = 0u64;
    let mut count = 0;
    while count < CHUNK_PBC_HASHES {
        let group = (hash_int_for_group(id, nonce) % k as u64) as usize;
        nonce += 1;
        if groups.iter().take(count).any(|&g| g == group) {
            continue;
        }
        groups[count] = group;
        count += 1;
    }
    groups
}

#[inline]
fn derive_cuckoo_key(master_seed: u64, group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        master_seed
            .wrapping_add((group_id as u64).wrapping_mul(GOLDEN_RATIO))
            .wrapping_add((hash_fn as u64).wrapping_mul(CUCKOO_KEY_MIX)),
    )
}

#[inline]
fn cuckoo_hash(script_hash: &[u8], key: u64, num_bins: usize) -> usize {
    let mut h = sh_a(script_hash) ^ key;
    h ^= sh_b(script_hash);
    h = splitmix64(h ^ sh_c(script_hash));
    (h % num_bins as u64) as usize
}

#[inline]
fn cuckoo_hash_int(id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((id as u64) ^ key) % num_bins as u64) as usize
}

#[inline]
fn compute_tag(tag_seed: u64, script_hash: &[u8]) -> u64 {
    let mut h = sh_a(script_hash) ^ tag_seed;
    h ^= sh_b(script_hash);
    splitmix64(h ^ sh_c(script_hash))
}

fn cuckoo_insert_index(
    table: &mut [u32],
    index_data: &[u8],
    entries: &[usize],
    local_index: usize,
    keys: &[u64; INDEX_CUCKOO_HASHES],
    bins_per_table: usize,
) -> bool {
    let hash_fn = |idx: usize, hf: usize| -> usize {
        let global_idx = entries[idx];
        let offset = global_idx * INDEX_RECORD_SIZE;
        let script_hash = &index_data[offset..offset + SCRIPT_HASH_SIZE];
        cuckoo_hash(script_hash, keys[hf], bins_per_table)
    };

    for hf in 0..INDEX_CUCKOO_HASHES {
        let bin = hash_fn(local_index, hf);
        let base = bin * INDEX_SLOTS_PER_BIN;
        for s in 0..INDEX_SLOTS_PER_BIN {
            if table[base + s] == EMPTY {
                table[base + s] = local_index as u32;
                return true;
            }
        }
    }

    let mut current = local_index;
    let mut current_bin = hash_fn(current, 0);
    for kick in 0..CUCKOO_MAX_KICKS {
        let base = current_bin * INDEX_SLOTS_PER_BIN;
        let evict_slot = kick % INDEX_SLOTS_PER_BIN;
        let evicted = table[base + evict_slot] as usize;
        table[base + evict_slot] = current as u32;

        let mut alt_bin = current_bin;
        for hf in 0..INDEX_CUCKOO_HASHES {
            let bin = hash_fn(evicted, hf);
            if bin != current_bin {
                alt_bin = bin;
                break;
            }
        }

        let alt_base = alt_bin * INDEX_SLOTS_PER_BIN;
        for s in 0..INDEX_SLOTS_PER_BIN {
            if table[alt_base + s] == EMPTY {
                table[alt_base + s] = evicted as u32;
                return true;
            }
        }

        current = evicted;
        current_bin = alt_bin;
    }

    false
}

fn cuckoo_insert_chunk(
    table: &mut [u32],
    chunk_ids: &[u32],
    local_index: usize,
    keys: &[u64; CHUNK_CUCKOO_HASHES],
    bins_per_table: usize,
) -> bool {
    let hash_fn = |idx: usize, hf: usize| -> usize {
        cuckoo_hash_int(chunk_ids[idx], keys[hf], bins_per_table)
    };

    for hf in 0..CHUNK_CUCKOO_HASHES {
        let bin = hash_fn(local_index, hf);
        let base = bin * CHUNK_SLOTS_PER_BIN;
        for s in 0..CHUNK_SLOTS_PER_BIN {
            if table[base + s] == EMPTY {
                table[base + s] = local_index as u32;
                return true;
            }
        }
    }

    let mut current = local_index;
    let mut current_bin = hash_fn(current, 0);
    for kick in 0..CUCKOO_MAX_KICKS {
        let base = current_bin * CHUNK_SLOTS_PER_BIN;
        let evict_slot = kick % CHUNK_SLOTS_PER_BIN;
        let evicted = table[base + evict_slot] as usize;
        table[base + evict_slot] = current as u32;

        let mut alt_bin = current_bin;
        for hf in 0..CHUNK_CUCKOO_HASHES {
            let bin = hash_fn(evicted, hf);
            if bin != current_bin {
                alt_bin = bin;
                break;
            }
        }

        let alt_base = alt_bin * CHUNK_SLOTS_PER_BIN;
        for s in 0..CHUNK_SLOTS_PER_BIN {
            if table[alt_base + s] == EMPTY {
                table[alt_base + s] = evicted as u32;
                return true;
            }
        }

        current = evicted;
        current_bin = alt_bin;
    }

    false
}

fn push_top_entry(heap: &mut BinaryHeap<Reverse<TopEntry>>, entry: TopEntry) {
    if heap.len() < TOP_N {
        heap.push(Reverse(entry));
    } else if entry.0 > heap.peek().expect("heap nonempty").0 .0 {
        heap.pop();
        heap.push(Reverse(entry));
    }
}

fn write_top100(path: &Path, heap: BinaryHeap<Reverse<TopEntry>>) -> Result<(), PipelineError> {
    let mut entries: Vec<TopEntry> = heap
        .into_sorted_vec()
        .into_iter()
        .map(|Reverse(e)| e)
        .collect();
    entries.reverse();
    let mut writer = BufWriter::new(File::create_new(path)?);
    for (data_len, script_hash, first_txid, first_vout) in entries {
        writer.write_all(&script_hash)?;
        writer.write_all(&first_txid)?;
        writer.write_all(&first_vout.to_le_bytes())?;
        writer.write_all(&(data_len as u32).to_le_bytes())?;
    }
    writer.flush()?;
    Ok(())
}

fn write_whales(
    path: &Path,
    whale_entries: &mut Vec<([u8; SCRIPT_HASH_SIZE], usize)>,
    max_utxos_per_spk: usize,
) -> Result<(), PipelineError> {
    whale_entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut writer = BufWriter::new(File::create_new(path)?);
    writeln!(
        writer,
        "# Excluded whale addresses (>{max_utxos_per_spk} UTXOs per scriptPubKey)"
    )?;
    writeln!(writer, "# Format: script_hash_hex  utxo_count")?;
    for (script_hash, count) in whale_entries {
        writeln!(writer, "{}  {count}", hex::encode(script_hash))?;
    }
    writer.flush()?;
    Ok(())
}

fn serialize_group_sorted(entries: &[ShortenedEntry]) -> Vec<u8> {
    let mut data = Vec::with_capacity(entries.len() * (TXID_SIZE + 8) + 4);
    write_varint(&mut data, entries.len() as u64);
    for entry in entries {
        data.extend_from_slice(&entry.txid);
        write_varint(&mut data, entry.vout as u64);
        write_varint(&mut data, entry.amount);
    }
    data
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn write_varint_to_writer<W: Write>(writer: &mut W, mut value: u64) -> Result<(), PipelineError> {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte])?;
        if value == 0 {
            return Ok(());
        }
    }
}

fn read_delta_u32(data: &[u8], pos: &mut usize, path: &Path) -> Result<u32, PipelineError> {
    let bytes = take_delta_bytes(data, pos, 4, path, "u32")?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_delta_varint(data: &[u8], pos: &mut usize, path: &Path) -> Result<u64, PipelineError> {
    let mut shift = 0u32;
    let mut value = 0u64;
    for _ in 0..10 {
        if *pos >= data.len() {
            return Err(PipelineError::InvalidDeltaFormat {
                path: path.to_path_buf(),
                reason: "truncated varint".to_owned(),
            });
        }
        let byte = data[*pos];
        *pos += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(PipelineError::InvalidDeltaFormat {
        path: path.to_path_buf(),
        reason: "varint exceeds 10 bytes".to_owned(),
    })
}

fn take_delta_bytes<'a>(
    data: &'a [u8],
    pos: &mut usize,
    len: usize,
    path: &Path,
    label: &str,
) -> Result<&'a [u8], PipelineError> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| PipelineError::InvalidDeltaFormat {
            path: path.to_path_buf(),
            reason: format!("{label} offset overflow"),
        })?;
    if end > data.len() {
        return Err(PipelineError::InvalidDeltaFormat {
            path: path.to_path_buf(),
            reason: format!("truncated {label}: need {len} bytes at offset {}", *pos),
        });
    }
    let out = &data[*pos..end];
    *pos = end;
    Ok(out)
}

fn read_delta_group_body<'a>(
    data: &'a [u8],
    pos: &mut usize,
    path: &Path,
) -> Result<([u8; SCRIPT_HASH_SIZE], &'a [u8]), PipelineError> {
    let mut script_hash = [0u8; SCRIPT_HASH_SIZE];
    script_hash.copy_from_slice(take_delta_bytes(
        data,
        pos,
        SCRIPT_HASH_SIZE,
        path,
        "script hash",
    )?);
    let body_start = *pos;

    let spent = read_delta_varint(data, pos, path)?;
    for _ in 0..spent {
        take_delta_bytes(data, pos, TXID_SIZE, path, "spent txid")?;
        read_delta_varint(data, pos, path)?;
    }

    let new_utxos = read_delta_varint(data, pos, path)?;
    for _ in 0..new_utxos {
        take_delta_bytes(data, pos, TXID_SIZE, path, "new txid")?;
        read_delta_varint(data, pos, path)?;
        read_delta_varint(data, pos, path)?;
    }

    Ok((script_hash, &data[body_start..*pos]))
}

struct FlatEntryIter {
    reader: BufReader<File>,
    buf: [u8; FLAT_UTXO_ENTRY_SIZE],
}

impl FlatEntryIter {
    fn open(path: &Path) -> Result<Self, PipelineError> {
        Ok(Self {
            reader: BufReader::with_capacity(1024 * 1024, File::open(path)?),
            buf: [0u8; FLAT_UTXO_ENTRY_SIZE],
        })
    }
}

impl Iterator for FlatEntryIter {
    type Item = Result<FlatEntry, PipelineError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_exact(&mut self.buf) {
            Ok(()) => {
                let mut script_hash = [0u8; SCRIPT_HASH_SIZE];
                script_hash.copy_from_slice(&self.buf[..SCRIPT_HASH_SIZE]);
                let mut txid = [0u8; TXID_SIZE];
                txid.copy_from_slice(&self.buf[20..52]);
                Some(Ok(FlatEntry {
                    script_hash,
                    txid,
                    vout: u32::from_le_bytes(self.buf[52..56].try_into().unwrap()),
                    amount: u64::from_le_bytes(self.buf[56..64].try_into().unwrap()),
                    height: u32::from_le_bytes(self.buf[64..68].try_into().unwrap()),
                }))
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => None,
            Err(e) => Some(Err(PipelineError::Io(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGTEST_FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/txoutset_regtest_111.dat"
    );
    const REGTEST_MUHASH: &str = "5b93564046e31a3798231c767eb24e45dd818b77ae022cbe8861e2af9d4a8c09";

    #[test]
    fn varint_matches_legacy_builder_encoding() {
        let mut out = Vec::new();
        for n in [0, 1, 127, 128, 255, 16_384] {
            write_varint(&mut out, n);
        }
        assert_eq!(
            out,
            [0x00, 0x01, 0x7f, 0x80, 0x01, 0xff, 0x01, 0x80, 0x80, 0x01]
        );
    }

    #[test]
    fn delta_from_flat_sets_is_deterministic_and_packs_legacy_format() {
        let dir = fresh_temp_dir("delta-flat");
        let from1 = dir.join("from1.bin");
        let to1 = dir.join("to1.bin");
        let from2 = dir.join("from2.bin");
        let to2 = dir.join("to2.bin");

        let sh1 = [1u8; SCRIPT_HASH_SIZE];
        let sh2 = [2u8; SCRIPT_HASH_SIZE];
        let sh3 = [3u8; SCRIPT_HASH_SIZE];
        let sh4 = [4u8; SCRIPT_HASH_SIZE];
        let sh5 = [5u8; SCRIPT_HASH_SIZE];
        let tx1 = [0x11u8; TXID_SIZE];
        let tx2 = [0x22u8; TXID_SIZE];
        let tx3 = [0x33u8; TXID_SIZE];
        let tx4 = [0x44u8; TXID_SIZE];
        let tx5 = [0x55u8; TXID_SIZE];

        write_flat_entries(
            &from1,
            &[
                (sh1, tx1, 0, 1_000, 10),
                (sh2, tx2, 1, 2_000, 11),
                (sh3, tx3, 2, 100, 12),
            ],
        );
        write_flat_entries(
            &to1,
            &[
                (sh1, tx1, 0, 1_000, 10),
                (sh4, tx4, 3, 3_000, 20),
                (sh5, tx5, 4, 100, 21),
            ],
        );
        write_flat_entries(
            &from2,
            &[
                (sh3, tx3, 2, 100, 12),
                (sh1, tx1, 0, 1_000, 10),
                (sh2, tx2, 1, 2_000, 11),
            ],
        );
        write_flat_entries(
            &to2,
            &[
                (sh5, tx5, 4, 100, 21),
                (sh4, tx4, 3, 3_000, 20),
                (sh1, tx1, 0, 1_000, 10),
            ],
        );

        let grouped1 = dir.join("delta1.bin");
        let grouped2 = dir.join("delta2.bin");
        let report1 = build_grouped_delta_from_flat_sets(
            &from1,
            &to1,
            &grouped1,
            &DeltaBuildOptions::default(),
        )
        .expect("build delta 1");
        let report2 = build_grouped_delta_from_flat_sets(
            &from2,
            &to2,
            &grouped2,
            &DeltaBuildOptions::default(),
        )
        .expect("build delta 2");
        assert_eq!(
            report1,
            DeltaBuildReport {
                from_entries: 3,
                to_entries: 3,
                unchanged_entries: 1,
                spent_entries: 2,
                created_entries: 1,
                dust_created_skipped: 1,
                scripts_changed: 3,
                grouped_file_bytes: 171,
            }
        );
        assert_eq!(report2, report1);
        assert_eq!(
            std::fs::read(&grouped1).unwrap(),
            std::fs::read(&grouped2).unwrap()
        );

        let chunks = dir.join("delta_chunks.bin");
        let index = dir.join("delta_index.bin");
        let chunk_report = build_delta_chunks(&grouped1, &chunks, &index).expect("delta chunks");
        assert_eq!(
            chunk_report,
            DeltaChunkBuildReport {
                scripts: 3,
                chunks_written: 3,
                index_entries: 3,
                skipped_too_large: 0,
                chunks_file_bytes: 120,
                index_file_bytes: 75,
                data_bytes: 107,
                padding_bytes: 13,
            }
        );

        let onion_dir = dir.join("onion");
        let onion_report = build_delta_onion_pack(
            &grouped1,
            &onion_dir,
            &OnionPackOptions {
                entry_size: 64,
                ..Default::default()
            },
        )
        .expect("delta onion pack");
        assert_eq!(
            onion_report,
            DeltaOnionPackReport {
                scripts: 3,
                groups_packed: 3,
                whale_spks_excluded: 0,
                onion_entries: 3,
                packed_file_bytes: 192,
                index_file_bytes: 81,
                data_bytes: 107,
                padding_bytes: 85,
                max_serialized_len: 37,
            }
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn regtest_chunk_build_is_deterministic() {
        let dir = fresh_temp_dir("chunk-determinism");
        let flat = dir.join("utxo_set.bin");
        let flat_report =
            utxosnapshot::materialize_flat_utxo_set(REGTEST_FIXTURE, &flat, REGTEST_MUHASH)
                .expect("materialize flat fixture");
        let mut regtest_anchor = [0u8; CHAIN_ANCHOR_BYTES];
        regtest_anchor[..32].copy_from_slice(&flat_report.header.base_hash);
        regtest_anchor[32..].copy_from_slice(&111u32.to_le_bytes());

        let out1 = dir.join("out1");
        let out2 = dir.join("out2");
        let options = UtxoChunkBuildOptions::default();
        let report1 = build_utxo_chunks(&flat, &out1, &options).expect("build chunks 1");
        let report2 = build_utxo_chunks(&flat, &out2, &options).expect("build chunks 2");

        let expected = UtxoChunkBuildReport {
            input_entries: 115,
            dust_utxos_skipped: 0,
            whale_spks_excluded: 0,
            groups_written: 9,
            index_entries: 9,
            chunks_written: 111,
            chunks_file_bytes: 4_440,
            index_file_bytes: 225,
            data_bytes: 4_375,
            padding_bytes: 65,
        };
        assert_eq!(report1, expected);
        assert_eq!(report2, expected);

        for file in [
            UTXO_CHUNKS_FILENAME,
            UTXO_CHUNKS_INDEX_FILENAME,
            TOP100_FILENAME,
            WHALES_FILENAME,
        ] {
            assert_eq!(
                std::fs::read(out1.join(file)).unwrap(),
                std::fs::read(out2.join(file)).unwrap(),
                "{file} differs across repeated builds"
            );
        }

        let onion_options = OnionPackOptions::default();
        let onion_report1 = build_onion_pack(&flat, &out1, &onion_options).expect("build onion 1");
        let onion_report2 = build_onion_pack(&flat, &out2, &onion_options).expect("build onion 2");
        let expected_onion = OnionPackReport {
            input_entries: 115,
            dust_utxos_skipped: 0,
            whale_spks_excluded: 0,
            groups_packed: 9,
            onion_entries: 3,
            packed_file_bytes: 9_984,
            index_file_bytes: 243,
            data_bytes: 4_375,
            padding_bytes: 5_609,
            max_serialized_len: 3_801,
        };
        assert_eq!(onion_report1, expected_onion);
        assert_eq!(onion_report2, expected_onion);

        for file in [ONION_PACKED_ENTRIES_FILENAME, ONION_INDEX_FILENAME] {
            assert_eq!(
                std::fs::read(out1.join(file)).unwrap(),
                std::fs::read(out2.join(file)).unwrap(),
                "{file} differs across repeated builds"
            );
        }

        let onion_data_report1 = build_onion_data_cuckoo(
            out1.join(ONION_PACKED_ENTRIES_FILENAME),
            &out1,
            &OnionDataCuckooOptions::default(),
        )
        .expect("build onion data cuckoo 1");
        let onion_data_report2 = build_onion_data_cuckoo(
            out2.join(ONION_PACKED_ENTRIES_FILENAME),
            &out2,
            &OnionDataCuckooOptions::default(),
        )
        .expect("build onion data cuckoo 2");
        let expected_onion_data = OnionDataCuckooBuildReport {
            packed_entries: 3,
            bins_per_table: 2,
            output_bytes: 676,
            bin_hashes_file_bytes: 5_128,
            total_placements: 9,
        };
        assert_eq!(onion_data_report1, expected_onion_data);
        assert_eq!(onion_data_report2, expected_onion_data);
        for file in [ONION_CHUNK_CUCKOO_FILENAME, ONION_DATA_BIN_HASHES_FILENAME] {
            assert_eq!(
                std::fs::read(out1.join(file)).unwrap(),
                std::fs::read(out2.join(file)).unwrap(),
                "{file} differs across repeated builds"
            );
        }
        let onion_data_cuckoo_bytes =
            std::fs::read(out1.join(ONION_CHUNK_CUCKOO_FILENAME)).unwrap();
        assert_eq!(
            u64::from_le_bytes(onion_data_cuckoo_bytes[0..8].try_into().unwrap()),
            ONION_DATA_CUCKOO_MAGIC
        );
        assert_eq!(
            u64::from_le_bytes(onion_data_cuckoo_bytes[20..28].try_into().unwrap()),
            LEGACY_CHUNK_MASTER_SEED
        );

        let onion_data_anchor1 = dir.join("onion-data-anchor-1");
        let onion_data_anchor2 = dir.join("onion-data-anchor-2");
        let onion_data_anchor_options = OnionDataCuckooOptions {
            master_seed: 0x875a_2299_804a_46fc,
            snapshot_anchor: Some(regtest_anchor),
            ..Default::default()
        };
        let onion_data_anchor_report1 = build_onion_data_cuckoo(
            out1.join(ONION_PACKED_ENTRIES_FILENAME),
            &onion_data_anchor1,
            &onion_data_anchor_options,
        )
        .expect("build anchored onion data cuckoo 1");
        let onion_data_anchor_report2 = build_onion_data_cuckoo(
            out1.join(ONION_PACKED_ENTRIES_FILENAME),
            &onion_data_anchor2,
            &onion_data_anchor_options,
        )
        .expect("build anchored onion data cuckoo 2");
        let expected_onion_data_anchor = OnionDataCuckooBuildReport {
            output_bytes: 712,
            ..expected_onion_data
        };
        assert_eq!(onion_data_anchor_report1, expected_onion_data_anchor);
        assert_eq!(onion_data_anchor_report2, expected_onion_data_anchor);
        for file in [ONION_CHUNK_CUCKOO_FILENAME, ONION_DATA_BIN_HASHES_FILENAME] {
            assert_eq!(
                std::fs::read(onion_data_anchor1.join(file)).unwrap(),
                std::fs::read(onion_data_anchor2.join(file)).unwrap(),
                "{file} differs across repeated anchored builds"
            );
        }
        let anchored_onion_data_cuckoo =
            std::fs::read(onion_data_anchor1.join(ONION_CHUNK_CUCKOO_FILENAME)).unwrap();
        assert_eq!(
            u64::from_le_bytes(anchored_onion_data_cuckoo[0..8].try_into().unwrap()),
            ONION_DATA_CUCKOO_MAGIC ^ ANCHOR_MAGIC_SNAPSHOT_XOR
        );
        assert_eq!(
            &anchored_onion_data_cuckoo
                [ONION_DATA_CUCKOO_HEADER_SIZE..ONION_DATA_CUCKOO_HEADER_SIZE + CHAIN_ANCHOR_BYTES],
            &regtest_anchor
        );

        let onion_index_report1 = build_onion_index_cuckoo(
            out1.join(ONION_INDEX_FILENAME),
            &out1,
            &OnionIndexCuckooOptions::default(),
        )
        .expect("build onion index cuckoo 1");
        let onion_index_report2 = build_onion_index_cuckoo(
            out2.join(ONION_INDEX_FILENAME),
            &out2,
            &OnionIndexCuckooOptions::default(),
        )
        .expect("build onion index cuckoo 2");
        let expected_onion_index = OnionIndexCuckooBuildReport {
            index_entries: 9,
            non_whale_entries: 9,
            bins_per_table: 1,
            slots_per_bin: 221,
            raw_bins_file_bytes: 249_600,
            meta_file_bytes: 44,
            bin_hashes_file_bytes: 2_408,
            total_placements: 27,
        };
        assert_eq!(onion_index_report1, expected_onion_index);
        assert_eq!(onion_index_report2, expected_onion_index);
        for file in [
            ONION_INDEX_BINS_FILENAME,
            ONION_INDEX_META_FILENAME,
            ONION_INDEX_BIN_HASHES_FILENAME,
        ] {
            assert_eq!(
                std::fs::read(out1.join(file)).unwrap(),
                std::fs::read(out2.join(file)).unwrap(),
                "{file} differs across repeated builds"
            );
        }
        let onion_index_meta = std::fs::read(out1.join(ONION_INDEX_META_FILENAME)).unwrap();
        assert_eq!(
            u64::from_le_bytes(onion_index_meta[0..8].try_into().unwrap()),
            ONION_INDEX_META_MAGIC
        );
        assert_eq!(
            u64::from_le_bytes(onion_index_meta[24..32].try_into().unwrap()),
            LEGACY_INDEX_MASTER_SEED
        );
        assert_eq!(
            u64::from_le_bytes(onion_index_meta[32..40].try_into().unwrap()),
            LEGACY_INDEX_TAG_SEED
        );

        let onion_index_anchor1 = dir.join("onion-index-anchor-1");
        let onion_index_anchor2 = dir.join("onion-index-anchor-2");
        let onion_index_anchor_options = OnionIndexCuckooOptions {
            master_seed: 0xf5c3_6b45_6159_d686,
            tag_seed: 0x0c65_b3f4_e239_2919,
            snapshot_anchor: Some(regtest_anchor),
            ..Default::default()
        };
        let onion_index_anchor_report1 = build_onion_index_cuckoo(
            out1.join(ONION_INDEX_FILENAME),
            &onion_index_anchor1,
            &onion_index_anchor_options,
        )
        .expect("build anchored onion index cuckoo 1");
        let onion_index_anchor_report2 = build_onion_index_cuckoo(
            out1.join(ONION_INDEX_FILENAME),
            &onion_index_anchor2,
            &onion_index_anchor_options,
        )
        .expect("build anchored onion index cuckoo 2");
        let expected_onion_index_anchor = OnionIndexCuckooBuildReport {
            meta_file_bytes: 80,
            ..expected_onion_index
        };
        assert_eq!(onion_index_anchor_report1, expected_onion_index_anchor);
        assert_eq!(onion_index_anchor_report2, expected_onion_index_anchor);
        for file in [
            ONION_INDEX_BINS_FILENAME,
            ONION_INDEX_META_FILENAME,
            ONION_INDEX_BIN_HASHES_FILENAME,
        ] {
            assert_eq!(
                std::fs::read(onion_index_anchor1.join(file)).unwrap(),
                std::fs::read(onion_index_anchor2.join(file)).unwrap(),
                "{file} differs across repeated anchored builds"
            );
        }
        let anchored_onion_index_meta =
            std::fs::read(onion_index_anchor1.join(ONION_INDEX_META_FILENAME)).unwrap();
        assert_eq!(
            u64::from_le_bytes(anchored_onion_index_meta[0..8].try_into().unwrap()),
            ONION_INDEX_META_MAGIC ^ ANCHOR_MAGIC_SNAPSHOT_XOR
        );
        assert_eq!(
            &anchored_onion_index_meta
                [ONION_INDEX_META_HEADER_SIZE..ONION_INDEX_META_HEADER_SIZE + CHAIN_ANCHOR_BYTES],
            &regtest_anchor
        );

        let onion_merkle_report1 = build_onion_merkle(
            out1.join(ONION_INDEX_BIN_HASHES_FILENAME),
            out1.join(ONION_DATA_BIN_HASHES_FILENAME),
            &out1,
            &OnionMerkleOptions::default(),
        )
        .expect("build onion merkle 1");
        let onion_merkle_report2 = build_onion_merkle(
            out2.join(ONION_INDEX_BIN_HASHES_FILENAME),
            out2.join(ONION_DATA_BIN_HASHES_FILENAME),
            &out2,
            &OnionMerkleOptions::default(),
        )
        .expect("build onion merkle 2");
        let expected_onion_merkle = OnionMerkleBuildReport {
            index_k: 75,
            data_k: 80,
            index_bins_per_table: 1,
            data_bins_per_table: 2,
            arity: 104,
            tree_count: 155,
            index_sibling_rows_per_group: 0,
            data_sibling_rows_per_group: 1,
            tree_tops_file_bytes: 4_124,
            roots_file_bytes: 4_960,
            index_sibling_rows_file_bytes: 24,
            data_sibling_rows_file_bytes: 266_264,
            super_root: hash_from_hex(
                "ba42763e4685f33a01e42337a63ab5e23619dd94035c6402fa9c76dfa28be518",
            ),
        };
        assert_eq!(onion_merkle_report1, expected_onion_merkle);
        assert_eq!(onion_merkle_report2, expected_onion_merkle);
        for file in [
            ONION_MERKLE_TREE_TOPS_FILENAME,
            ONION_MERKLE_ROOTS_FILENAME,
            ONION_MERKLE_ROOT_FILENAME,
            ONION_MERKLE_SIB_ROWS_INDEX_FILENAME,
            ONION_MERKLE_SIB_ROWS_DATA_FILENAME,
        ] {
            assert_eq!(
                std::fs::read(out1.join(file)).unwrap(),
                std::fs::read(out2.join(file)).unwrap(),
                "{file} differs across repeated builds"
            );
        }

        let onion_merkle_anchor1 = dir.join("onion-merkle-anchor-1");
        let onion_merkle_anchor2 = dir.join("onion-merkle-anchor-2");
        let onion_merkle_anchor_report1 = build_onion_merkle(
            onion_index_anchor1.join(ONION_INDEX_BIN_HASHES_FILENAME),
            onion_data_anchor1.join(ONION_DATA_BIN_HASHES_FILENAME),
            &onion_merkle_anchor1,
            &OnionMerkleOptions::default(),
        )
        .expect("build anchored onion merkle 1");
        let onion_merkle_anchor_report2 = build_onion_merkle(
            onion_index_anchor2.join(ONION_INDEX_BIN_HASHES_FILENAME),
            onion_data_anchor2.join(ONION_DATA_BIN_HASHES_FILENAME),
            &onion_merkle_anchor2,
            &OnionMerkleOptions::default(),
        )
        .expect("build anchored onion merkle 2");
        let expected_onion_merkle_anchor = OnionMerkleBuildReport {
            super_root: hash_from_hex(
                "61aa94907bdeb13b3ff243c0e011ccf08d4c77cb78bbc6bb43cdec0c2eb9e64e",
            ),
            ..expected_onion_merkle
        };
        assert_eq!(onion_merkle_anchor_report1, expected_onion_merkle_anchor);
        assert_eq!(onion_merkle_anchor_report2, expected_onion_merkle_anchor);
        let onion_merkle_root_only = dir.join("onion-merkle-root-only");
        let onion_merkle_root_only_report = build_onion_merkle(
            onion_index_anchor1.join(ONION_INDEX_BIN_HASHES_FILENAME),
            onion_data_anchor1.join(ONION_DATA_BIN_HASHES_FILENAME),
            &onion_merkle_root_only,
            &OnionMerkleOptions {
                root_only: true,
                ..Default::default()
            },
        )
        .expect("build anchored onion merkle root-only");
        assert_eq!(
            onion_merkle_root_only_report,
            OnionMerkleBuildReport {
                tree_tops_file_bytes: 0,
                roots_file_bytes: 0,
                index_sibling_rows_file_bytes: 0,
                data_sibling_rows_file_bytes: 0,
                ..expected_onion_merkle_anchor
            }
        );
        assert!(onion_merkle_root_only
            .join(ONION_MERKLE_ROOT_FILENAME)
            .exists());
        for file in [
            ONION_MERKLE_TREE_TOPS_FILENAME,
            ONION_MERKLE_ROOTS_FILENAME,
            ONION_MERKLE_SIB_ROWS_INDEX_FILENAME,
            ONION_MERKLE_SIB_ROWS_DATA_FILENAME,
        ] {
            assert!(
                !onion_merkle_root_only.join(file).exists(),
                "{file} should not exist in root-only mode"
            );
        }
        for file in [
            ONION_MERKLE_TREE_TOPS_FILENAME,
            ONION_MERKLE_ROOTS_FILENAME,
            ONION_MERKLE_ROOT_FILENAME,
            ONION_MERKLE_SIB_ROWS_INDEX_FILENAME,
            ONION_MERKLE_SIB_ROWS_DATA_FILENAME,
        ] {
            assert_eq!(
                std::fs::read(onion_merkle_anchor1.join(file)).unwrap(),
                std::fs::read(onion_merkle_anchor2.join(file)).unwrap(),
                "{file} differs across repeated anchored builds"
            );
        }

        let cuckoo1 = dir.join("index-cuckoo-1.bin");
        let cuckoo2 = dir.join("index-cuckoo-2.bin");
        let cuckoo_options = IndexCuckooOptions::default();
        let cuckoo_report1 = build_index_cuckoo(
            out1.join(UTXO_CHUNKS_INDEX_FILENAME),
            &cuckoo1,
            &cuckoo_options,
        )
        .expect("build index cuckoo 1");
        let cuckoo_report2 = build_index_cuckoo(
            out2.join(UTXO_CHUNKS_INDEX_FILENAME),
            &cuckoo2,
            &cuckoo_options,
        )
        .expect("build index cuckoo 2");
        let expected_cuckoo = IndexCuckooBuildReport {
            index_entries: 9,
            bins_per_table: 1,
            slots_per_table: 4,
            output_bytes: 3_940,
            total_placements: 27,
        };
        assert_eq!(cuckoo_report1, expected_cuckoo);
        assert_eq!(cuckoo_report2, expected_cuckoo);
        let cuckoo_bytes1 = std::fs::read(&cuckoo1).unwrap();
        let cuckoo_bytes2 = std::fs::read(&cuckoo2).unwrap();
        assert_eq!(cuckoo_bytes1, cuckoo_bytes2);
        assert_eq!(
            u64::from_le_bytes(cuckoo_bytes1[0..8].try_into().unwrap()),
            INDEX_CUCKOO_MAGIC
        );
        assert_eq!(
            u64::from_le_bytes(cuckoo_bytes1[24..32].try_into().unwrap()),
            LEGACY_INDEX_MASTER_SEED
        );
        assert_eq!(
            u64::from_le_bytes(cuckoo_bytes1[32..40].try_into().unwrap()),
            LEGACY_INDEX_TAG_SEED
        );

        let anchored_index_cuckoo = dir.join("index-cuckoo-anchored.bin");
        let anchored_index_report = build_index_cuckoo(
            out1.join(UTXO_CHUNKS_INDEX_FILENAME),
            &anchored_index_cuckoo,
            &IndexCuckooOptions {
                master_seed: 0xf5c3_6b45_6159_d686,
                tag_seed: 0x0c65_b3f4_e239_2919,
                snapshot_anchor: Some(regtest_anchor),
                delta_anchor: None,
            },
        )
        .expect("build anchored index cuckoo");
        assert_eq!(
            anchored_index_report,
            IndexCuckooBuildReport {
                index_entries: 9,
                bins_per_table: 1,
                slots_per_table: 4,
                output_bytes: 3_976,
                total_placements: 27,
            }
        );
        let anchored_index_bytes = std::fs::read(&anchored_index_cuckoo).unwrap();
        assert_eq!(
            u64::from_le_bytes(anchored_index_bytes[0..8].try_into().unwrap()),
            INDEX_CUCKOO_MAGIC ^ ANCHOR_MAGIC_SNAPSHOT_XOR
        );
        assert_eq!(
            &anchored_index_bytes
                [INDEX_CUCKOO_HEADER_SIZE..INDEX_CUCKOO_HEADER_SIZE + CHAIN_ANCHOR_BYTES],
            &regtest_anchor
        );

        let chunk_cuckoo1 = dir.join("chunk-cuckoo-1.bin");
        let chunk_cuckoo2 = dir.join("chunk-cuckoo-2.bin");
        let chunk_cuckoo_options = ChunkCuckooOptions::default();
        let chunk_cuckoo_report1 = build_chunk_cuckoo(
            out1.join(UTXO_CHUNKS_FILENAME),
            &chunk_cuckoo1,
            &chunk_cuckoo_options,
        )
        .expect("build chunk cuckoo 1");
        let chunk_cuckoo_report2 = build_chunk_cuckoo(
            out2.join(UTXO_CHUNKS_FILENAME),
            &chunk_cuckoo2,
            &chunk_cuckoo_options,
        )
        .expect("build chunk cuckoo 2");
        let expected_chunk_cuckoo = ChunkCuckooBuildReport {
            chunks: 111,
            bins_per_table: 3,
            slots_per_table: 9,
            output_bytes: 31_712,
            total_placements: 333,
        };
        assert_eq!(chunk_cuckoo_report1, expected_chunk_cuckoo);
        assert_eq!(chunk_cuckoo_report2, expected_chunk_cuckoo);
        let chunk_cuckoo_bytes1 = std::fs::read(&chunk_cuckoo1).unwrap();
        let chunk_cuckoo_bytes2 = std::fs::read(&chunk_cuckoo2).unwrap();
        assert_eq!(chunk_cuckoo_bytes1, chunk_cuckoo_bytes2);
        assert_eq!(
            u64::from_le_bytes(chunk_cuckoo_bytes1[0..8].try_into().unwrap()),
            CHUNK_CUCKOO_MAGIC
        );
        assert_eq!(
            u64::from_le_bytes(chunk_cuckoo_bytes1[24..32].try_into().unwrap()),
            LEGACY_CHUNK_MASTER_SEED
        );

        let anchor_seed_chunk_cuckoo = dir.join("chunk-cuckoo-anchor-seed.bin");
        let anchor_seed_chunk_report = build_chunk_cuckoo(
            out1.join(UTXO_CHUNKS_FILENAME),
            &anchor_seed_chunk_cuckoo,
            &ChunkCuckooOptions {
                master_seed: 0x875a_2299_804a_46fc,
                snapshot_anchor: Some(regtest_anchor),
                delta_anchor: None,
            },
        )
        .expect("build chunk cuckoo with regtest anchor-derived seed");
        assert_eq!(
            anchor_seed_chunk_report,
            ChunkCuckooBuildReport {
                chunks: 111,
                bins_per_table: 4,
                slots_per_table: 12,
                output_bytes: 42_308,
                total_placements: 333,
            }
        );
        let anchor_seed_chunk_bytes = std::fs::read(&anchor_seed_chunk_cuckoo).unwrap();
        assert_eq!(
            u64::from_le_bytes(anchor_seed_chunk_bytes[0..8].try_into().unwrap()),
            CHUNK_CUCKOO_MAGIC ^ ANCHOR_MAGIC_SNAPSHOT_XOR
        );
        assert_eq!(
            &anchor_seed_chunk_bytes
                [CHUNK_CUCKOO_HEADER_SIZE..CHUNK_CUCKOO_HEADER_SIZE + CHAIN_ANCHOR_BYTES],
            &regtest_anchor
        );

        let merkle_legacy = dir.join("merkle-legacy");
        let merkle_legacy_report = build_bucket_merkle(&cuckoo1, &chunk_cuckoo1, &merkle_legacy)
            .expect("build legacy bucket merkle");
        assert_eq!(
            merkle_legacy_report,
            BucketMerkleBuildReport {
                index_bins_per_table: 1,
                chunk_bins_per_table: 3,
                index_sibling_levels: Vec::new(),
                chunk_sibling_levels: Vec::new(),
                tree_count: 155,
                tree_tops_file_bytes: 14_824,
                roots_file_bytes: 4_960,
                super_root: hash_from_hex(
                    "3f9333950fe369352657c354951f2cfb217cd5726fc406299a01aad90a6fd714"
                ),
            }
        );
        assert!(merkle_legacy
            .join(MERKLE_BUCKET_TREE_TOPS_FILENAME)
            .exists());
        assert!(merkle_legacy.join(MERKLE_BUCKET_ROOTS_FILENAME).exists());
        assert!(merkle_legacy.join(MERKLE_BUCKET_ROOT_FILENAME).exists());
        assert!(!merkle_legacy
            .join(merkle_index_sibling_filename(0))
            .exists());
        assert!(!merkle_legacy
            .join(merkle_chunk_sibling_filename(0))
            .exists());

        let merkle_anchor = dir.join("merkle-anchor");
        let merkle_anchor_report = build_bucket_merkle(
            &anchored_index_cuckoo,
            &anchor_seed_chunk_cuckoo,
            &merkle_anchor,
        )
        .expect("build anchored bucket merkle");
        assert_eq!(
            merkle_anchor_report,
            BucketMerkleBuildReport {
                index_bins_per_table: 1,
                chunk_bins_per_table: 4,
                index_sibling_levels: Vec::new(),
                chunk_sibling_levels: Vec::new(),
                tree_count: 155,
                tree_tops_file_bytes: 17_384,
                roots_file_bytes: 4_960,
                super_root: hash_from_hex(
                    "d75ea9f795defe239a08f371a2954b0e2150ee72bc65612ecdfa27b0f8a5a280"
                ),
            }
        );
        let merkle_anchor_root_only = dir.join("merkle-anchor-root-only");
        let merkle_anchor_root_only_report = build_bucket_merkle_with_options(
            &anchored_index_cuckoo,
            &anchor_seed_chunk_cuckoo,
            &merkle_anchor_root_only,
            &BucketMerkleOptions { root_only: true },
        )
        .expect("build anchored bucket merkle root-only");
        assert_eq!(
            merkle_anchor_root_only_report,
            BucketMerkleBuildReport {
                tree_tops_file_bytes: 0,
                roots_file_bytes: 0,
                ..merkle_anchor_report
            }
        );
        assert!(merkle_anchor_root_only
            .join(MERKLE_BUCKET_ROOT_FILENAME)
            .exists());
        assert!(!merkle_anchor_root_only
            .join(MERKLE_BUCKET_TREE_TOPS_FILENAME)
            .exists());
        assert!(!merkle_anchor_root_only
            .join(MERKLE_BUCKET_ROOTS_FILENAME)
            .exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn existing_onion_layout_v2_checks_final_tables_and_roots() {
        let dir = fresh_temp_dir("existing-onion-v2");
        let entry_size = 64usize;
        let packed = vec![0x5au8; entry_size];
        std::fs::write(dir.join(ONION_PACKED_ENTRIES_FILENAME), &packed).unwrap();

        let index_options = OnionIndexCuckooOptions {
            entry_size,
            ..Default::default()
        };
        write_onion_index_meta(
            &dir.join(ONION_INDEX_META_FILENAME),
            2,
            entry_size / ONION_INDEX_SLOT_SIZE,
            &index_options,
        )
        .unwrap();
        let index_bin = vec![0u8; entry_size];
        std::fs::write(
            dir.join(ONION_INDEX_BINS_FILENAME),
            index_bin.repeat(INDEX_K * 2),
        )
        .unwrap();
        let mut index_hashes = Vec::new();
        index_hashes.extend_from_slice(&(INDEX_K as u32).to_le_bytes());
        index_hashes.extend_from_slice(&2u32.to_le_bytes());
        for _ in 0..INDEX_K * 2 {
            index_hashes.extend_from_slice(&sha256(&index_bin));
        }
        std::fs::write(dir.join(ONION_INDEX_BIN_HASHES_FILENAME), index_hashes).unwrap();

        let chunk_options = OnionDataCuckooOptions {
            entry_size,
            ..Default::default()
        };
        let chunk_tables = vec![vec![0, EMPTY]; CHUNK_K];
        write_onion_data_cuckoo_file(
            &dir.join(ONION_CHUNK_CUCKOO_FILENAME),
            &chunk_tables,
            2,
            1,
            &chunk_options,
        )
        .unwrap();
        write_onion_data_bin_hashes(
            &dir.join(ONION_DATA_BIN_HASHES_FILENAME),
            &dir.join(ONION_PACKED_ENTRIES_FILENAME),
            &chunk_tables,
            2,
            &chunk_options,
        )
        .unwrap();
        build_onion_merkle(
            dir.join(ONION_INDEX_BIN_HASHES_FILENAME),
            dir.join(ONION_DATA_BIN_HASHES_FILENAME),
            &dir,
            &OnionMerkleOptions {
                entry_size,
                root_only: false,
            },
        )
        .unwrap();

        let layout = inspect_existing_onion_layout_v2(&dir).unwrap();
        assert_eq!(layout.total_packed_entries, 1);
        assert_eq!(layout.entry_size, 64);
        assert_eq!(layout.index_bins_per_table, 2);
        assert_eq!(layout.chunk_bins_per_table, 2);

        let mut tampered = std::fs::read(dir.join(ONION_INDEX_BINS_FILENAME)).unwrap();
        tampered[0] ^= 1;
        std::fs::write(dir.join(ONION_INDEX_BINS_FILENAME), tampered).unwrap();
        assert!(inspect_existing_onion_layout_v2(&dir)
            .unwrap_err()
            .to_string()
            .contains("index leaf hash mismatch"));
        let _ = std::fs::remove_dir_all(dir);
    }

    fn hash_from_hex(s: &str) -> Hash256 {
        let bytes = hex::decode(s).unwrap();
        bytes.try_into().unwrap()
    }

    fn fresh_temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "attested-builder-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn write_flat_entries(
        path: &Path,
        entries: &[([u8; SCRIPT_HASH_SIZE], [u8; TXID_SIZE], u32, u64, u32)],
    ) {
        let mut out = Vec::with_capacity(entries.len() * FLAT_UTXO_ENTRY_SIZE);
        for (script_hash, txid, vout, amount, height) in entries {
            out.extend_from_slice(script_hash);
            out.extend_from_slice(txid);
            out.extend_from_slice(&vout.to_le_bytes());
            out.extend_from_slice(&amount.to_le_bytes());
            out.extend_from_slice(&height.to_le_bytes());
        }
        std::fs::write(path, out).unwrap();
    }
}
