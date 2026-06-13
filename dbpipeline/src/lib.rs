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

pub const MERKLE_ARITY: usize = 8;
pub const MERKLE_HASH_SIZE: usize = 32;
pub const MERKLE_SIB_ROW_SIZE: usize = MERKLE_ARITY * MERKLE_HASH_SIZE;
pub const MERKLE_TREE_TOP_THRESHOLD: usize = 1024;
pub const MERKLE_BUCKET_TREE_TOPS_FILENAME: &str = "merkle_bucket_tree_tops.bin";
pub const MERKLE_BUCKET_ROOTS_FILENAME: &str = "merkle_bucket_roots.bin";
pub const MERKLE_BUCKET_ROOT_FILENAME: &str = "merkle_bucket_root.bin";

pub const ONION_PACKED_ENTRIES_FILENAME: &str = "onion_packed_entries.bin";
pub const ONION_INDEX_FILENAME: &str = "onion_index.bin";
pub const ONION_INDEX_RECORD_SIZE: usize = 20 + 4 + 2 + 1;
pub const DEFAULT_ONION_ENTRY_SIZE: usize = 3_328;
pub const ONION_WHALE_FLAG: u8 = 0x40;

const ZERO_PAD: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];
const ZERO_HASH: Hash256 = [0u8; MERKLE_HASH_SIZE];
const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 10_000;
const EMPTY: u32 = u32::MAX;
const GOLDEN_RATIO: u64 = 0x9e3779b97f4a7c15;
const CUCKOO_KEY_MIX: u64 = 0x517cc1b727220a95;

type Hash256 = [u8; MERKLE_HASH_SIZE];

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
    InvalidIndexSize {
        bytes: u64,
    },
    InvalidChunksSize {
        bytes: u64,
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
pub struct IndexCuckooOptions {
    pub master_seed: u64,
    pub tag_seed: u64,
    pub snapshot_anchor: Option<[u8; CHAIN_ANCHOR_BYTES]>,
}

impl Default for IndexCuckooOptions {
    fn default() -> Self {
        Self {
            master_seed: LEGACY_INDEX_MASTER_SEED,
            tag_seed: LEGACY_INDEX_TAG_SEED,
            snapshot_anchor: None,
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
}

impl Default for ChunkCuckooOptions {
    fn default() -> Self {
        Self {
            master_seed: LEGACY_CHUNK_MASTER_SEED,
            snapshot_anchor: None,
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
    let mut output_paths = vec![
        out_dir.join(MERKLE_BUCKET_TREE_TOPS_FILENAME),
        out_dir.join(MERKLE_BUCKET_ROOTS_FILENAME),
        out_dir.join(MERKLE_BUCKET_ROOT_FILENAME),
    ];
    for level in 0..index_sibling_levels.len() {
        output_paths.push(out_dir.join(merkle_index_sibling_filename(level)));
    }
    for level in 0..chunk_sibling_levels.len() {
        output_paths.push(out_dir.join(merkle_chunk_sibling_filename(level)));
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

    let mut roots = Vec::with_capacity(INDEX_K + CHUNK_K);
    roots.extend(index_trees.iter().map(|tree| tree.root));
    roots.extend(chunk_trees.iter().map(|tree| tree.root));

    let roots_path = temp_path(&out_dir.join(MERKLE_BUCKET_ROOTS_FILENAME));
    write_roots(&roots_path, &roots)?;

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
        tree_tops_file_bytes: std::fs::metadata(&tree_tops_path)?.len(),
        roots_file_bytes: std::fs::metadata(&roots_path)?.len(),
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
    let anchor_len = if magic == legacy_magic {
        0
    } else if magic == snapshot_magic {
        CHAIN_ANCHOR_BYTES
    } else {
        return Err(PipelineError::InvalidCuckooHeader {
            path: path.to_path_buf(),
            reason: format!(
                "bad magic 0x{magic:016x}; expected legacy 0x{legacy_magic:016x} or snapshot v2 0x{snapshot_magic:016x}"
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

fn temp_path(path: &Path) -> PathBuf {
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("out");
    path.with_file_name(format!("{file_name}.tmp-{}", std::process::id()))
}

fn write_index_cuckoo_header<W: Write>(
    writer: &mut W,
    bins_per_table: u32,
    options: &IndexCuckooOptions,
) -> Result<(), PipelineError> {
    let magic = cuckoo_magic(INDEX_CUCKOO_MAGIC, options.snapshot_anchor.is_some());
    writer.write_all(&magic.to_le_bytes())?;
    writer.write_all(&(INDEX_K as u32).to_le_bytes())?;
    writer.write_all(&(INDEX_SLOTS_PER_BIN as u32).to_le_bytes())?;
    writer.write_all(&bins_per_table.to_le_bytes())?;
    writer.write_all(&(INDEX_PBC_HASHES as u32).to_le_bytes())?;
    writer.write_all(&options.master_seed.to_le_bytes())?;
    writer.write_all(&options.tag_seed.to_le_bytes())?;
    if let Some(anchor) = options.snapshot_anchor {
        writer.write_all(&anchor)?;
    }
    Ok(())
}

fn write_chunk_cuckoo_header<W: Write>(
    writer: &mut W,
    bins_per_table: u32,
    options: &ChunkCuckooOptions,
) -> Result<(), PipelineError> {
    let magic = cuckoo_magic(CHUNK_CUCKOO_MAGIC, options.snapshot_anchor.is_some());
    writer.write_all(&magic.to_le_bytes())?;
    writer.write_all(&(CHUNK_K as u32).to_le_bytes())?;
    writer.write_all(&(CHUNK_SLOTS_PER_BIN as u32).to_le_bytes())?;
    writer.write_all(&bins_per_table.to_le_bytes())?;
    writer.write_all(&(CHUNK_PBC_HASHES as u32).to_le_bytes())?;
    writer.write_all(&options.master_seed.to_le_bytes())?;
    if let Some(anchor) = options.snapshot_anchor {
        writer.write_all(&anchor)?;
    }
    Ok(())
}

fn index_cuckoo_header_size(options: &IndexCuckooOptions) -> usize {
    INDEX_CUCKOO_HEADER_SIZE + options.snapshot_anchor.map_or(0, |_| CHAIN_ANCHOR_BYTES)
}

fn chunk_cuckoo_header_size(options: &ChunkCuckooOptions) -> usize {
    CHUNK_CUCKOO_HEADER_SIZE + options.snapshot_anchor.map_or(0, |_| CHAIN_ANCHOR_BYTES)
}

fn cuckoo_magic(legacy_magic: u64, has_snapshot_anchor: bool) -> u64 {
    if has_snapshot_anchor {
        legacy_magic ^ ANCHOR_MAGIC_SNAPSHOT_XOR
    } else {
        legacy_magic
    }
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
}
