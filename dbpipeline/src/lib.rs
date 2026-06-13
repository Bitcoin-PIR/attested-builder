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

const ZERO_PAD: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];
const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 10_000;
const EMPTY: u32 = u32::MAX;
const GOLDEN_RATIO: u64 = 0x9e3779b97f4a7c15;
const CUCKOO_KEY_MIX: u64 = 0x517cc1b727220a95;

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
pub struct IndexCuckooOptions {
    pub master_seed: u64,
    pub tag_seed: u64,
}

impl Default for IndexCuckooOptions {
    fn default() -> Self {
        Self {
            master_seed: LEGACY_INDEX_MASTER_SEED,
            tag_seed: LEGACY_INDEX_TAG_SEED,
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
}

impl Default for ChunkCuckooOptions {
    fn default() -> Self {
        Self {
            master_seed: LEGACY_CHUNK_MASTER_SEED,
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

    let output_bytes =
        INDEX_CUCKOO_HEADER_SIZE as u64 + (INDEX_K * slots_per_table * INDEX_SLOT_SIZE) as u64;
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

    let output_bytes =
        CHUNK_CUCKOO_HEADER_SIZE as u64 + (CHUNK_K * slots_per_table * CHUNK_SLOT_SIZE) as u64;
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

fn temp_path(path: &Path) -> PathBuf {
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("out");
    path.with_file_name(format!("{file_name}.tmp-{}", std::process::id()))
}

fn write_index_cuckoo_header<W: Write>(
    writer: &mut W,
    bins_per_table: u32,
    options: &IndexCuckooOptions,
) -> Result<(), PipelineError> {
    writer.write_all(&INDEX_CUCKOO_MAGIC.to_le_bytes())?;
    writer.write_all(&(INDEX_K as u32).to_le_bytes())?;
    writer.write_all(&(INDEX_SLOTS_PER_BIN as u32).to_le_bytes())?;
    writer.write_all(&bins_per_table.to_le_bytes())?;
    writer.write_all(&(INDEX_PBC_HASHES as u32).to_le_bytes())?;
    writer.write_all(&options.master_seed.to_le_bytes())?;
    writer.write_all(&options.tag_seed.to_le_bytes())?;
    Ok(())
}

fn write_chunk_cuckoo_header<W: Write>(
    writer: &mut W,
    bins_per_table: u32,
    options: &ChunkCuckooOptions,
) -> Result<(), PipelineError> {
    writer.write_all(&CHUNK_CUCKOO_MAGIC.to_le_bytes())?;
    writer.write_all(&(CHUNK_K as u32).to_le_bytes())?;
    writer.write_all(&(CHUNK_SLOTS_PER_BIN as u32).to_le_bytes())?;
    writer.write_all(&bins_per_table.to_le_bytes())?;
    writer.write_all(&(CHUNK_PBC_HASHES as u32).to_le_bytes())?;
    writer.write_all(&options.master_seed.to_le_bytes())?;
    Ok(())
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
        utxosnapshot::materialize_flat_utxo_set(REGTEST_FIXTURE, &flat, REGTEST_MUHASH)
            .expect("materialize flat fixture");

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
            },
        )
        .expect("build chunk cuckoo with regtest anchor-derived seed");
        assert_eq!(
            anchor_seed_chunk_report,
            ChunkCuckooBuildReport {
                chunks: 111,
                bins_per_table: 4,
                slots_per_table: 12,
                output_bytes: 42_272,
                total_placements: 333,
            }
        );
        let _ = std::fs::remove_dir_all(dir);
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
