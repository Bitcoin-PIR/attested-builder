//! Deterministic build-pipeline stages for attested BitcoinPIR roots.
//!
//! This crate starts by splitting the old `build/src/build_utxo_chunks.rs`
//! binary into a callable library function. The output format is compatible
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

const ZERO_PAD: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];

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
