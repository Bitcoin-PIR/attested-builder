//! Spool stable groups, then keep only one group's records and table in RAM.

use super::*;
use crate::external_sort::{read_record, reader, writer, Scratch};
use std::io::{Seek, SeekFrom};

#[cfg(test)]
mod tests;

struct Groups {
    scratch: Scratch,
    counts: Vec<usize>,
}

impl Groups {
    fn path(&self, group: usize) -> PathBuf {
        self.scratch.0.join(group.to_string())
    }
}

fn spool<const IN: usize, const OUT: usize>(
    input: &Path,
    output: &Path,
    group_count: usize,
    expected_records: u64,
    mut route: impl FnMut(u64, [u8; IN]) -> ([usize; 3], [u8; OUT]),
) -> Result<Groups, PipelineError> {
    let mut groups = Groups {
        scratch: Scratch::new(output)?,
        counts: vec![0; group_count],
    };
    let mut writers = (0..group_count)
        .map(|group| writer(&groups.path(group)))
        .collect::<io::Result<Vec<_>>>()?;
    let mut input = reader(input)?;
    let mut ordinal = 0;
    while let Some(record) = read_record::<IN>(&mut input)? {
        if ordinal >= expected_records {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cuckoo input grew during spooling",
            )
            .into());
        }
        let (destinations, record) = route(ordinal, record);
        for group in destinations {
            writers[group].write_all(&record)?;
            groups.counts[group] += 1;
        }
        ordinal += 1;
    }
    if ordinal != expected_records {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "cuckoo input shrank during spooling",
        )
        .into());
    }
    for writer in &mut writers {
        writer.flush()?;
    }
    Ok(groups)
}

// A failed group changes the common bin count, so all preceding tables must
// be rebuilt too. Flush, rewind and truncate between attempts: never retain
// an old header, buffered bytes, or a tail from a failed attempt.
fn write_groups(
    output: &Path,
    counts: &[usize],
    slots_per_bin: usize,
    mut header: impl FnMut(&mut BufWriter<File>, usize) -> Result<(), PipelineError>,
    mut group: impl FnMut(&mut BufWriter<File>, usize, usize) -> Result<(), PipelineError>,
) -> Result<usize, PipelineError> {
    let mut bins = compute_bins_per_table(counts.iter().copied().max().unwrap_or(0), slots_per_bin);
    let max_bins = max_retry_bins(bins);
    let mut output = BufWriter::with_capacity(4 * 1024 * 1024, File::create_new(output)?);
    'retry: loop {
        output.seek(SeekFrom::Start(0))?;
        output.get_mut().set_len(0)?;
        header(&mut output, bins)?;
        for id in 0..counts.len() {
            match group(&mut output, id, bins) {
                Ok(()) => {}
                Err(PipelineError::CuckooInsertFailed { .. }) if bins < max_bins => {
                    bins += 1;
                    continue 'retry;
                }
                Err(e) => return Err(e),
            }
        }
        output.flush()?;
        return Ok(bins);
    }
}

pub(super) fn build_index(
    input: &Path,
    output: &Path,
    options: &IndexCuckooOptions,
) -> Result<IndexCuckooBuildReport, PipelineError> {
    let bytes = std::fs::metadata(input)?.len();
    if bytes % INDEX_RECORD_SIZE as u64 != 0 {
        return Err(PipelineError::InvalidIndexSize { bytes });
    }
    let entries = bytes / INDEX_RECORD_SIZE as u64;
    let groups = spool::<INDEX_RECORD_SIZE, INDEX_RECORD_SIZE>(
        input,
        output,
        INDEX_K,
        entries,
        |_, record| {
            (
                derive_groups_3(&record[..SCRIPT_HASH_SIZE], INDEX_K),
                record,
            )
        },
    )?;
    // Reuse fixed-capacity buffers across groups. Repeated near-sized large
    // allocations can otherwise leave several old groups resident in malloc.
    let max_count = groups.counts.iter().copied().max().unwrap_or(0);
    let mut data = vec![0; max_count * INDEX_RECORD_SIZE];
    let local_entries: Vec<usize> = (0..max_count).collect();
    let bins = write_groups(
        output,
        &groups.counts,
        INDEX_SLOTS_PER_BIN,
        |writer, bins| write_index_cuckoo_header(writer, bins as u32, options),
        |writer, group, bins| {
            let count = groups.counts[group];
            let data = &mut data[..count * INDEX_RECORD_SIZE];
            File::open(groups.path(group))?.read_exact(data)?;
            // Local order is exactly the original input traversal. Remapping
            // global offsets to this compact buffer changes no hash or kick.
            let table = build_index_cuckoo_table(
                data,
                &local_entries[..count],
                group,
                bins,
                options.master_seed,
            )?;
            for local in table {
                if local == EMPTY {
                    writer.write_all(&[0; INDEX_SLOT_SIZE])?;
                } else {
                    let offset = local as usize * INDEX_RECORD_SIZE;
                    let tag =
                        compute_tag(options.tag_seed, &data[offset..offset + SCRIPT_HASH_SIZE]);
                    writer.write_all(&tag.to_le_bytes())?;
                    writer
                        .write_all(&data[offset + SCRIPT_HASH_SIZE..offset + INDEX_RECORD_SIZE])?;
                }
            }
            Ok(())
        },
    )?;
    let slots = bins * INDEX_SLOTS_PER_BIN;
    Ok(IndexCuckooBuildReport {
        index_entries: entries,
        bins_per_table: bins as u32,
        slots_per_table: slots as u64,
        output_bytes: index_cuckoo_header_size(options) as u64
            + (INDEX_K * slots * INDEX_SLOT_SIZE) as u64,
        total_placements: entries * INDEX_PBC_HASHES as u64,
    })
}

pub(super) fn build_chunks(
    input: &Path,
    output: &Path,
    options: &ChunkCuckooOptions,
) -> Result<ChunkCuckooBuildReport, PipelineError> {
    let bytes = std::fs::metadata(input)?.len();
    if bytes % CHUNK_SIZE as u64 != 0 {
        return Err(PipelineError::InvalidChunksSize { bytes });
    }
    let entries = bytes / CHUNK_SIZE as u64;
    if entries > u32::MAX as u64 {
        return Err(PipelineError::ChunkIdOverflow(entries));
    }
    let groups =
        spool::<CHUNK_SIZE, CHUNK_SLOT_SIZE>(input, output, CHUNK_K, entries, |ordinal, chunk| {
            let id = ordinal as u32;
            let mut record = [0; CHUNK_SLOT_SIZE];
            record[..4].copy_from_slice(&id.to_le_bytes());
            record[4..].copy_from_slice(&chunk);
            (derive_int_groups_3(id, CHUNK_K), record)
        })?;
    let max_count = groups.counts.iter().copied().max().unwrap_or(0);
    let mut data = vec![0; max_count * CHUNK_SLOT_SIZE];
    let mut ids = Vec::with_capacity(max_count);
    let bins = write_groups(
        output,
        &groups.counts,
        CHUNK_SLOTS_PER_BIN,
        |writer, bins| write_chunk_cuckoo_header(writer, bins as u32, options),
        |writer, group, bins| {
            let data = &mut data[..groups.counts[group] * CHUNK_SLOT_SIZE];
            File::open(groups.path(group))?.read_exact(data)?;
            ids.clear();
            ids.extend(
                data.chunks_exact(CHUNK_SLOT_SIZE)
                    .map(|r| u32::from_le_bytes(r[..4].try_into().unwrap())),
            );
            let table = build_chunk_cuckoo_table(&ids, group, bins, options.master_seed)?;
            for local in table {
                if local == EMPTY {
                    writer.write_all(&[0; CHUNK_SLOT_SIZE])?;
                } else {
                    let offset = local as usize * CHUNK_SLOT_SIZE;
                    writer.write_all(&data[offset..offset + CHUNK_SLOT_SIZE])?;
                }
            }
            Ok(())
        },
    )?;
    let slots = bins * CHUNK_SLOTS_PER_BIN;
    Ok(ChunkCuckooBuildReport {
        chunks: entries,
        bins_per_table: bins as u32,
        slots_per_table: slots as u64,
        output_bytes: chunk_cuckoo_header_size(options) as u64
            + (CHUNK_K * slots * CHUNK_SLOT_SIZE) as u64,
        total_placements: entries * CHUNK_PBC_HASHES as u64,
    })
}
