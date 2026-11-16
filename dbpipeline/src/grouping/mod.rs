//! Preserve the existing partition/script/input ordering using bounded sort runs.

use super::*;
use crate::external_sort::{read_record, reader, Limits, Scratch, Sorter};

#[cfg(test)]
mod tests;

pub(super) fn visit(
    input: &Path,
    output: &Path,
    options: &UtxoChunkBuildOptions,
    emit: impl FnMut([u8; SCRIPT_HASH_SIZE], usize, Vec<ShortenedEntry>) -> Result<(), PipelineError>,
) -> Result<u64, PipelineError> {
    visit_with_limits(input, output, options, Limits::default(), emit)
}

fn visit_with_limits(
    input: &Path,
    output: &Path,
    options: &UtxoChunkBuildOptions,
    limits: Limits,
    mut emit: impl FnMut(
        [u8; SCRIPT_HASH_SIZE],
        usize,
        Vec<ShortenedEntry>,
    ) -> Result<(), PipelineError>,
) -> Result<u64, PipelineError> {
    let scratch = Scratch::new(output)?;
    // Partition(1), script(20), input ordinal(8), shortened entry(48).
    let mut sorter = Sorter::<77>::new(&scratch.0, "groups", limits);
    let mut dust_skipped = 0;
    for (ordinal, entry) in FlatEntryIter::open(input)?.enumerate() {
        let entry = entry?;
        if entry.amount <= options.dust_threshold_sats {
            dust_skipped += 1;
            continue;
        }
        let mut record = [0; 77];
        record[0] = (entry.script_hash[0] as usize % options.partitions) as u8;
        record[1..21].copy_from_slice(&entry.script_hash);
        // Equal-height entries must reach the existing unstable sort in their
        // original input order, not an incidental order from the merge passes.
        record[21..29].copy_from_slice(&(ordinal as u64).to_be_bytes());
        record[29..61].copy_from_slice(&entry.txid);
        record[61..65].copy_from_slice(&entry.vout.to_le_bytes());
        record[65..73].copy_from_slice(&entry.amount.to_le_bytes());
        record[73..77].copy_from_slice(&entry.height.to_le_bytes());
        sorter.push(record)?;
    }
    let sorted = sorter.finish()?;
    let mut input = reader(&sorted)?;
    let mut next = read_record::<77>(&mut input)?;
    while let Some(first) = next {
        let mut entries = Vec::new();
        let mut count = 0;
        while let Some(record) = next {
            if record[..21] != first[..21] {
                break;
            }
            count += 1;
            if count <= options.max_utxos_per_spk {
                entries.push(ShortenedEntry {
                    txid: record[29..61].try_into().unwrap(),
                    vout: u32::from_le_bytes(record[61..65].try_into().unwrap()),
                    amount: u64::from_le_bytes(record[65..73].try_into().unwrap()),
                    height: u32::from_le_bytes(record[73..77].try_into().unwrap()),
                });
            } else {
                // Keep counting whales without accumulating their UTXOs.
                entries.clear();
            }
            next = read_record::<77>(&mut input)?;
        }
        emit(first[1..21].try_into().unwrap(), count, entries)?;
    }
    Ok(dust_skipped)
}
