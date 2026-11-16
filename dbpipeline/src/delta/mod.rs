//! Snapshot set-diff using external sorts, independent of input order and run size.

use super::*;
use std::cmp::Ordering;
use std::fs;

use crate::external_sort::{read_record, reader, writer, Limits, Scratch, Sorter};

#[cfg(test)]
mod tests;

// Numeric sort fields use big endian; the output retains the legacy varints.
// Outpoint: txid(32), vout(4), input ordinal(8), script hash(20), amount(8).
type Coin = [u8; 72];
// Change: script hash(20), spent/new(1), txid(32), vout(4), amount(8).
type Change = [u8; 65];

pub(super) fn build(
    from_path: &Path,
    to_path: &Path,
    output: &Path,
    options: &DeltaBuildOptions,
) -> Result<DeltaBuildReport, PipelineError> {
    build_with_limits(from_path, to_path, output, options, Limits::default())
}

fn build_with_limits(
    from_path: &Path,
    to_path: &Path,
    output: &Path,
    options: &DeltaBuildOptions,
    limits: Limits,
) -> Result<DeltaBuildReport, PipelineError> {
    let from_entries = entry_count(from_path)?;
    let to_entries = entry_count(to_path)?;
    let scratch = Scratch::new(output)?;
    let from_sorted = sort_snapshot(from_path, &scratch.0, "from", limits)?;
    let to_sorted = sort_snapshot(to_path, &scratch.0, "to", limits)?;
    let mut from = reader(&from_sorted)?;
    let mut to = reader(&to_sorted)?;
    let mut previous_from = None;
    let mut a = next_from(&mut from, &mut previous_from, from_path)?;
    let mut b = read_record::<72>(&mut to)?;
    let mut changes = Sorter::<65>::new(&scratch.0, "changes", limits);
    let mut report = DeltaBuildReport {
        from_entries,
        to_entries,
        unchanged_entries: 0,
        spent_entries: 0,
        created_entries: 0,
        dust_created_skipped: 0,
        scripts_changed: 0,
        grouped_file_bytes: 0,
    };
    while a.is_some() || b.is_some() {
        let order = match (&a, &b) {
            (Some(a), Some(b)) => a[..36].cmp(&b[..36]),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => unreachable!(),
        };
        match order {
            Ordering::Less => {
                changes.push(change(a.as_ref().unwrap(), false))?;
                report.spent_entries += 1;
                a = next_from(&mut from, &mut previous_from, from_path)?;
            }
            Ordering::Greater => {
                let coin = b.as_ref().unwrap();
                let amount = u64::from_be_bytes(coin[64..72].try_into().unwrap());
                if amount <= options.dust_threshold_sats {
                    report.dust_created_skipped += 1;
                } else {
                    changes.push(change(coin, true))?;
                    report.created_entries += 1;
                }
                b = read_record::<72>(&mut to)?;
            }
            Ordering::Equal => {
                report.unchanged_entries += 1;
                a = next_from(&mut from, &mut previous_from, from_path)?;
                b = read_record::<72>(&mut to)?;
            }
        }
    }
    drop((from, to));
    fs::remove_file(from_sorted)?;
    fs::remove_file(to_sorted)?;
    let sorted_changes = changes.finish()?;
    let counts = scratch.0.join("counts");
    report.scripts_changed = count_scripts(&sorted_changes, &counts, output)?;
    write_grouped(
        &sorted_changes,
        &counts,
        output,
        report.scripts_changed as u32,
    )?;
    report.grouped_file_bytes = fs::metadata(output)?.len();
    Ok(report)
}

fn entry_count(path: &Path) -> Result<u64, PipelineError> {
    let bytes = fs::metadata(path)?.len();
    if bytes % FLAT_UTXO_ENTRY_SIZE as u64 != 0 {
        return Err(PipelineError::InvalidFlatUtxoSize { bytes });
    }
    Ok(bytes / FLAT_UTXO_ENTRY_SIZE as u64)
}

fn sort_snapshot(
    path: &Path,
    dir: &Path,
    prefix: &'static str,
    limits: Limits,
) -> Result<PathBuf, PipelineError> {
    let mut input = reader(path)?;
    let mut sorter = Sorter::<72>::new(dir, prefix, limits);
    let mut ordinal = 0u64;
    while let Some(flat) = read_record::<FLAT_UTXO_ENTRY_SIZE>(&mut input)? {
        let mut coin: Coin = [0; 72];
        coin[..32].copy_from_slice(&flat[20..52]);
        coin[32..36]
            .copy_from_slice(&u32::from_le_bytes(flat[52..56].try_into().unwrap()).to_be_bytes());
        // Preserve the old first-match behavior even for duplicate target outpoints.
        coin[36..44].copy_from_slice(&ordinal.to_be_bytes());
        coin[44..64].copy_from_slice(&flat[..20]);
        coin[64..72]
            .copy_from_slice(&u64::from_le_bytes(flat[56..64].try_into().unwrap()).to_be_bytes());
        sorter.push(coin)?;
        ordinal += 1;
    }
    Ok(sorter.finish()?)
}

fn next_from(
    input: &mut BufReader<File>,
    previous: &mut Option<[u8; 36]>,
    path: &Path,
) -> Result<Option<Coin>, PipelineError> {
    let coin = read_record::<72>(input)?;
    if let Some(coin) = &coin {
        let key: [u8; 36] = coin[..36].try_into().unwrap();
        if previous.as_ref() == Some(&key) {
            return Err(PipelineError::InvalidDeltaFormat {
                path: path.to_path_buf(),
                reason: format!(
                    "duplicate outpoint {}:{}",
                    hex::encode(&key[..32]),
                    u32::from_be_bytes(key[32..36].try_into().unwrap())
                ),
            });
        }
        *previous = Some(key);
    }
    Ok(coin)
}

fn change(coin: &Coin, created: bool) -> Change {
    let mut record = [0; 65];
    record[..20].copy_from_slice(&coin[44..64]);
    record[20] = u8::from(created);
    record[21..57].copy_from_slice(&coin[..36]);
    if created {
        record[57..65].copy_from_slice(&coin[64..72]);
    }
    record
}

fn count_scripts(changes: &Path, counts: &Path, output: &Path) -> Result<u64, PipelineError> {
    let mut input = reader(changes)?;
    let mut counts = writer(counts)?;
    let mut next = read_record::<65>(&mut input)?;
    let mut scripts = 0u64;
    while let Some(first) = next {
        let script = &first[..20];
        let mut spent = 0u64;
        let mut created = 0u64;
        while let Some(record) = next {
            if &record[..20] != script {
                break;
            }
            if record[20] == 0 {
                spent += 1;
            } else {
                created += 1;
            }
            next = read_record::<65>(&mut input)?;
        }
        counts.write_all(script)?;
        counts.write_all(&spent.to_le_bytes())?;
        counts.write_all(&created.to_le_bytes())?;
        scripts += 1;
        if scripts > u32::MAX as u64 {
            return Err(PipelineError::InvalidDeltaFormat {
                path: output.to_path_buf(),
                reason: format!("too many changed scripts: {scripts}"),
            });
        }
    }
    counts.flush()?;
    Ok(scripts)
}

fn write_grouped(
    changes: &Path,
    counts: &Path,
    output: &Path,
    scripts: u32,
) -> Result<(), PipelineError> {
    let mut input = reader(changes)?;
    let mut counts = reader(counts)?;
    let mut output = writer(output)?;
    output.write_all(&scripts.to_le_bytes())?;
    while let Some(group) = read_record::<36>(&mut counts)? {
        output.write_all(&group[..20])?;
        let spent = u64::from_le_bytes(group[20..28].try_into().unwrap());
        let created = u64::from_le_bytes(group[28..36].try_into().unwrap());
        for (count, is_new) in [(spent, false), (created, true)] {
            write_varint_to_writer(&mut output, count)?;
            for _ in 0..count {
                let mut record: Change = [0; 65];
                input.read_exact(&mut record)?;
                output.write_all(&record[21..53])?;
                write_varint_to_writer(
                    &mut output,
                    u32::from_be_bytes(record[53..57].try_into().unwrap()) as u64,
                )?;
                if is_new {
                    write_varint_to_writer(
                        &mut output,
                        u64::from_be_bytes(record[57..65].try_into().unwrap()),
                    )?;
                }
            }
        }
    }
    output.flush()?;
    Ok(())
}
