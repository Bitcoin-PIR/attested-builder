use super::*;
use std::collections::BTreeMap;
use std::io::Cursor;

type Outpoint = ([u8; 32], u32);
type Group = (Vec<Outpoint>, Vec<([u8; 32], u32, u64)>);

// In-memory reference for the pre-external-sort semantics. It deliberately has
// no shared sorting/record decoding code with the disk pipeline.
fn reference(from: &[FlatEntry], to: &[FlatEntry], dust: u64) -> (Vec<u8>, DeltaBuildReport) {
    let mut old = BTreeMap::new();
    for coin in from {
        assert!(old
            .insert((coin.txid, coin.vout), coin.script_hash)
            .is_none());
    }
    let mut groups: BTreeMap<[u8; 20], Group> = BTreeMap::new();
    let mut report = DeltaBuildReport {
        from_entries: from.len() as u64,
        to_entries: to.len() as u64,
        unchanged_entries: 0,
        spent_entries: 0,
        created_entries: 0,
        dust_created_skipped: 0,
        scripts_changed: 0,
        grouped_file_bytes: 0,
    };
    for coin in to {
        if old.remove(&(coin.txid, coin.vout)).is_some() {
            report.unchanged_entries += 1;
        } else if coin.amount <= dust {
            report.dust_created_skipped += 1;
        } else {
            groups
                .entry(coin.script_hash)
                .or_default()
                .1
                .push((coin.txid, coin.vout, coin.amount));
            report.created_entries += 1;
        }
    }
    report.spent_entries = old.len() as u64;
    for (key, script) in old {
        groups.entry(script).or_default().0.push(key);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(groups.len() as u32).to_le_bytes());
    for (script, (spent, created)) in &mut groups {
        spent.sort_unstable();
        created.sort_unstable();
        bytes.extend_from_slice(script);
        write_varint(&mut bytes, spent.len() as u64);
        for (txid, vout) in spent {
            bytes.extend_from_slice(txid);
            write_varint(&mut bytes, *vout as u64);
        }
        write_varint(&mut bytes, created.len() as u64);
        for (txid, vout, amount) in created {
            bytes.extend_from_slice(txid);
            write_varint(&mut bytes, *vout as u64);
            write_varint(&mut bytes, *amount);
        }
    }
    report.scripts_changed = groups.len() as u64;
    report.grouped_file_bytes = bytes.len() as u64;
    (bytes, report)
}

fn write_flat(path: &Path, coins: &[FlatEntry]) {
    let mut bytes = Vec::new();
    for coin in coins {
        bytes.extend_from_slice(&coin.script_hash);
        bytes.extend_from_slice(&coin.txid);
        bytes.extend_from_slice(&coin.vout.to_le_bytes());
        bytes.extend_from_slice(&coin.amount.to_le_bytes());
        bytes.extend_from_slice(&coin.height.to_le_bytes());
    }
    fs::write(path, bytes).unwrap();
}

fn sample(i: u32) -> FlatEntry {
    let mut txid = [0x81; 32];
    txid[..4].copy_from_slice(&(i / 5).to_le_bytes());
    FlatEntry {
        script_hash: [(i % 7) as u8; 20],
        txid,
        vout: [0, 127, 128, 256, u32::MAX][(i % 5) as usize],
        amount: [0, 576, 577, 1000, u64::MAX][(i % 5) as usize],
        height: i,
    }
}

#[test]
fn external_sort_matches_legacy() {
    let path = std::env::temp_dir().join(format!("bpir-delta-sort-test-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    let fixture = Scratch(path);
    let from_path = fixture.0.join("from.bin");
    let to_path = fixture.0.join("to.bin");
    let from: Vec<_> = (0..127).map(|i| sample(i * 37 % 127)).collect();
    let to: Vec<_> = (64..191).rev().map(sample).collect();
    let mut whale_from = from.clone();
    let mut whale_to = to.clone();
    for coin in whale_from.iter_mut().chain(&mut whale_to) {
        coin.script_hash = [0; 20];
    }
    let mut duplicate_to = vec![sample(1), sample(1), sample(1)];
    duplicate_to[0].amount = u64::MAX;
    duplicate_to[0].script_hash = [255; 20];
    duplicate_to[1].amount = 577;
    duplicate_to[2].amount = 576;
    let cases = [
        (vec![], vec![]),
        (from.clone(), vec![]),
        (vec![], to.clone()),
        (from.clone(), from.iter().cloned().rev().collect()),
        (from.clone(), to.clone()),
        (whale_from, whale_to),
        (vec![sample(1)], duplicate_to),
    ];
    for (case, (from, to)) in cases.into_iter().enumerate() {
        for dust in [0, 576, u64::MAX] {
            let (expected, expected_report) = reference(&from, &to, dust);
            write_flat(&from_path, &from);
            write_flat(&to_path, &to);
            for (run, limits) in [
                Limits {
                    run_bytes: 144,
                    fan_in: 2,
                },
                Limits {
                    run_bytes: 720,
                    fan_in: 3,
                },
                Limits::default(),
            ]
            .into_iter()
            .enumerate()
            {
                let output = fixture.0.join(format!("case-{case}-{dust}-{run}"));
                let report = build_with_limits(
                    &from_path,
                    &to_path,
                    &output,
                    &DeltaBuildOptions {
                        dust_threshold_sats: dust,
                    },
                    limits,
                )
                .unwrap();
                assert_eq!(report, expected_report, "case {case}, run {run}");
                assert_eq!(
                    fs::read(&output).unwrap(),
                    expected,
                    "case {case}, run {run}"
                );
                assert!(!output
                    .with_file_name(format!(
                        "{}.sort",
                        output.file_name().unwrap().to_str().unwrap()
                    ))
                    .exists());
            }
        }
    }

    // Duplicate source outpoints separated by many runs must still be rejected.
    let mut duplicate_from = from.clone();
    duplicate_from.push(from[0].clone());
    write_flat(&from_path, &duplicate_from);
    write_flat(&to_path, &to);
    let output = fixture.0.join("duplicate-source");
    assert!(matches!(
        build_with_limits(
            &from_path,
            &to_path,
            &output,
            &DeltaBuildOptions::default(),
            Limits {
                run_bytes: 144,
                fan_in: 2
            }
        ),
        Err(PipelineError::InvalidDeltaFormat { .. })
    ));
    assert!(!output.exists());
    assert!(!fixture.0.join("duplicate-source.sort").exists());

    // The public path preserves existing output and cleans up on invalid input.
    write_flat(&from_path, &from);
    fs::write(&output, b"keep").unwrap();
    assert!(matches!(
        build_grouped_delta_from_flat_sets(
            &from_path,
            &to_path,
            &output,
            &DeltaBuildOptions::default()
        ),
        Err(PipelineError::OutputExists(_))
    ));
    assert_eq!(fs::read(&output).unwrap(), b"keep");
    fs::remove_file(&output).unwrap();
    fs::write(&from_path, [0; 67]).unwrap();
    assert!(matches!(
        build_grouped_delta_from_flat_sets(
            &from_path,
            &to_path,
            &output,
            &DeltaBuildOptions::default()
        ),
        Err(PipelineError::InvalidFlatUtxoSize { .. })
    ));
    assert!(!output.exists());
    assert!(!temp_path(&output).exists());
    write_flat(&from_path, &from);
    let scratch_path = PathBuf::from(format!("{}.sort", temp_path(&output).display()));
    fs::create_dir(&scratch_path).unwrap();
    fs::write(scratch_path.join("keep"), b"keep").unwrap();
    assert!(build_grouped_delta_from_flat_sets(
        &from_path,
        &to_path,
        &output,
        &DeltaBuildOptions::default()
    )
    .is_err());
    assert_eq!(fs::read(scratch_path.join("keep")).unwrap(), b"keep");

    // A partial temporary record is an error, not silent EOF.
    assert!(read_record::<72>(&mut Cursor::new(vec![0; 71])).is_err());
    assert_eq!(
        read_record::<72>(&mut Cursor::new(Vec::<u8>::new())).unwrap(),
        None
    );
}
