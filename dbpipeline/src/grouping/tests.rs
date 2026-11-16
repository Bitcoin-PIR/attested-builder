use super::*;
use std::collections::BTreeMap;

type Entry = ([u8; 32], u32, u64, u32);
type Group = ([u8; 20], usize, Vec<Entry>);

fn values(entries: &[ShortenedEntry]) -> Vec<Entry> {
    entries
        .iter()
        .map(|e| (e.txid, e.vout, e.amount, e.height))
        .collect()
}

#[test]
fn grouping_preserves_legacy_order_and_whales() {
    let dir = std::env::temp_dir().join(format!("bpir-grouping-test-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let fixture = Scratch(dir);
    let input = fixture.0.join("flat.bin");
    let output = fixture.0.join("out");
    let mut source = Vec::new();
    for (script, count) in [(0u8, 99usize), (7, 100), (255, 101), (16, 23)] {
        for i in 0..count {
            let mut txid = [script; 32];
            txid[..8].copy_from_slice(&(i as u64).to_le_bytes());
            source.push(FlatEntry {
                script_hash: [script; 20],
                txid,
                vout: i as u32,
                amount: 577 + i as u64,
                height: (i % 3) as u32,
            });
        }
    }
    for amount in [0, 575, 576] {
        source.push(FlatEntry {
            script_hash: [42; 20],
            txid: [42; 32],
            vout: 0,
            amount,
            height: 0,
        });
    }
    source.reverse();
    source.rotate_left(37);
    let mut bytes = Vec::new();
    for e in &source {
        bytes.extend_from_slice(&e.script_hash);
        bytes.extend_from_slice(&e.txid);
        bytes.extend_from_slice(&e.vout.to_le_bytes());
        bytes.extend_from_slice(&e.amount.to_le_bytes());
        bytes.extend_from_slice(&e.height.to_le_bytes());
    }
    std::fs::write(&input, bytes).unwrap();

    for partitions in [1, 4, 17, 256, 300] {
        for max_utxos_per_spk in [0, 1, 100] {
            for dust_threshold_sats in [0, 576] {
                let options = UtxoChunkBuildOptions {
                    partitions,
                    dust_threshold_sats,
                    max_utxos_per_spk,
                };
                let mut expected: Vec<Group> = Vec::new();
                let mut dust = 0;
                // Reference is the original partition traversal and per-script
                // input insertion order, independent of external run encoding.
                for partition in 0..partitions {
                    let mut map: BTreeMap<[u8; 20], Vec<ShortenedEntry>> = BTreeMap::new();
                    for e in &source {
                        if e.script_hash[0] as usize % partitions != partition {
                            continue;
                        }
                        if e.amount <= dust_threshold_sats {
                            dust += 1;
                            continue;
                        }
                        map.entry(e.script_hash).or_default().push(ShortenedEntry {
                            txid: e.txid,
                            vout: e.vout,
                            amount: e.amount,
                            height: e.height,
                        });
                    }
                    for (script, entries) in map {
                        let count = entries.len();
                        expected.push((
                            script,
                            count,
                            if count > max_utxos_per_spk {
                                Vec::new()
                            } else {
                                values(&entries)
                            },
                        ));
                    }
                }
                for limits in [
                    Limits {
                        run_bytes: 154,
                        fan_in: 2,
                    },
                    Limits {
                        run_bytes: 770,
                        fan_in: 3,
                    },
                    Limits::default(),
                ] {
                    let mut actual = Vec::new();
                    let skipped = visit_with_limits(
                        &input,
                        &output,
                        &options,
                        limits,
                        |script, count, entries| {
                            actual.push((script, count, values(&entries)));
                            Ok(())
                        },
                    )
                    .unwrap();
                    assert_eq!(skipped, dust);
                    assert_eq!(actual, expected);
                    assert!(!fixture.0.join("out.sort").exists());
                }
            }
        }
    }

    let result = visit(&input, &output, &Default::default(), |_, _, _| {
        Err(PipelineError::Io(io::Error::other("output failure")))
    });
    assert!(result.is_err());
    assert!(!fixture.0.join("out.sort").exists());

    // Empty and fully filtered sources emit no groups and leave no scratch.
    for empty in [false, true] {
        if empty {
            std::fs::write(&input, []).unwrap();
        }
        let skipped = visit(
            &input,
            &output,
            &UtxoChunkBuildOptions {
                dust_threshold_sats: u64::MAX,
                ..Default::default()
            },
            |_, _, _| panic!("unexpected group"),
        )
        .unwrap();
        assert_eq!(skipped, if empty { 0 } else { source.len() as u64 });
        assert!(!fixture.0.join("out.sort").exists());
    }
}
