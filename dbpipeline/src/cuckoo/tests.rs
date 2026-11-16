use super::*;

fn fixture(label: &str) -> Scratch {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    Scratch::new(
        &std::env::temp_dir().join(format!("cuckoo-{label}-{}-{nonce}", std::process::id())),
    )
    .unwrap()
}

#[test]
fn spooled_tables_match_full_memory_reference() {
    let dir = fixture("reference");
    for count in [0, 1, 111, 2048] {
        let mut indices = Vec::new();
        let mut chunks = Vec::new();
        for i in 0..count as u64 {
            let hash = sha256(&i.to_le_bytes());
            indices.extend_from_slice(&hash[..20]);
            indices.extend_from_slice(&(i as u32 * 3).to_le_bytes());
            indices.push((i % 101) as u8);
            chunks.extend_from_slice(&hash);
            chunks.extend_from_slice(&i.to_le_bytes());
        }
        let index_path = dir.0.join("index-input");
        let chunk_path = dir.0.join("chunk-input");
        std::fs::write(&index_path, &indices).unwrap();
        std::fs::write(&chunk_path, &chunks).unwrap();
        for kind in 0..3 {
            let snapshot_anchor = (kind == 1).then_some([0x51; CHAIN_ANCHOR_BYTES]);
            let delta_anchor = (kind == 2).then_some([0x72; DELTA_ANCHOR_BYTES]);
            let index_options = IndexCuckooOptions {
                master_seed: 17,
                tag_seed: 29,
                snapshot_anchor,
                delta_anchor,
            };
            let chunk_options = ChunkCuckooOptions {
                master_seed: 0x875a_2299_804a_46fc,
                snapshot_anchor,
                delta_anchor,
            };
            let reference = dir.0.join("reference");
            let output = dir.0.join("output");
            let old = build_index_cuckoo_legacy(&index_path, &reference, &index_options).unwrap();
            let new = build_index_cuckoo(&index_path, &output, &index_options).unwrap();
            assert_eq!(old, new);
            assert_eq!(
                std::fs::read(&reference).unwrap(),
                std::fs::read(&output).unwrap()
            );
            std::fs::remove_file(&reference).unwrap();
            std::fs::remove_file(&output).unwrap();
            let old = build_chunk_cuckoo_legacy(&chunk_path, &reference, &chunk_options).unwrap();
            let new = build_chunk_cuckoo(&chunk_path, &output, &chunk_options).unwrap();
            assert_eq!(old, new);
            if count == 111 {
                // Known fixture requiring an actual global bin-count retry.
                assert_eq!(new.bins_per_table, 4);
            }
            assert_eq!(
                std::fs::read(&reference).unwrap(),
                std::fs::read(&output).unwrap()
            );
            std::fs::remove_file(&reference).unwrap();
            std::fs::remove_file(&output).unwrap();
            assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 2);
        }
    }
}

#[test]
fn late_retry_rewrites_earlier_groups_header_and_tail() {
    let dir = fixture("retry");
    let output = dir.0.join("output");
    let mut visits = Vec::new();
    let bins = write_groups(
        &output,
        &[1, 1, 1],
        INDEX_SLOTS_PER_BIN,
        |writer, bins| {
            writer.write_all(&(bins as u64).to_le_bytes())?;
            Ok(())
        },
        |writer, group, bins| {
            visits.push((bins, group));
            if bins == 1 {
                // Exceed BufWriter capacity so this attempt leaves both
                // on-disk bytes and buffered bytes before the late failure.
                if group == 2 {
                    return Err(PipelineError::CuckooInsertFailed {
                        group_id: group,
                        local_index: 1,
                    });
                }
                writer.write_all(&vec![0x55; 5 * 1024 * 1024])?;
                writer.write_all(b"buffered tail")?;
            } else {
                writer.write_all(&[group as u8])?;
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(bins, 2);
    assert_eq!(visits, [(1, 0), (1, 1), (1, 2), (2, 0), (2, 1), (2, 2)]);
    let mut expected = 2u64.to_le_bytes().to_vec();
    expected.extend_from_slice(&[0, 1, 2]);
    assert_eq!(std::fs::read(output).unwrap(), expected);
}

#[test]
fn invalid_inputs_and_spool_failures_leave_no_owned_files() {
    let dir = fixture("errors");
    let input = dir.0.join("input");
    let output = dir.0.join("output");
    std::fs::write(&input, [0]).unwrap();
    assert!(matches!(
        build_index_cuckoo(&input, &output, &Default::default()),
        Err(PipelineError::InvalidIndexSize { bytes: 1 })
    ));
    assert!(matches!(
        build_chunk_cuckoo(&input, &output, &Default::default()),
        Err(PipelineError::InvalidChunksSize { bytes: 1 })
    ));
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
    // Truncation after metadata validation, after a record was already spooled.
    std::fs::write(&input, [0; INDEX_RECORD_SIZE]).unwrap();
    assert!(
        spool::<INDEX_RECORD_SIZE, INDEX_RECORD_SIZE>(&input, &output, INDEX_K, 2, |_, r| (
            [0, 1, 2],
            r
        ))
        .is_err()
    );
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
    // An existing output or scratch directory belongs to its creator.
    std::fs::write(&output, b"keep").unwrap();
    assert!(matches!(
        build_index_cuckoo(&input, &output, &Default::default()),
        Err(PipelineError::OutputExists(_))
    ));
    assert_eq!(std::fs::read(&output).unwrap(), b"keep");
    std::fs::remove_file(&output).unwrap();
    let scratch = Scratch::new(&temp_path(&output)).unwrap();
    std::fs::write(scratch.0.join("keep"), b"keep").unwrap();
    assert!(build_index_cuckoo(&input, &output, &Default::default()).is_err());
    assert_eq!(std::fs::read(scratch.0.join("keep")).unwrap(), b"keep");
    assert!(!output.exists());
}
