use super::*;

fn fixture(label: &str) -> Scratch {
    let path = temp_save_path_near(&std::env::temp_dir().join(label)).unwrap();
    std::fs::create_dir(&path).unwrap();
    Scratch(path)
}

// Independent full-table FFI reference. Explicitly initialize shape padding:
// the old allocator left these bytes unspecified (the retained mainnet build
// happened to get zero pages). No batching/scattering logic is shared here.
fn full_table(raw: &[u8], dir: &Path) -> Vec<u8> {
    let entries = raw.len() / 3328;
    let p = onionpir::params_info(entries as u64);
    let mut coeffs = Vec::new();
    for entry in raw.chunks_exact(3328) {
        coeffs.extend(pack_bytes_into_coefficients(
            entry,
            3328,
            p.poly_degree as usize,
        ));
    }
    coeffs.resize(p.num_plaintexts as usize * p.poly_degree as usize, 0);
    let mut server = onionpir::Server::new(entries as u64);
    assert!(server.push_plaintexts(&coeffs, p.num_plaintexts, 0, &[]));
    let saved = dir.join("reference.bin");
    assert!(server.save_db(saved.to_str().unwrap()));
    let bytes = std::fs::read(saved).unwrap();
    bytes[ONION_SAVE_DB_HEADER_SIZE..].to_vec()
}

#[test]
fn batches_match_full_table_across_shapes() {
    let dir = fixture("ntt-shapes");
    let input = dir.0.join("input");
    let output = dir.0.join("output");
    for (count, batches) in [
        (1, vec![1, 256]),
        (17, vec![1, 7, 8, 16, 256]),
        (257, vec![7, 256, 257]),
        (1025, vec![256, 511, usize::MAX]),
        (4097, vec![256, 511, usize::MAX]),
    ] {
        let raw: Vec<u8> = (0..count * 3328)
            .map(|i| ((i * 73 + i / 3328 * 19) % 256) as u8)
            .collect();
        std::fs::write(&input, &raw).unwrap();
        let expected = full_table(&raw, &dir.0);
        let p = onionpir::params_info(count as u64);
        for batch in batches {
            let report = preprocess_data_ntt_file(
                &input,
                &output,
                &DataNttOptions {
                    push_batch_entries: batch,
                },
            )
            .unwrap();
            assert_eq!(report.input_entries, count as u64);
            assert_eq!(report.num_plaintexts, p.num_plaintexts);
            assert_eq!(report.output_bytes, expected.len() as u64);
            assert_eq!(
                std::fs::read(&output).unwrap(),
                expected,
                "count={count}, batch={batch}"
            );
            std::fs::remove_file(&output).unwrap();
            assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 2);
        }
    }
}

#[test]
fn empty_input_keeps_default_shape_and_zero_payload() {
    let dir = fixture("ntt-empty");
    let input = dir.0.join("input");
    let output = dir.0.join("output");
    std::fs::write(&input, []).unwrap();
    let p = onionpir::params_info(0);
    let report = preprocess_data_ntt_file(&input, &output, &Default::default()).unwrap();
    assert_eq!(report.input_entries, 0);
    assert_eq!(report.num_plaintexts, p.num_plaintexts);
    assert_eq!(report.output_bytes, p.num_plaintexts * p.coeff_val_cnt * 8);
    let mut file = File::open(&output).unwrap();
    assert_eq!(file.metadata().unwrap().len(), report.output_bytes);
    for offset in [0, report.output_bytes / 2, report.output_bytes - 64] {
        let mut buf = [0xff; 64];
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0; 64]);
    }
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 2);
}

#[test]
fn failures_clean_owned_files_and_preserve_existing_output() {
    let dir = fixture("ntt-errors");
    let input = dir.0.join("input");
    let output = dir.0.join("output");
    std::fs::write(&input, vec![0x51; MAX_BATCH_ENTRIES * 3328]).unwrap();
    let options = DataNttOptions {
        push_batch_entries: 256,
    };
    let entries = MAX_BATCH_ENTRIES as u64 + 1;
    let p = onionpir::params_info(entries);
    // Simulate input truncation after metadata validation and one saved tile.
    // Both the partially constructed output and batch scratch must vanish.
    assert!(write(
        &input,
        &output,
        &options,
        &p,
        entries,
        p.num_plaintexts * p.coeff_val_cnt * 8
    )
    .is_err());
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
    std::fs::write(&output, b"existing").unwrap();
    assert!(write(&input, &output, &options, &p, 2, 32768).is_err());
    assert_eq!(std::fs::read(&output).unwrap(), b"existing");
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 2);
    std::fs::remove_file(&output).unwrap();
    std::fs::write(&input, [1]).unwrap();
    assert!(matches!(
        preprocess_data_ntt_file(&input, &output, &options),
        Err(Error::InvalidPackedSize { .. })
    ));
    assert!(matches!(
        preprocess_data_ntt_file(
            &input,
            &output,
            &DataNttOptions {
                push_batch_entries: 0
            }
        ),
        Err(Error::InvalidBatchSize(0))
    ));
    assert!(!output.exists());
}
