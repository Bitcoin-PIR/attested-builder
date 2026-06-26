use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    run_with_args(&args)
}

fn run_with_args(args: &[String]) -> ExitCode {
    match args.get(1).map(String::as_str) {
        Some("inspect-sibling-rows") if args.len() == 3 => inspect_sibling_rows(&args[2]),
        Some("preprocess-sibling-rows") if args.len() == 4 => {
            preprocess_sibling_rows(&args[2], &args[3])
        }
        Some("preprocess-data-ntt") if args.len() == 4 || args.len() == 5 => {
            preprocess_data_ntt(&args)
        }
        Some("preprocess-index-all") if args.len() == 5 => preprocess_index_all(&args),
        Some("preprocess-all") if args.len() == 3 || args.len() == 4 => preprocess_all(&args),
        _ => {
            usage(&args[0]);
            ExitCode::from(2)
        }
    }
}

fn inspect_sibling_rows(path: &str) -> ExitCode {
    match onionffi::inspect_sibling_rows_file(path) {
        Ok(meta) => {
            println!("kind={}", meta.kind.label());
            println!("k={}", meta.k);
            println!("arity={}", meta.arity);
            println!("rows_per_group={}", meta.rows_per_group);
            println!("row_bytes={}", meta.row_bytes);
            match meta.body_len() {
                Ok(n) => println!("body_bytes={n}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(1);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn preprocess_sibling_rows(input: &str, output: &str) -> ExitCode {
    match onionffi::preprocess_sibling_rows_file(input, output) {
        Ok(report) => {
            println!("kind={}", report.kind.label());
            println!("k={}", report.k);
            println!("arity={}", report.arity);
            println!("rows_per_group={}", report.rows_per_group);
            println!("blob_len={}", report.blob_len);
            println!("output_bytes={}", report.output_bytes);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn preprocess_data_ntt(args: &[String]) -> ExitCode {
    let push_batch_entries = match args.get(4) {
        Some(s) => match s.parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!("error: push_batch_entries must be a positive integer: {s}");
                return ExitCode::from(2);
            }
        },
        None => onionffi::DEFAULT_PUSH_BATCH_ENTRIES,
    };
    let options = onionffi::DataNttOptions { push_batch_entries };

    match onionffi::preprocess_data_ntt_file(&args[2], &args[3], &options) {
        Ok(report) => {
            println!("input_entries={}", report.input_entries);
            println!("entry_size={}", report.entry_size);
            println!("poly_degree={}", report.poly_degree);
            println!("num_plaintexts={}", report.num_plaintexts);
            println!("coeff_val_cnt={}", report.coeff_val_cnt);
            println!("output_bytes={}", report.output_bytes);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn preprocess_index_all(args: &[String]) -> ExitCode {
    match onionffi::preprocess_index_all_file(&args[2], &args[3], &args[4]) {
        Ok(report) => {
            println!("k={}", report.k);
            println!("bins_per_table={}", report.bins_per_table);
            println!("entry_size={}", report.entry_size);
            println!("poly_degree={}", report.poly_degree);
            println!("num_entries={}", report.num_entries);
            println!("num_plaintexts={}", report.num_plaintexts);
            println!("per_group_bytes={}", report.per_group_bytes);
            println!("anchor_bytes={}", report.anchor_bytes);
            println!("output_bytes={}", report.output_bytes);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn preprocess_all(args: &[String]) -> ExitCode {
    let push_batch_entries = match args.get(3) {
        Some(s) => match s.parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!("error: push_batch_entries must be a positive integer: {s}");
                return ExitCode::from(2);
            }
        },
        None => onionffi::DEFAULT_PUSH_BATCH_ENTRIES,
    };
    let options = onionffi::PreprocessAllOptions {
        data_ntt: onionffi::DataNttOptions { push_batch_entries },
    };

    match onionffi::preprocess_all_dir(&args[2], &options) {
        Ok(report) => {
            println!("data_ntt_input_entries={}", report.data_ntt.input_entries);
            println!("data_ntt_output_bytes={}", report.data_ntt.output_bytes);
            println!("index_all_k={}", report.index_all.k);
            println!(
                "index_all_per_group_bytes={}",
                report.index_all.per_group_bytes
            );
            println!("index_all_output_bytes={}", report.index_all.output_bytes);
            println!(
                "sibling_index_output_bytes={}",
                report.sibling_index.output_bytes
            );
            println!(
                "sibling_data_output_bytes={}",
                report.sibling_data.output_bytes
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn usage(bin: &str) {
    eprintln!(
        "usage:\n  {bin} inspect-sibling-rows <merkle_onion_sib_rows_*.bin>\n  {bin} preprocess-sibling-rows <merkle_onion_sib_rows_*.bin> <out-merkle_onion_sib_*.bin>\n  {bin} preprocess-data-ntt <onion_packed_entries.bin> <out-onion_shared_ntt.bin> [push_batch_entries]\n  {bin} preprocess-index-all <onion_index_bins.bin> <onion_index_meta.bin> <out-onion_index_all.bin>\n  {bin} preprocess-all <pipeline-output-dir> [push_batch_entries]\n\nNon-empty preprocessing commands require rebuilding with `--features ffi`."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_with_args_rejects_unknown_command_with_exit_code_2() {
        let argv: Vec<String> = ["onionffi", "definitely-not-a-real-command"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(run_with_args(&argv), ExitCode::from(2));
    }

    #[test]
    fn run_with_args_rejects_known_command_with_wrong_arity() {
        // `inspect-sibling-rows` expects exactly 3 args (bin + cmd + path).
        let argv: Vec<String> = ["onionffi", "inspect-sibling-rows"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(run_with_args(&argv), ExitCode::from(2));

        let argv: Vec<String> = [
            "onionffi",
            "inspect-sibling-rows",
            "in.bin",
            "extra-arg.bin",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(run_with_args(&argv), ExitCode::from(2));
    }

    #[test]
    fn run_with_args_inspect_missing_file_returns_exit_code_1() {
        let path = unique_temp_path("missing");
        let argv: Vec<String> = ["onionffi", "inspect-sibling-rows", path.to_str().unwrap()]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(run_with_args(&argv), ExitCode::from(1));
    }

    static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        // Combine process id, monotonic counter, and clock so that even
        // parallel test threads get distinct paths even when `as_nanos()`
        // resolution is coarser than expected on some platforms.
        let counter = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "onionffi-main-test-{label}-{pid}-{nanos}-{counter}",
            pid = std::process::id(),
        ));
        path
    }

    fn write_valid_sibling_rows(kind_magic: u64) -> std::path::PathBuf {
        // Header layout matches `onionffi::parse_sibling_rows`:
        //   [magic u64][k u32][arity u32][rows_per_group u32][row_bytes u32]
        // Body length = k * rows_per_group * row_bytes.
        let k: u32 = 1;
        let arity: u32 = 2;
        let rows_per_group: u32 = 1;
        let row_bytes: u32 = arity * 32;
        let body_len = (k as usize) * (rows_per_group as usize) * (row_bytes as usize);

        let mut data = Vec::with_capacity(onionffi::SIBLING_ROWS_HEADER_SIZE + body_len);
        data.extend_from_slice(&kind_magic.to_le_bytes());
        data.extend_from_slice(&k.to_le_bytes());
        data.extend_from_slice(&arity.to_le_bytes());
        data.extend_from_slice(&rows_per_group.to_le_bytes());
        data.extend_from_slice(&row_bytes.to_le_bytes());
        data.extend_from_slice(&vec![0u8; body_len]);

        let path = unique_temp_path("sib-rows");
        std::fs::write(&path, &data).expect("write sibling rows file");
        path
    }

    #[test]
    fn inspect_sibling_rows_reports_meta_for_index_file() {
        let path = write_valid_sibling_rows(onionffi::SIBLING_ROWS_INDEX_MAGIC);
        let meta = onionffi::inspect_sibling_rows_file(&path).expect("inspect should succeed");
        assert_eq!(meta.kind, onionffi::SiblingKind::Index);
        assert_eq!(meta.k, 1);
        assert_eq!(meta.arity, 2);
        assert_eq!(meta.rows_per_group, 1);
        assert_eq!(meta.row_bytes, 64);
        assert_eq!(meta.body_len().unwrap(), 64);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inspect_sibling_rows_reports_meta_for_data_file() {
        let path = write_valid_sibling_rows(onionffi::SIBLING_ROWS_DATA_MAGIC);
        let meta = onionffi::inspect_sibling_rows_file(&path).expect("inspect should succeed");
        assert_eq!(meta.kind, onionffi::SiblingKind::Data);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inspect_sibling_rows_returns_error_for_missing_file() {
        let path = unique_temp_path("missing");
        let err = onionffi::inspect_sibling_rows_file(&path)
            .expect_err("expected error for missing file");
        // Any I/O error is fine; the contract we care about is that a
        // nonexistent path produces an Err rather than a panic.
        let _ = format!("{err}");
    }

    #[test]
    fn inspect_sibling_rows_returns_error_for_truncated_file() {
        let path = unique_temp_path("truncated");
        std::fs::write(&path, [0u8; 4]).expect("write truncated file");
        let err = onionffi::inspect_sibling_rows_file(&path)
            .expect_err("expected error for truncated file");
        assert!(
            matches!(err, onionffi::Error::TooShort { len: 4 }),
            "expected TooShort {{ len: 4 }}, got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
