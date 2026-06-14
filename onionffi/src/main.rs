use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("inspect-sibling-rows") if args.len() == 3 => inspect_sibling_rows(&args[2]),
        Some("preprocess-sibling-rows") if args.len() == 4 => {
            preprocess_sibling_rows(&args[2], &args[3])
        }
        Some("preprocess-data-ntt") if args.len() == 4 || args.len() == 5 => {
            preprocess_data_ntt(&args)
        }
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

fn usage(bin: &str) {
    eprintln!(
        "usage:\n  {bin} inspect-sibling-rows <merkle_onion_sib_rows_*.bin>\n  {bin} preprocess-sibling-rows <merkle_onion_sib_rows_*.bin> <out-merkle_onion_sib_*.bin>\n  {bin} preprocess-data-ntt <onion_packed_entries.bin> <out-onion_shared_ntt.bin> [push_batch_entries]\n\nNon-empty preprocessing commands require rebuilding with `--features ffi`."
    );
}
