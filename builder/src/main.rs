use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;
use std::{env, fs};

mod evidence;
mod receipt;
mod root_payload;
mod signer;

const DEFAULT_PROGRESS_INTERVAL_COINS: u64 = 5_000_000;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("verify-snapshot") if args.len() == 4 => verify_snapshot(&args[2], &args[3]),
        Some("compute-muhash") if args.len() == 3 => compute_muhash(&args[2]),
        Some("materialize-utxo-set") if args.len() == 7 => {
            materialize_utxo_set(&args[2], &args[3], &args[4], &args[5], &args[6])
        }
        Some("params-hash") if args.len() == 5 => params_hash(&args[2], &args[3], &args[4]),
        Some("build-utxo-chunks") if args.len() == 4 || args.len() == 5 => {
            build_utxo_chunks(&args[2], &args[3], args.get(4))
        }
        Some("build-onion-pack") if args.len() == 4 || args.len() == 5 => {
            build_onion_pack(&args[2], &args[3], args.get(4))
        }
        Some("write-delta-anchor") if args.len() == 5 => {
            write_delta_anchor(&args[2], &args[3], &args[4])
        }
        Some("build-grouped-delta") if args.len() == 5 => {
            build_grouped_delta(&args[2], &args[3], &args[4])
        }
        Some("build-delta-chunks") if args.len() == 5 => {
            build_delta_chunks(&args[2], &args[3], &args[4])
        }
        Some("build-delta-onion-pack") if args.len() == 4 || args.len() == 5 => {
            build_delta_onion_pack(&args[2], &args[3], args.get(4))
        }
        Some("build-onion-data-cuckoo") if args.len() >= 4 => build_onion_data_cuckoo(&args),
        Some("build-onion-index-cuckoo") if args.len() >= 4 => build_onion_index_cuckoo(&args),
        Some("build-onion-merkle") if (5..=7).contains(&args.len()) => {
            build_onion_merkle(&args[2], &args[3], &args[4], &args[5..])
        }
        Some("build-index-cuckoo") if args.len() == 4 || args.len() == 6 => {
            match parse_optional_anchor(&args, 4) {
                Ok(anchor) => build_index_cuckoo(&args[2], &args[3], anchor),
                Err(code) => code,
            }
        }
        Some("build-chunk-cuckoo") if args.len() == 4 || args.len() == 6 => {
            match parse_optional_anchor(&args, 4) {
                Ok(anchor) => build_chunk_cuckoo(&args[2], &args[3], anchor),
                Err(code) => code,
            }
        }
        Some("build-bucket-merkle") if args.len() == 5 || args.len() == 6 => {
            build_bucket_merkle(&args[2], &args[3], &args[4], args.get(5))
        }
        Some("build-root-bundle-payload") if args.len() == 11 => {
            root_payload::build_root_bundle_payload(
                &args[2], &args[3], &args[4], &args[5], &args[6], &args[7], &args[8], &args[9],
                &args[10],
            )
        }
        Some("build-delta-root-bundle-payload") if args.len() == 12 => {
            root_payload::build_delta_root_bundle_payload(
                &args[2], &args[3], &args[4], &args[5], &args[6], &args[7], &args[8], &args[9],
                &args[10], &args[11],
            )
        }
        Some("write-build-receipt") if args.len() == 6 => {
            receipt::write_build_receipt(&args[2], &args[3], &args[4], &args[5])
        }
        Some("write-build-evidence") if args.len() == 10 => evidence::write_build_evidence(
            &args[2], &args[3], &args[4], &args[5], &args[6], &args[7], &args[8], &args[9],
        ),
        Some("attest-existing-layout") if args.len() == 10 => evidence::attest_existing_layout(
            &args[2], &args[3], &args[4], &args[5], &args[6], &args[7], &args[8], &args[9],
        ),
        Some("inspect-build-evidence") if args.len() == 3 => {
            evidence::inspect_build_evidence(&args[2])
        }
        Some("verify-build-evidence") if args.len() >= 3 => {
            evidence::verify_build_evidence(&args[2], &args[3..])
        }
        Some("write-tee-report-data") if args.len() == 4 => {
            evidence::write_tee_report_data(&args[2], &args[3])
        }
        Some("verify-tee-report-data") if args.len() == 4 => {
            evidence::verify_tee_report_data(&args[2], &args[3])
        }
        Some("emit-sev-snp-quote") if args.len() == 4 || args.len() == 5 => {
            evidence::emit_sev_snp_quote(&args[2], &args[3], args.get(4))
        }
        Some("generate-builder-key") if args.len() == 3 => signer::generate_builder_key(&args[2]),
        Some("sign-root-bundle") if args.len() == 5 => {
            signer::sign_root_bundle(&args[2], &args[3], &args[4])
        }
        Some("verify-root-bundle") if args.len() >= 5 => {
            signer::verify_root_bundle(&args[2], &args[3], &args[4..])
        }
        _ => {
            usage(&args[0]);
            ExitCode::from(2)
        }
    }
}

fn verify_snapshot(snapshot: &str, expected_muhash: &str) -> ExitCode {
    match utxosnapshot::verify_muhash_with_progress(
        snapshot,
        expected_muhash,
        progress_interval_coins(),
        progress_logger("verify-snapshot"),
    ) {
        Ok(report) => {
            println!("network_magic={}", hex::encode(report.header.network_magic));
            println!("coin_count={}", report.header.coin_count);
            println!("base_hash={}", report.header.base_hash_display_hex());
            println!("muhash={}", report.muhash_display_hex);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn compute_muhash(snapshot: &str) -> ExitCode {
    match utxosnapshot::compute_muhash_with_progress(
        snapshot,
        progress_interval_coins(),
        progress_logger("compute-muhash"),
    ) {
        Ok(report) => {
            println!("network_magic={}", hex::encode(report.header.network_magic));
            println!("coin_count={}", report.header.coin_count);
            println!("base_hash={}", report.header.base_hash_display_hex());
            println!("muhash={}", report.muhash_display_hex);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn materialize_utxo_set(
    snapshot: &str,
    expected_muhash: &str,
    out_utxo_set: &str,
    anchor_height: &str,
    out_chain_anchor: &str,
) -> ExitCode {
    let Ok(anchor_height) = anchor_height.parse::<u32>() else {
        eprintln!("error: anchor height must be a u32: {anchor_height}");
        return ExitCode::from(2);
    };
    if Path::new(out_utxo_set).exists() {
        eprintln!("error: output already exists: {out_utxo_set}");
        return ExitCode::from(1);
    }
    if Path::new(out_chain_anchor).exists() {
        eprintln!("error: output already exists: {out_chain_anchor}");
        return ExitCode::from(1);
    }

    match utxosnapshot::materialize_flat_utxo_set_with_progress(
        snapshot,
        out_utxo_set,
        expected_muhash,
        progress_interval_coins(),
        progress_logger("materialize-utxo-set"),
    ) {
        Ok(report) => {
            if let Err(e) =
                utxosnapshot::write_chain_anchor(out_chain_anchor, &report.header, anchor_height)
            {
                eprintln!("error: wrote flat UTXO set but failed writing chain anchor: {e}");
                return ExitCode::from(1);
            }
            println!("network_magic={}", hex::encode(report.header.network_magic));
            println!("coin_count={}", report.coins);
            println!("base_hash={}", report.header.base_hash_display_hex());
            println!("anchor_height={anchor_height}");
            println!("muhash={}", report.muhash_display_hex);
            println!("flat_utxo_bytes={}", report.flat_utxo_bytes);
            println!("flat_utxo_path={out_utxo_set}");
            println!("chain_anchor_path={out_chain_anchor}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn progress_interval_coins() -> u64 {
    match env::var("ATTESTED_BUILDER_PROGRESS_INTERVAL_COINS") {
        Ok(value) => value
            .parse::<u64>()
            .unwrap_or(DEFAULT_PROGRESS_INTERVAL_COINS),
        Err(_) => DEFAULT_PROGRESS_INTERVAL_COINS,
    }
}

fn progress_logger(label: &'static str) -> impl FnMut(utxosnapshot::ScanProgress) {
    let start = Instant::now();
    move |progress| {
        let elapsed = start.elapsed().as_secs_f64();
        let pct = if progress.total_coins == 0 {
            100.0
        } else {
            progress.coins as f64 * 100.0 / progress.total_coins as f64
        };
        let rate = if elapsed > 0.0 {
            progress.coins as f64 / elapsed
        } else {
            0.0
        };
        eprintln!(
            "{label}: coins={}/{} pct={pct:.3} elapsed_s={elapsed:.1} coins_per_s={rate:.0}",
            progress.coins, progress.total_coins
        );
    }
}

fn usage(bin: &str) {
    eprintln!(
        "usage:\n\
  {bin} verify-snapshot <txoutset.dat> <expected-muhash-display-hex>\n\
  {bin} compute-muhash <txoutset.dat>\n\
  {bin} materialize-utxo-set <txoutset.dat> <expected-muhash-display-hex> <out-utxo_set.bin> <anchor-height> <out-chain_anchor.bin>\n\
  {bin} build-utxo-chunks <utxo_set.bin> <out-dir> [partitions]\n\
  {bin} build-onion-pack <utxo_set.bin> <out-dir> [entry-size]\n\
  {bin} write-delta-anchor <from-chain_anchor.bin> <to-chain_anchor.bin> <out-delta_anchor.bin>\n\
  {bin} build-grouped-delta <from-utxo_set.bin> <to-utxo_set.bin> <out-delta_grouped.bin>\n\
  {bin} build-delta-chunks <delta_grouped.bin> <out-delta_chunks.bin> <out-delta_index.bin>\n\
  {bin} build-delta-onion-pack <delta_grouped.bin> <out-dir> [entry-size]\n\
  {bin} build-onion-data-cuckoo <onion_packed_entries.bin> <out-dir> [entry-size] [--anchor <chain-or-delta-anchor.bin>]\n\
  {bin} build-onion-index-cuckoo <onion_index.bin> <out-dir> [entry-size] [--anchor <chain-or-delta-anchor.bin>]\n\
  {bin} build-onion-merkle <onion_index_bin_hashes.bin> <onion_data_bin_hashes.bin> <out-dir> [entry-size] [--root-only]\n\
  {bin} build-index-cuckoo <utxo_chunks_index_nodust.bin> <out-batch_pir_cuckoo.bin> [--anchor <chain-or-delta-anchor.bin>]\n\
  {bin} build-chunk-cuckoo <utxo_chunks_nodust.bin> <out-chunk_pir_cuckoo.bin> [--anchor <chain-or-delta-anchor.bin>]\n\
  {bin} build-bucket-merkle <batch_pir_cuckoo.bin> <chunk_pir_cuckoo.bin> <out-dir> [--root-only]\n\
  {bin} build-root-bundle-payload <out-dir> <network-magic-hex> <chain_anchor.bin> <muhash-display-hex> <index-bins-per-table> <chunk-bins-per-table> <onion-entry-size> <issued-at-unix> <out-payload.bin>\n\
  {bin} build-delta-root-bundle-payload <out-dir> <network-magic-hex> <delta_anchor.bin> <from-muhash-display-hex> <to-muhash-display-hex> <index-bins-per-table> <chunk-bins-per-table> <onion-entry-size> <issued-at-unix> <out-payload.bin>\n\
  {bin} write-build-receipt <signed-root-bundle.bin> <snapshot.dat> <core-version> <out-receipt.txt>\n\
  {bin} write-build-evidence <out-dir> <snapshot.dat> <core-version> <builder-git-commit> <builder-bin> <tee-platform> <tee-image-measurement-hex-or-none> <out-evidence.bin>\n\
  {bin} attest-existing-layout <v1-proof-dir> <artifact-dir> <builder-git-commit> <builder-bin> <tee-platform> <tee-image-measurement-hex-or-none> <issued-at-unix> <out-v2-proof-dir>\n\
  {bin} inspect-build-evidence <build-evidence.bin>\n\
  {bin} verify-build-evidence <build-evidence.bin> [--snapshot <snapshot.dat>] [--builder-bin <path>] [--payload <root-bundle-payload.bin>] [--database-manifest <path>] [--all-artifacts-manifest <path>] [--server-db-manifest <path>] [--expected-muhash <hex>] [--expected-anchor-height <height>] [--expected-anchor-hash <hex>] [--expected-report-data <64-byte-hex>] [--sev-snp-report <report.bin>]\n\
  {bin} write-tee-report-data <build-evidence.bin> <out-report-data.bin>\n\
  {bin} verify-tee-report-data <build-evidence.bin> <report-data-hex-or-file>\n\
  {bin} emit-sev-snp-quote <build-evidence.bin> <out-sev-snp-report.bin> [out-report-data.bin]\n\
  {bin} generate-builder-key <out-builder-key.txt>\n\
  {bin} sign-root-bundle <payload.bin> <builder-key.txt> <out-signed-root-bundle.bin>\n\
  {bin} verify-root-bundle <signed-root-bundle.bin> <threshold> <trusted-pubkey-hex> [trusted-pubkey-hex...]\n\
  {bin} params-hash <index-bins-per-table> <chunk-bins-per-table> <onion-entry-size>"
    );
}

fn parse_optional_anchor<'a>(
    args: &'a [String],
    start: usize,
) -> Result<Option<&'a str>, ExitCode> {
    if args.len() == start {
        return Ok(None);
    }
    if args.len() == start + 2 && args[start] == "--anchor" {
        return Ok(Some(&args[start + 1]));
    }
    eprintln!("error: expected optional argument shape: --anchor <chain-or-delta-anchor.bin>");
    usage(&args[0]);
    Err(ExitCode::from(2))
}

fn build_utxo_chunks(flat_utxo_set: &str, out_dir: &str, partitions: Option<&String>) -> ExitCode {
    let partitions = match partitions {
        Some(s) => match s.parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!("error: partitions must be a positive integer: {s}");
                return ExitCode::from(2);
            }
        },
        None => dbpipeline::UtxoChunkBuildOptions::default().partitions,
    };
    let options = dbpipeline::UtxoChunkBuildOptions {
        partitions,
        ..Default::default()
    };
    match dbpipeline::build_utxo_chunks(flat_utxo_set, out_dir, &options) {
        Ok(report) => {
            println!("input_entries={}", report.input_entries);
            println!("dust_utxos_skipped={}", report.dust_utxos_skipped);
            println!("whale_spks_excluded={}", report.whale_spks_excluded);
            println!("groups_written={}", report.groups_written);
            println!("index_entries={}", report.index_entries);
            println!("chunks_written={}", report.chunks_written);
            println!("chunks_file_bytes={}", report.chunks_file_bytes);
            println!("index_file_bytes={}", report.index_file_bytes);
            println!("data_bytes={}", report.data_bytes);
            println!("padding_bytes={}", report.padding_bytes);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn build_onion_pack(flat_utxo_set: &str, out_dir: &str, entry_size: Option<&String>) -> ExitCode {
    let entry_size = match entry_size {
        Some(s) => match s.parse::<usize>() {
            Ok(n) if n > 0 && n <= u16::MAX as usize => n,
            _ => {
                eprintln!(
                    "error: entry-size must be an integer in 1..={}: {s}",
                    u16::MAX
                );
                return ExitCode::from(2);
            }
        },
        None => dbpipeline::OnionPackOptions::default().entry_size,
    };
    let options = dbpipeline::OnionPackOptions {
        entry_size,
        ..Default::default()
    };
    match dbpipeline::build_onion_pack(flat_utxo_set, out_dir, &options) {
        Ok(report) => {
            println!("input_entries={}", report.input_entries);
            println!("dust_utxos_skipped={}", report.dust_utxos_skipped);
            println!("whale_spks_excluded={}", report.whale_spks_excluded);
            println!("groups_packed={}", report.groups_packed);
            println!("onion_entries={}", report.onion_entries);
            println!("packed_file_bytes={}", report.packed_file_bytes);
            println!("index_file_bytes={}", report.index_file_bytes);
            println!("data_bytes={}", report.data_bytes);
            println!("padding_bytes={}", report.padding_bytes);
            println!("max_serialized_len={}", report.max_serialized_len);
            println!("entry_size={entry_size}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn write_delta_anchor(from_anchor_path: &str, to_anchor_path: &str, out_path: &str) -> ExitCode {
    if Path::new(out_path).exists() {
        eprintln!("error: output already exists: {out_path}");
        return ExitCode::from(1);
    }
    let result = (|| {
        let from = rootbundle::ChainAnchor::load(from_anchor_path)
            .map_err(|e| format!("failed to read from anchor {from_anchor_path}: {e}"))?;
        let to = rootbundle::ChainAnchor::load(to_anchor_path)
            .map_err(|e| format!("failed to read to anchor {to_anchor_path}: {e}"))?;
        let anchor = rootbundle::DeltaAnchor { from, to };
        fs::write(out_path, anchor.to_bytes())
            .map_err(|e| format!("failed to write delta anchor {out_path}: {e}"))?;
        println!("seed_source=delta_anchor");
        println!("from_anchor_height={}", anchor.from.height);
        println!(
            "from_anchor_hash={}",
            display_hash_hex(&anchor.from.block_hash)
        );
        println!("anchor_height={}", anchor.to.height);
        println!("anchor_hash={}", display_hash_hex(&anchor.to.block_hash));
        println!("delta_anchor_path={out_path}");
        Ok::<(), String>(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn build_grouped_delta(from_utxo_set: &str, to_utxo_set: &str, out_grouped: &str) -> ExitCode {
    match dbpipeline::build_grouped_delta_from_flat_sets(
        from_utxo_set,
        to_utxo_set,
        out_grouped,
        &dbpipeline::DeltaBuildOptions::default(),
    ) {
        Ok(report) => {
            println!("from_entries={}", report.from_entries);
            println!("to_entries={}", report.to_entries);
            println!("unchanged_entries={}", report.unchanged_entries);
            println!("spent_entries={}", report.spent_entries);
            println!("created_entries={}", report.created_entries);
            println!("dust_created_skipped={}", report.dust_created_skipped);
            println!("scripts_changed={}", report.scripts_changed);
            println!("grouped_file_bytes={}", report.grouped_file_bytes);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn build_delta_chunks(grouped_delta: &str, chunks_file: &str, index_file: &str) -> ExitCode {
    match dbpipeline::build_delta_chunks(grouped_delta, chunks_file, index_file) {
        Ok(report) => {
            println!("scripts={}", report.scripts);
            println!("chunks_written={}", report.chunks_written);
            println!("index_entries={}", report.index_entries);
            println!("skipped_too_large={}", report.skipped_too_large);
            println!("chunks_file_bytes={}", report.chunks_file_bytes);
            println!("index_file_bytes={}", report.index_file_bytes);
            println!("data_bytes={}", report.data_bytes);
            println!("padding_bytes={}", report.padding_bytes);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn build_delta_onion_pack(
    grouped_delta: &str,
    out_dir: &str,
    entry_size: Option<&String>,
) -> ExitCode {
    let entry_size = match entry_size {
        Some(s) => match s.parse::<usize>() {
            Ok(n) if n > 0 && n <= u16::MAX as usize => n,
            _ => {
                eprintln!(
                    "error: entry-size must be an integer in 1..={}: {s}",
                    u16::MAX
                );
                return ExitCode::from(2);
            }
        },
        None => dbpipeline::OnionPackOptions::default().entry_size,
    };
    let options = dbpipeline::OnionPackOptions {
        entry_size,
        ..Default::default()
    };
    match dbpipeline::build_delta_onion_pack(grouped_delta, out_dir, &options) {
        Ok(report) => {
            println!("scripts={}", report.scripts);
            println!("whale_spks_excluded={}", report.whale_spks_excluded);
            println!("groups_packed={}", report.groups_packed);
            println!("onion_entries={}", report.onion_entries);
            println!("packed_file_bytes={}", report.packed_file_bytes);
            println!("index_file_bytes={}", report.index_file_bytes);
            println!("data_bytes={}", report.data_bytes);
            println!("padding_bytes={}", report.padding_bytes);
            println!("max_serialized_len={}", report.max_serialized_len);
            println!("entry_size={entry_size}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn build_onion_data_cuckoo(args: &[String]) -> ExitCode {
    let packed_file = &args[2];
    let out_dir = &args[3];
    let (entry_size, anchor_path) =
        match parse_onion_entry_size_and_anchor(args, dbpipeline::DEFAULT_ONION_ENTRY_SIZE) {
            Ok(parsed) => parsed,
            Err(code) => return code,
        };

    let options = match onion_data_cuckoo_options(anchor_path, entry_size) {
        Ok(options) => options,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    match dbpipeline::build_onion_data_cuckoo(packed_file, out_dir, &options) {
        Ok(report) => {
            println!("packed_entries={}", report.packed_entries);
            println!("bins_per_table={}", report.bins_per_table);
            println!("total_placements={}", report.total_placements);
            println!("output_bytes={}", report.output_bytes);
            println!("bin_hashes_file_bytes={}", report.bin_hashes_file_bytes);
            println!("entry_size={entry_size}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn build_onion_index_cuckoo(args: &[String]) -> ExitCode {
    let index_file = &args[2];
    let out_dir = &args[3];
    let (entry_size, anchor_path) =
        match parse_onion_entry_size_and_anchor(args, dbpipeline::DEFAULT_ONION_ENTRY_SIZE) {
            Ok(parsed) => parsed,
            Err(code) => return code,
        };

    let options = match onion_index_cuckoo_options(anchor_path, entry_size) {
        Ok(options) => options,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    match dbpipeline::build_onion_index_cuckoo(index_file, out_dir, &options) {
        Ok(report) => {
            println!("index_entries={}", report.index_entries);
            println!("non_whale_entries={}", report.non_whale_entries);
            println!("bins_per_table={}", report.bins_per_table);
            println!("slots_per_bin={}", report.slots_per_bin);
            println!("total_placements={}", report.total_placements);
            println!("raw_bins_file_bytes={}", report.raw_bins_file_bytes);
            println!("meta_file_bytes={}", report.meta_file_bytes);
            println!("bin_hashes_file_bytes={}", report.bin_hashes_file_bytes);
            println!("entry_size={entry_size}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn build_onion_merkle(
    index_bin_hashes: &str,
    data_bin_hashes: &str,
    out_dir: &str,
    optional_args: &[String],
) -> ExitCode {
    let (entry_size, root_only) = match parse_entry_size_and_root_only(
        optional_args,
        dbpipeline::OnionMerkleOptions::default().entry_size,
    ) {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };
    let options = dbpipeline::OnionMerkleOptions {
        entry_size,
        root_only,
    };
    match dbpipeline::build_onion_merkle(index_bin_hashes, data_bin_hashes, out_dir, &options) {
        Ok(report) => {
            println!("index_k={}", report.index_k);
            println!("data_k={}", report.data_k);
            println!("index_bins_per_table={}", report.index_bins_per_table);
            println!("data_bins_per_table={}", report.data_bins_per_table);
            println!("arity={}", report.arity);
            println!("tree_count={}", report.tree_count);
            println!(
                "index_sibling_rows_per_group={}",
                report.index_sibling_rows_per_group
            );
            println!(
                "data_sibling_rows_per_group={}",
                report.data_sibling_rows_per_group
            );
            println!("tree_tops_file_bytes={}", report.tree_tops_file_bytes);
            println!("roots_file_bytes={}", report.roots_file_bytes);
            println!(
                "index_sibling_rows_file_bytes={}",
                report.index_sibling_rows_file_bytes
            );
            println!(
                "data_sibling_rows_file_bytes={}",
                report.data_sibling_rows_file_bytes
            );
            println!("super_root={}", hex::encode(report.super_root));
            println!("entry_size={entry_size}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn parse_entry_size_and_root_only(
    args: &[String],
    default_entry_size: usize,
) -> Result<(usize, bool), ExitCode> {
    let mut entry_size = default_entry_size;
    let mut root_only = false;
    let mut saw_entry_size = false;

    for arg in args {
        if arg == "--root-only" {
            root_only = true;
        } else if saw_entry_size {
            eprintln!("error: unexpected argument: {arg}");
            return Err(ExitCode::from(2));
        } else {
            match arg.parse::<usize>() {
                Ok(n) if n > 0 && n <= u16::MAX as usize => {
                    entry_size = n;
                    saw_entry_size = true;
                }
                _ => {
                    eprintln!(
                        "error: entry-size must be an integer in 1..={}: {arg}",
                        u16::MAX
                    );
                    return Err(ExitCode::from(2));
                }
            }
        }
    }

    Ok((entry_size, root_only))
}

fn parse_onion_entry_size_and_anchor<'a>(
    args: &'a [String],
    default_entry_size: usize,
) -> Result<(usize, Option<&'a str>), ExitCode> {
    let mut entry_size = default_entry_size;
    let mut anchor_path: Option<&str> = None;

    let mut i = 4;
    if let Some(arg) = args.get(i) {
        if arg != "--anchor" {
            match arg.parse::<usize>() {
                Ok(n) if n > 0 && n <= u16::MAX as usize => entry_size = n,
                _ => {
                    eprintln!(
                        "error: entry-size must be an integer in 1..={}: {arg}",
                        u16::MAX
                    );
                    return Err(ExitCode::from(2));
                }
            }
            i += 1;
        }
    }
    if i < args.len() {
        if args.len() == i + 2 && args[i] == "--anchor" {
            anchor_path = Some(&args[i + 1]);
        } else {
            eprintln!("error: expected optional argument shape: [entry-size] [--anchor <chain-or-delta-anchor.bin>]");
            usage(&args[0]);
            return Err(ExitCode::from(2));
        }
    }

    Ok((entry_size, anchor_path))
}

fn build_index_cuckoo(index_file: &str, output_file: &str, anchor_path: Option<&str>) -> ExitCode {
    let options = match index_cuckoo_options(anchor_path) {
        Ok(options) => options,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    match dbpipeline::build_index_cuckoo(index_file, output_file, &options) {
        Ok(report) => {
            println!("index_entries={}", report.index_entries);
            println!("bins_per_table={}", report.bins_per_table);
            println!("slots_per_table={}", report.slots_per_table);
            println!("total_placements={}", report.total_placements);
            println!("output_bytes={}", report.output_bytes);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn build_chunk_cuckoo(chunks_file: &str, output_file: &str, anchor_path: Option<&str>) -> ExitCode {
    let options = match chunk_cuckoo_options(anchor_path) {
        Ok(options) => options,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    match dbpipeline::build_chunk_cuckoo(chunks_file, output_file, &options) {
        Ok(report) => {
            println!("chunks={}", report.chunks);
            println!("bins_per_table={}", report.bins_per_table);
            println!("slots_per_table={}", report.slots_per_table);
            println!("total_placements={}", report.total_placements);
            println!("output_bytes={}", report.output_bytes);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn build_bucket_merkle(
    index_cuckoo: &str,
    chunk_cuckoo: &str,
    out_dir: &str,
    mode: Option<&String>,
) -> ExitCode {
    let root_only = match mode.map(String::as_str) {
        None => false,
        Some("--root-only") => true,
        Some(arg) => {
            eprintln!("error: unexpected argument for build-bucket-merkle: {arg}");
            return ExitCode::from(2);
        }
    };
    let options = dbpipeline::BucketMerkleOptions { root_only };
    match dbpipeline::build_bucket_merkle_with_options(
        index_cuckoo,
        chunk_cuckoo,
        out_dir,
        &options,
    ) {
        Ok(report) => {
            println!("index_bins_per_table={}", report.index_bins_per_table);
            println!("chunk_bins_per_table={}", report.chunk_bins_per_table);
            println!("index_sibling_levels={:?}", report.index_sibling_levels);
            println!("chunk_sibling_levels={:?}", report.chunk_sibling_levels);
            println!("tree_count={}", report.tree_count);
            println!("tree_tops_file_bytes={}", report.tree_tops_file_bytes);
            println!("roots_file_bytes={}", report.roots_file_bytes);
            println!("super_root={}", hex::encode(report.super_root));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn index_cuckoo_options(
    anchor_path: Option<&str>,
) -> Result<dbpipeline::IndexCuckooOptions, String> {
    match anchor_path {
        Some(path) => {
            let source = load_anchor_seed_source(path)?;
            source.print_seed_source();
            println!("index_master_seed=0x{:016x}", source.index_master_seed());
            println!("index_tag_seed=0x{:016x}", source.index_tag_seed());
            Ok(dbpipeline::IndexCuckooOptions {
                master_seed: source.index_master_seed(),
                tag_seed: source.index_tag_seed(),
                snapshot_anchor: source.snapshot_anchor_bytes(),
                delta_anchor: source.delta_anchor_bytes(),
            })
        }
        None => {
            let options = dbpipeline::IndexCuckooOptions::default();
            println!("seed_source=legacy");
            println!("index_master_seed=0x{:016x}", options.master_seed);
            println!("index_tag_seed=0x{:016x}", options.tag_seed);
            Ok(options)
        }
    }
}

fn chunk_cuckoo_options(
    anchor_path: Option<&str>,
) -> Result<dbpipeline::ChunkCuckooOptions, String> {
    match anchor_path {
        Some(path) => {
            let source = load_anchor_seed_source(path)?;
            source.print_seed_source();
            println!("chunk_master_seed=0x{:016x}", source.chunk_master_seed());
            Ok(dbpipeline::ChunkCuckooOptions {
                master_seed: source.chunk_master_seed(),
                snapshot_anchor: source.snapshot_anchor_bytes(),
                delta_anchor: source.delta_anchor_bytes(),
            })
        }
        None => {
            let options = dbpipeline::ChunkCuckooOptions::default();
            println!("seed_source=legacy");
            println!("chunk_master_seed=0x{:016x}", options.master_seed);
            Ok(options)
        }
    }
}

fn onion_data_cuckoo_options(
    anchor_path: Option<&str>,
    entry_size: usize,
) -> Result<dbpipeline::OnionDataCuckooOptions, String> {
    match anchor_path {
        Some(path) => {
            let source = load_anchor_seed_source(path)?;
            source.print_seed_source();
            println!(
                "onion_data_master_seed=0x{:016x}",
                source.chunk_master_seed()
            );
            Ok(dbpipeline::OnionDataCuckooOptions {
                master_seed: source.chunk_master_seed(),
                snapshot_anchor: source.snapshot_anchor_bytes(),
                delta_anchor: source.delta_anchor_bytes(),
                entry_size,
            })
        }
        None => {
            let options = dbpipeline::OnionDataCuckooOptions {
                entry_size,
                ..Default::default()
            };
            println!("seed_source=legacy");
            println!("onion_data_master_seed=0x{:016x}", options.master_seed);
            Ok(options)
        }
    }
}

fn onion_index_cuckoo_options(
    anchor_path: Option<&str>,
    entry_size: usize,
) -> Result<dbpipeline::OnionIndexCuckooOptions, String> {
    match anchor_path {
        Some(path) => {
            let source = load_anchor_seed_source(path)?;
            source.print_seed_source();
            println!(
                "onion_index_master_seed=0x{:016x}",
                source.index_master_seed()
            );
            println!("onion_index_tag_seed=0x{:016x}", source.index_tag_seed());
            Ok(dbpipeline::OnionIndexCuckooOptions {
                master_seed: source.index_master_seed(),
                tag_seed: source.index_tag_seed(),
                snapshot_anchor: source.snapshot_anchor_bytes(),
                delta_anchor: source.delta_anchor_bytes(),
                entry_size,
            })
        }
        None => {
            let options = dbpipeline::OnionIndexCuckooOptions {
                entry_size,
                ..Default::default()
            };
            println!("seed_source=legacy");
            println!("onion_index_master_seed=0x{:016x}", options.master_seed);
            println!("onion_index_tag_seed=0x{:016x}", options.tag_seed);
            Ok(options)
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AnchorSeedSource {
    Snapshot(rootbundle::ChainAnchor, rootbundle::SnapshotSeeds),
    Delta(rootbundle::DeltaAnchor, rootbundle::DeltaSeeds),
}

impl AnchorSeedSource {
    fn index_master_seed(&self) -> u64 {
        match self {
            AnchorSeedSource::Snapshot(_, seeds) => seeds.index_master,
            AnchorSeedSource::Delta(_, seeds) => seeds.index_master,
        }
    }

    fn chunk_master_seed(&self) -> u64 {
        match self {
            AnchorSeedSource::Snapshot(_, seeds) => seeds.chunk_master,
            AnchorSeedSource::Delta(_, seeds) => seeds.chunk_master,
        }
    }

    fn index_tag_seed(&self) -> u64 {
        match self {
            AnchorSeedSource::Snapshot(_, seeds) => seeds.index_tag,
            AnchorSeedSource::Delta(_, seeds) => seeds.index_tag,
        }
    }

    fn snapshot_anchor_bytes(&self) -> Option<[u8; dbpipeline::CHAIN_ANCHOR_BYTES]> {
        match self {
            AnchorSeedSource::Snapshot(anchor, _) => Some(anchor.to_bytes()),
            AnchorSeedSource::Delta(_, _) => None,
        }
    }

    fn delta_anchor_bytes(&self) -> Option<[u8; dbpipeline::DELTA_ANCHOR_BYTES]> {
        match self {
            AnchorSeedSource::Snapshot(_, _) => None,
            AnchorSeedSource::Delta(anchor, _) => Some(anchor.to_bytes()),
        }
    }

    fn print_seed_source(&self) {
        match self {
            AnchorSeedSource::Snapshot(anchor, _) => {
                println!("seed_source=chain_anchor");
                println!("anchor_height={}", anchor.height);
                println!("anchor_hash={}", display_hash_hex(&anchor.block_hash));
            }
            AnchorSeedSource::Delta(anchor, _) => {
                println!("seed_source=delta_anchor");
                println!("from_anchor_height={}", anchor.from.height);
                println!(
                    "from_anchor_hash={}",
                    display_hash_hex(&anchor.from.block_hash)
                );
                println!("anchor_height={}", anchor.to.height);
                println!("anchor_hash={}", display_hash_hex(&anchor.to.block_hash));
            }
        }
    }
}

fn load_anchor_seed_source(path: &str) -> Result<AnchorSeedSource, String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read anchor {path}: {e}"))?;
    match bytes.len() {
        rootbundle::CHAIN_ANCHOR_BYTES => {
            let anchor = rootbundle::ChainAnchor::from_bytes(&bytes)
                .map_err(|e| format!("failed to decode chain anchor {path}: {e}"))?;
            let seeds = rootbundle::SnapshotSeeds::derive(&anchor);
            Ok(AnchorSeedSource::Snapshot(anchor, seeds))
        }
        rootbundle::DELTA_ANCHOR_BYTES => {
            let anchor = rootbundle::DeltaAnchor::from_bytes(&bytes)
                .map_err(|e| format!("failed to decode delta anchor {path}: {e}"))?;
            let seeds = rootbundle::DeltaSeeds::derive(&anchor);
            Ok(AnchorSeedSource::Delta(anchor, seeds))
        }
        len => Err(format!(
            "anchor {path} must be {} bytes (chain) or {} bytes (delta), got {len}",
            rootbundle::CHAIN_ANCHOR_BYTES,
            rootbundle::DELTA_ANCHOR_BYTES
        )),
    }
}

fn display_hash_hex(internal: &[u8; 32]) -> String {
    let mut h = *internal;
    h.reverse();
    hex::encode(h)
}

fn params_hash(index_bins: &str, chunk_bins: &str, onion_entry_size: &str) -> ExitCode {
    let Ok(index_bins) = index_bins.parse::<u32>() else {
        eprintln!("error: index-bins-per-table must be a u32: {index_bins}");
        return ExitCode::from(2);
    };
    let Ok(chunk_bins) = chunk_bins.parse::<u32>() else {
        eprintln!("error: chunk-bins-per-table must be a u32: {chunk_bins}");
        return ExitCode::from(2);
    };
    let Ok(onion_entry_size) = onion_entry_size.parse::<u32>() else {
        eprintln!("error: onion-entry-size must be a u32: {onion_entry_size}");
        return ExitCode::from(2);
    };
    let params =
        rootbundle::BuildParamsV1::current_snapshot(index_bins, chunk_bins, onion_entry_size);
    println!("index_dpf_n={}", params.index.dpf_n);
    println!("chunk_dpf_n={}", params.chunk.dpf_n);
    println!(
        "onion_index_slots_per_bin={}",
        params.onion_index_slots_per_bin
    );
    println!("params_hash={}", hex::encode(params.params_hash()));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_optional_anchor_returns_none_when_no_extra_args() {
        let argv = args(&[
            "pir-attested-builder",
            "build-index-cuckoo",
            "in.bin",
            "out.bin",
        ]);
        assert!(matches!(parse_optional_anchor(&argv, 4), Ok(None)));
    }

    #[test]
    fn parse_optional_anchor_accepts_anchor_value() {
        let argv = args(&[
            "pir-attested-builder",
            "build-index-cuckoo",
            "in.bin",
            "out.bin",
            "--anchor",
            "anchor.bin",
        ]);
        match parse_optional_anchor(&argv, 4) {
            Ok(Some(path)) => assert_eq!(path, "anchor.bin"),
            other => panic!("expected Ok(Some(\"anchor.bin\")), got {other:?}"),
        }
    }

    #[test]
    fn parse_optional_anchor_rejects_malformed_extra_args() {
        // `--anchor` without a value
        let argv = args(&[
            "pir-attested-builder",
            "build-index-cuckoo",
            "in.bin",
            "out.bin",
            "--anchor",
        ]);
        assert_eq!(parse_optional_anchor(&argv, 4), Err(ExitCode::from(2)));

        // trailing positional arg without `--anchor` flag
        let argv = args(&[
            "pir-attested-builder",
            "build-index-cuckoo",
            "in.bin",
            "out.bin",
            "unexpected.bin",
        ]);
        assert_eq!(parse_optional_anchor(&argv, 4), Err(ExitCode::from(2)));
    }

    #[test]
    fn parse_entry_size_and_root_only_uses_defaults_for_empty_args() {
        let argv = args(&[]);
        let (size, root_only) =
            parse_entry_size_and_root_only(&argv, 3_328).expect("empty args should parse");
        assert_eq!(size, 3_328);
        assert!(!root_only);
    }

    #[test]
    fn parse_entry_size_and_root_only_accepts_entry_size_alone() {
        let argv = args(&["42"]);
        let (size, root_only) =
            parse_entry_size_and_root_only(&argv, 3_328).expect("entry-size only should parse");
        assert_eq!(size, 42);
        assert!(!root_only);
    }

    #[test]
    fn parse_entry_size_and_root_only_accepts_root_only_alone() {
        let argv = args(&["--root-only"]);
        let (size, root_only) =
            parse_entry_size_and_root_only(&argv, 3_328).expect("--root-only should parse");
        assert_eq!(size, 3_328);
        assert!(root_only);
    }

    #[test]
    fn parse_entry_size_and_root_only_accepts_entry_size_then_root_only() {
        let argv = args(&["42", "--root-only"]);
        let (size, root_only) = parse_entry_size_and_root_only(&argv, 3_328)
            .expect("entry-size+root-only should parse");
        assert_eq!(size, 42);
        assert!(root_only);
    }

    #[test]
    fn parse_entry_size_and_root_only_rejects_zero_entry_size() {
        let argv = args(&["0"]);
        assert_eq!(
            parse_entry_size_and_root_only(&argv, 3_328),
            Err(ExitCode::from(2))
        );
    }

    #[test]
    fn parse_entry_size_and_root_only_rejects_out_of_range_entry_size() {
        let argv = args(&["65536"]);
        assert_eq!(
            parse_entry_size_and_root_only(&argv, 3_328),
            Err(ExitCode::from(2))
        );
    }

    #[test]
    fn parse_entry_size_and_root_only_rejects_non_integer_entry_size() {
        let argv = args(&["not-a-number"]);
        assert_eq!(
            parse_entry_size_and_root_only(&argv, 3_328),
            Err(ExitCode::from(2))
        );
    }

    #[test]
    fn parse_entry_size_and_root_only_rejects_extra_positional_after_entry_size() {
        let argv = args(&["42", "extra"]);
        assert_eq!(
            parse_entry_size_and_root_only(&argv, 3_328),
            Err(ExitCode::from(2))
        );
    }

    #[test]
    fn parse_onion_entry_size_and_anchor_uses_defaults_for_empty_tail() {
        let argv = args(&[
            "pir-attested-builder",
            "build-onion-data-cuckoo",
            "in.bin",
            "out-dir",
        ]);
        let (size, anchor) =
            parse_onion_entry_size_and_anchor(&argv, dbpipeline::DEFAULT_ONION_ENTRY_SIZE)
                .expect("empty tail should parse");
        assert_eq!(size, dbpipeline::DEFAULT_ONION_ENTRY_SIZE);
        assert_eq!(anchor, None);
    }

    #[test]
    fn parse_onion_entry_size_and_anchor_accepts_anchor_only() {
        let argv = args(&[
            "pir-attested-builder",
            "build-onion-data-cuckoo",
            "in.bin",
            "out-dir",
            "--anchor",
            "anchor.bin",
        ]);
        let (size, anchor) =
            parse_onion_entry_size_and_anchor(&argv, dbpipeline::DEFAULT_ONION_ENTRY_SIZE)
                .expect("anchor-only should parse");
        assert_eq!(size, dbpipeline::DEFAULT_ONION_ENTRY_SIZE);
        assert_eq!(anchor, Some("anchor.bin"));
    }

    #[test]
    fn parse_onion_entry_size_and_anchor_accepts_entry_size_and_anchor() {
        let argv = args(&[
            "pir-attested-builder",
            "build-onion-data-cuckoo",
            "in.bin",
            "out-dir",
            "42",
            "--anchor",
            "anchor.bin",
        ]);
        let (size, anchor) =
            parse_onion_entry_size_and_anchor(&argv, dbpipeline::DEFAULT_ONION_ENTRY_SIZE)
                .expect("entry-size+anchor should parse");
        assert_eq!(size, 42);
        assert_eq!(anchor, Some("anchor.bin"));
    }

    #[test]
    fn parse_onion_entry_size_and_anchor_rejects_invalid_entry_size() {
        let argv = args(&[
            "pir-attested-builder",
            "build-onion-data-cuckoo",
            "in.bin",
            "out-dir",
            "not-a-number",
        ]);
        assert_eq!(
            parse_onion_entry_size_and_anchor(&argv, dbpipeline::DEFAULT_ONION_ENTRY_SIZE),
            Err(ExitCode::from(2))
        );
    }

    #[test]
    fn parse_onion_entry_size_and_anchor_rejects_dangling_anchor_flag() {
        let argv = args(&[
            "pir-attested-builder",
            "build-onion-data-cuckoo",
            "in.bin",
            "out-dir",
            "--anchor",
        ]);
        assert_eq!(
            parse_onion_entry_size_and_anchor(&argv, dbpipeline::DEFAULT_ONION_ENTRY_SIZE),
            Err(ExitCode::from(2))
        );
    }

    #[test]
    fn parse_onion_entry_size_and_anchor_rejects_trailing_positional_without_flag() {
        let argv = args(&[
            "pir-attested-builder",
            "build-onion-data-cuckoo",
            "in.bin",
            "out-dir",
            "42",
            "extra",
        ]);
        assert_eq!(
            parse_onion_entry_size_and_anchor(&argv, dbpipeline::DEFAULT_ONION_ENTRY_SIZE),
            Err(ExitCode::from(2))
        );
    }

    #[test]
    fn display_hash_hex_reverses_and_encodes() {
        let mut internal = [0u8; 32];
        for (i, b) in internal.iter_mut().enumerate() {
            *b = i as u8;
        }
        // After reversal, the first output byte is the original last byte (0x1f).
        assert_eq!(
            display_hash_hex(&internal),
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        );
    }
}
