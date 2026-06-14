use std::env;
use std::path::Path;
use std::process::ExitCode;

mod root_payload;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("verify-snapshot") if args.len() == 4 => verify_snapshot(&args[2], &args[3]),
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
        Some("build-onion-data-cuckoo") if args.len() >= 4 => build_onion_data_cuckoo(&args),
        Some("build-onion-index-cuckoo") if args.len() >= 4 => build_onion_index_cuckoo(&args),
        Some("build-onion-merkle") if args.len() == 5 || args.len() == 6 => {
            build_onion_merkle(&args[2], &args[3], &args[4], args.get(5))
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
        Some("build-bucket-merkle") if args.len() == 5 => {
            build_bucket_merkle(&args[2], &args[3], &args[4])
        }
        Some("build-root-bundle-payload") if args.len() == 11 => {
            root_payload::build_root_bundle_payload(
                &args[2], &args[3], &args[4], &args[5], &args[6], &args[7], &args[8], &args[9],
                &args[10],
            )
        }
        _ => {
            usage(&args[0]);
            ExitCode::from(2)
        }
    }
}

fn verify_snapshot(snapshot: &str, expected_muhash: &str) -> ExitCode {
    match utxosnapshot::verify_muhash(snapshot, expected_muhash) {
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

    match utxosnapshot::materialize_flat_utxo_set(snapshot, out_utxo_set, expected_muhash) {
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

fn usage(bin: &str) {
    eprintln!(
        "usage:\n  {bin} verify-snapshot <txoutset.dat> <expected-muhash-display-hex>\n  {bin} materialize-utxo-set <txoutset.dat> <expected-muhash-display-hex> <out-utxo_set.bin> <anchor-height> <out-chain_anchor.bin>\n  {bin} build-utxo-chunks <utxo_set.bin> <out-dir> [partitions]\n  {bin} build-onion-pack <utxo_set.bin> <out-dir> [entry-size]\n  {bin} build-onion-data-cuckoo <onion_packed_entries.bin> <out-dir> [entry-size] [--anchor <chain_anchor.bin>]\n  {bin} build-onion-index-cuckoo <onion_index.bin> <out-dir> [entry-size] [--anchor <chain_anchor.bin>]\n  {bin} build-onion-merkle <onion_index_bin_hashes.bin> <onion_data_bin_hashes.bin> <out-dir> [entry-size]\n  {bin} build-index-cuckoo <utxo_chunks_index_nodust.bin> <out-batch_pir_cuckoo.bin> [--anchor <chain_anchor.bin>]\n  {bin} build-chunk-cuckoo <utxo_chunks_nodust.bin> <out-chunk_pir_cuckoo.bin> [--anchor <chain_anchor.bin>]\n  {bin} build-bucket-merkle <batch_pir_cuckoo.bin> <chunk_pir_cuckoo.bin> <out-dir>\n  {bin} build-root-bundle-payload <out-dir> <network-magic-hex> <chain_anchor.bin> <muhash-display-hex> <index-bins-per-table> <chunk-bins-per-table> <onion-entry-size> <issued-at-unix> <out-payload.bin>\n  {bin} params-hash <index-bins-per-table> <chunk-bins-per-table> <onion-entry-size>"
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
    eprintln!("error: expected optional argument shape: --anchor <chain_anchor.bin>");
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
        None => dbpipeline::OnionMerkleOptions::default().entry_size,
    };
    let options = dbpipeline::OnionMerkleOptions { entry_size };
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
            eprintln!("error: expected optional argument shape: [entry-size] [--anchor <chain_anchor.bin>]");
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

fn build_bucket_merkle(index_cuckoo: &str, chunk_cuckoo: &str, out_dir: &str) -> ExitCode {
    match dbpipeline::build_bucket_merkle(index_cuckoo, chunk_cuckoo, out_dir) {
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
            let (anchor, seeds) = load_snapshot_seeds(path)?;
            print_anchor_seed_source(&anchor);
            println!("index_master_seed=0x{:016x}", seeds.index_master);
            println!("index_tag_seed=0x{:016x}", seeds.index_tag);
            Ok(dbpipeline::IndexCuckooOptions {
                master_seed: seeds.index_master,
                tag_seed: seeds.index_tag,
                snapshot_anchor: Some(anchor.to_bytes()),
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
            let (anchor, seeds) = load_snapshot_seeds(path)?;
            print_anchor_seed_source(&anchor);
            println!("chunk_master_seed=0x{:016x}", seeds.chunk_master);
            Ok(dbpipeline::ChunkCuckooOptions {
                master_seed: seeds.chunk_master,
                snapshot_anchor: Some(anchor.to_bytes()),
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
            let (anchor, seeds) = load_snapshot_seeds(path)?;
            print_anchor_seed_source(&anchor);
            println!("onion_data_master_seed=0x{:016x}", seeds.chunk_master);
            Ok(dbpipeline::OnionDataCuckooOptions {
                master_seed: seeds.chunk_master,
                snapshot_anchor: Some(anchor.to_bytes()),
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
            let (anchor, seeds) = load_snapshot_seeds(path)?;
            print_anchor_seed_source(&anchor);
            println!("onion_index_master_seed=0x{:016x}", seeds.index_master);
            println!("onion_index_tag_seed=0x{:016x}", seeds.index_tag);
            Ok(dbpipeline::OnionIndexCuckooOptions {
                master_seed: seeds.index_master,
                tag_seed: seeds.index_tag,
                snapshot_anchor: Some(anchor.to_bytes()),
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

fn load_snapshot_seeds(
    path: &str,
) -> Result<(rootbundle::ChainAnchor, rootbundle::SnapshotSeeds), String> {
    let anchor = rootbundle::ChainAnchor::load(path)
        .map_err(|e| format!("failed to read chain anchor {path}: {e}"))?;
    let seeds = rootbundle::SnapshotSeeds::derive(&anchor);
    Ok((anchor, seeds))
}

fn print_anchor_seed_source(anchor: &rootbundle::ChainAnchor) {
    println!("seed_source=chain_anchor");
    println!("anchor_height={}", anchor.height);
    println!("anchor_hash={}", display_hash_hex(&anchor.block_hash));
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
