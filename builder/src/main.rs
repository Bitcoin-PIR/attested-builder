use std::env;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("verify-snapshot") if args.len() == 4 => verify_snapshot(&args[2], &args[3]),
        Some("materialize-utxo-set") if args.len() == 7 => {
            materialize_utxo_set(&args[2], &args[3], &args[4], &args[5], &args[6])
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
        "usage:\n  {bin} verify-snapshot <txoutset.dat> <expected-muhash-display-hex>\n  {bin} materialize-utxo-set <txoutset.dat> <expected-muhash-display-hex> <out-utxo_set.bin> <anchor-height> <out-chain_anchor.bin>"
    );
}
