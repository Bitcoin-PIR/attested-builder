use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 || args[1] != "verify-snapshot" {
        eprintln!(
            "usage: {} verify-snapshot <txoutset.dat> <expected-muhash-display-hex>",
            args[0]
        );
        return ExitCode::from(2);
    }

    match utxosnapshot::verify_muhash(&args[2], &args[3]) {
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
