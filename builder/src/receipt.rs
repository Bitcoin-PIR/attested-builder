use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use sha2::{Digest, Sha256};

fn sha256_file(path: &Path) -> Result<([u8; 32], u64), String> {
    let mut file =
        File::open(path).map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    let mut bytes = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        h.update(&buf[..n]);
    }
    Ok((h.finalize().into(), bytes))
}

fn display_hash_hex(internal: &[u8; 32]) -> String {
    let mut h = *internal;
    h.reverse();
    hex::encode(h)
}

fn build_kind_label(kind: rootbundle::BuildKind) -> &'static str {
    match kind {
        rootbundle::BuildKind::Snapshot => "snapshot",
        rootbundle::BuildKind::Delta => "delta",
    }
}

fn check_value(value: &str, key: &str) -> Result<(), String> {
    if value.bytes().any(|b| b == b'\n' || b == b'\r') {
        return Err(format!("{key} must not contain newlines"));
    }
    Ok(())
}

fn write_kv(writer: &mut dyn Write, key: &str, value: impl AsRef<str>) -> Result<(), String> {
    let value = value.as_ref();
    check_value(value, key)?;
    writeln!(writer, "{key}={value}").map_err(|e| format!("failed to write receipt: {e}"))
}

fn create_new_file(path: &Path) -> Result<File, String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create output directory {}: {e}",
                parent.display()
            )
        })?;
    }
    File::create_new(path).map_err(|e| format!("failed to create {}: {e}", path.display()))
}

fn write_build_receipt_file(
    bundle_path: &Path,
    snapshot_path: &Path,
    core_version: &str,
    out_receipt: &Path,
) -> Result<([u8; 32], usize), String> {
    check_value(core_version, "core_version")?;

    let bundle_bytes = fs::read(bundle_path)
        .map_err(|e| format!("failed to read bundle {}: {e}", bundle_path.display()))?;
    let bundle = rootbundle::SignedRootBundle::decode(&bundle_bytes)
        .map_err(|e| format!("failed to decode bundle {}: {e}", bundle_path.display()))?;
    let bundle_sha256: [u8; 32] = Sha256::digest(&bundle_bytes).into();
    let (snapshot_sha256, snapshot_bytes) = sha256_file(snapshot_path)?;

    let mut writer = create_new_file(out_receipt)?;
    writeln!(writer, "# BitcoinPIR attested-builder build receipt v1")
        .map_err(|e| format!("failed to write {}: {e}", out_receipt.display()))?;
    writeln!(
        writer,
        "# This receipt is an audit index. The signed root bundle is the trust artifact."
    )
    .map_err(|e| format!("failed to write {}: {e}", out_receipt.display()))?;

    let payload = &bundle.payload;
    write_kv(&mut writer, "receipt_version", "1")?;
    write_kv(&mut writer, "core_version", core_version)?;
    write_kv(
        &mut writer,
        "snapshot_path",
        snapshot_path.display().to_string(),
    )?;
    write_kv(&mut writer, "snapshot_bytes", snapshot_bytes.to_string())?;
    write_kv(&mut writer, "snapshot_sha256", hex::encode(snapshot_sha256))?;
    write_kv(
        &mut writer,
        "bundle_path",
        bundle_path.display().to_string(),
    )?;
    write_kv(&mut writer, "bundle_bytes", bundle_bytes.len().to_string())?;
    write_kv(&mut writer, "bundle_sha256", hex::encode(bundle_sha256))?;
    write_kv(
        &mut writer,
        "network_magic",
        hex::encode(payload.network_magic),
    )?;
    write_kv(
        &mut writer,
        "build_kind",
        build_kind_label(payload.build_kind),
    )?;
    write_kv(
        &mut writer,
        "from_anchor_height",
        payload.from_anchor.height.to_string(),
    )?;
    write_kv(
        &mut writer,
        "from_anchor_hash",
        display_hash_hex(&payload.from_anchor.block_hash),
    )?;
    write_kv(
        &mut writer,
        "anchor_height",
        payload.anchor.height.to_string(),
    )?;
    write_kv(
        &mut writer,
        "anchor_hash",
        display_hash_hex(&payload.anchor.block_hash),
    )?;
    write_kv(
        &mut writer,
        "muhash",
        display_hash_hex(&payload.utxo_muhash),
    )?;
    write_kv(
        &mut writer,
        "dust_threshold_sats",
        payload.dust_threshold_sats.to_string(),
    )?;
    write_kv(
        &mut writer,
        "max_utxos_per_spk",
        payload.max_utxos_per_spk.to_string(),
    )?;
    write_kv(&mut writer, "params_hash", hex::encode(payload.params_hash))?;
    write_kv(&mut writer, "issued_at", payload.issued_at.to_string())?;
    write_kv(
        &mut writer,
        "signature_count",
        bundle.signatures.len().to_string(),
    )?;
    for (i, sig) in bundle.signatures.iter().enumerate() {
        write_kv(
            &mut writer,
            &format!("signature.{i}.signer_pubkey"),
            hex::encode(sig.signer_pubkey),
        )?;
        write_kv(
            &mut writer,
            &format!("signature.{i}.signature"),
            hex::encode(sig.signature),
        )?;
    }
    write_kv(&mut writer, "root_count", payload.roots.len().to_string())?;
    for (i, root) in payload.roots.iter().enumerate() {
        write_kv(&mut writer, &format!("root.{i}.label"), &root.label)?;
        write_kv(
            &mut writer,
            &format!("root.{i}.hash"),
            hex::encode(root.root),
        )?;
    }
    write_kv(&mut writer, "attestation_evidence", "not_included")?;
    writer
        .flush()
        .map_err(|e| format!("failed to flush {}: {e}", out_receipt.display()))?;

    let receipt_bytes =
        fs::read(out_receipt).map_err(|e| format!("failed to read receipt for hash: {e}"))?;
    let receipt_sha256 = Sha256::digest(&receipt_bytes).into();
    Ok((receipt_sha256, receipt_bytes.len()))
}

pub fn write_build_receipt(
    bundle_path: &str,
    snapshot_path: &str,
    core_version: &str,
    out_receipt: &str,
) -> ExitCode {
    match write_build_receipt_file(
        Path::new(bundle_path),
        Path::new(snapshot_path),
        core_version,
        Path::new(out_receipt),
    ) {
        Ok((receipt_sha256, receipt_bytes)) => {
            println!("receipt_version=1");
            println!("receipt_bytes={receipt_bytes}");
            println!("receipt_sha256={}", hex::encode(receipt_sha256));
            println!("receipt_path={out_receipt}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use ed25519_dalek::SigningKey;

    fn unique_temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "pir-attested-builder-receipt-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_payload() -> rootbundle::RootBundlePayload {
        rootbundle::RootBundlePayload {
            network_magic: [0xfa, 0xbf, 0xb5, 0xda],
            build_kind: rootbundle::BuildKind::Snapshot,
            from_anchor: rootbundle::ChainAnchor {
                block_hash: [0; 32],
                height: 0,
            },
            anchor: rootbundle::ChainAnchor {
                block_hash: [0xab; 32],
                height: 111,
            },
            utxo_muhash: [0xcd; 32],
            dust_threshold_sats: dbpipeline::DUST_THRESHOLD_SATS,
            max_utxos_per_spk: dbpipeline::MAX_UTXOS_PER_SPK as u32,
            params_hash: rootbundle::BuildParamsV1::current_snapshot(8, 16, 3_328).params_hash(),
            issued_at: 1_800_000_000,
            roots: vec![
                rootbundle::NamedRoot {
                    label: "file-sha256/batch_pir_cuckoo.bin".into(),
                    root: [0x22; 32],
                },
                rootbundle::NamedRoot {
                    label: "merkle/bucket/super_root".into(),
                    root: [0x11; 32],
                },
            ],
        }
    }

    #[test]
    fn write_build_receipt_records_snapshot_and_bundle_metadata() {
        let dir = unique_temp_dir("ok");
        let snapshot = dir.join("txoutset.dat");
        let bundle = dir.join("bundle.bin");
        let receipt = dir.join("receipt.txt");
        fs::write(&snapshot, b"fake snapshot").unwrap();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let payload = test_payload();
        let signed = rootbundle::SignedRootBundle {
            payload: payload.clone(),
            signatures: vec![rootbundle::sign_root_bundle(&payload, &key).unwrap()],
        };
        fs::write(&bundle, signed.encode().unwrap()).unwrap();

        let (receipt_sha256, receipt_bytes) =
            write_build_receipt_file(&bundle, &snapshot, "Bitcoin Core v31.0.0", &receipt).unwrap();
        let text = fs::read_to_string(&receipt).unwrap();

        assert!(receipt_bytes > 0);
        assert_eq!(
            receipt_sha256,
            <[u8; 32]>::from(Sha256::digest(fs::read(&receipt).unwrap()))
        );
        assert!(text.contains("receipt_version=1\n"));
        assert!(text.contains("core_version=Bitcoin Core v31.0.0\n"));
        assert!(text.contains("snapshot_bytes=13\n"));
        assert!(text.contains("anchor_height=111\n"));
        assert!(text.contains("build_kind=snapshot\n"));
        assert!(text.contains("signature_count=1\n"));
        assert!(text.contains("root.0.label=file-sha256/batch_pir_cuckoo.bin\n"));
        assert!(text.contains("attestation_evidence=not_included\n"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_build_receipt_rejects_newlines_in_core_version() {
        let dir = unique_temp_dir("bad-version");
        let snapshot = dir.join("txoutset.dat");
        let bundle = dir.join("bundle.bin");
        let receipt = dir.join("receipt.txt");
        fs::write(&snapshot, b"fake snapshot").unwrap();
        fs::write(
            &bundle,
            rootbundle::SignedRootBundle {
                payload: test_payload(),
                signatures: Vec::new(),
            }
            .encode()
            .unwrap(),
        )
        .unwrap();

        let err = write_build_receipt_file(&bundle, &snapshot, "bad\nversion", &receipt)
            .expect_err("newlines should be rejected");
        assert!(err.contains("core_version"));

        fs::remove_dir_all(dir).unwrap();
    }
}
