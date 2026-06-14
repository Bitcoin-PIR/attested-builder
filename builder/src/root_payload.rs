use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use sha2::{Digest, Sha256};

fn display_hash_hex(internal: &[u8; 32]) -> String {
    let mut h = *internal;
    h.reverse();
    hex::encode(h)
}

fn parse_hex_array<const N: usize>(s: &str, name: &str) -> Result<[u8; N], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| format!("{name} must be hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{name} must be {N} bytes, got {}", bytes.len()))
}

fn parse_muhash_display_hex(s: &str) -> Result<[u8; 32], String> {
    let mut bytes = parse_hex_array::<32>(s, "muhash-display-hex")?;
    bytes.reverse();
    Ok(bytes)
}

fn parse_u32_arg(s: &str, name: &str) -> Result<u32, String> {
    s.parse::<u32>()
        .map_err(|_| format!("{name} must be a u32: {s}"))
}

fn parse_i64_arg(s: &str, name: &str) -> Result<i64, String> {
    s.parse::<i64>()
        .map_err(|_| format!("{name} must be an i64: {s}"))
}

fn read_32_byte_file(path: &Path, label: &str) -> Result<[u8; 32], String> {
    let bytes =
        fs::read(path).map_err(|e| format!("failed to read {label} {}: {e}", path.display()))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "{label} {} must be 32 bytes, got {}",
            path.display(),
            bytes.len()
        )
    })
}

fn sha256_file(path: &Path) -> Result<[u8; 32], String> {
    let mut file =
        File::open(path).map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

fn known_pipeline_output_filenames() -> &'static [&'static str] {
    &[
        dbpipeline::UTXO_CHUNKS_FILENAME,
        dbpipeline::UTXO_CHUNKS_INDEX_FILENAME,
        dbpipeline::TOP100_FILENAME,
        dbpipeline::WHALES_FILENAME,
        dbpipeline::INDEX_CUCKOO_FILENAME,
        dbpipeline::CHUNK_CUCKOO_FILENAME,
        dbpipeline::MERKLE_BUCKET_TREE_TOPS_FILENAME,
        dbpipeline::MERKLE_BUCKET_ROOTS_FILENAME,
        dbpipeline::MERKLE_BUCKET_ROOT_FILENAME,
        dbpipeline::ONION_PACKED_ENTRIES_FILENAME,
        dbpipeline::ONION_INDEX_FILENAME,
        dbpipeline::ONION_CHUNK_CUCKOO_FILENAME,
        dbpipeline::ONION_DATA_BIN_HASHES_FILENAME,
        dbpipeline::ONION_INDEX_BINS_FILENAME,
        dbpipeline::ONION_INDEX_META_FILENAME,
        dbpipeline::ONION_INDEX_BIN_HASHES_FILENAME,
        dbpipeline::ONION_MERKLE_TREE_TOPS_FILENAME,
        dbpipeline::ONION_MERKLE_ROOTS_FILENAME,
        dbpipeline::ONION_MERKLE_ROOT_FILENAME,
        dbpipeline::ONION_MERKLE_SIB_ROWS_INDEX_FILENAME,
        dbpipeline::ONION_MERKLE_SIB_ROWS_DATA_FILENAME,
        "onion_shared_ntt.bin",
        "onion_index_all.bin",
        "merkle_onion_sib_index.bin",
        "merkle_onion_sib_data.bin",
    ]
}

fn add_super_root_if_present(
    roots: &mut Vec<rootbundle::NamedRoot>,
    out_dir: &Path,
    filename: &str,
    label: &str,
) -> Result<bool, String> {
    let path = out_dir.join(filename);
    if !path.exists() {
        return Ok(false);
    }
    if !path.is_file() {
        return Err(format!(
            "expected regular file for {label}: {}",
            path.display()
        ));
    }
    roots.push(rootbundle::NamedRoot {
        label: label.to_owned(),
        root: read_32_byte_file(&path, label)?,
    });
    Ok(true)
}

fn collect_payload_roots(out_dir: &Path) -> Result<Vec<rootbundle::NamedRoot>, String> {
    if !out_dir.is_dir() {
        return Err(format!(
            "output directory does not exist: {}",
            out_dir.display()
        ));
    }

    let mut roots = Vec::new();
    let mut super_roots = 0usize;
    if add_super_root_if_present(
        &mut roots,
        out_dir,
        dbpipeline::MERKLE_BUCKET_ROOT_FILENAME,
        "merkle/bucket/super_root",
    )? {
        super_roots += 1;
    }
    if add_super_root_if_present(
        &mut roots,
        out_dir,
        dbpipeline::ONION_MERKLE_ROOT_FILENAME,
        "merkle/onion/super_root",
    )? {
        super_roots += 1;
    }
    if super_roots == 0 {
        return Err(format!(
            "missing {} or {} in {}",
            dbpipeline::MERKLE_BUCKET_ROOT_FILENAME,
            dbpipeline::ONION_MERKLE_ROOT_FILENAME,
            out_dir.display()
        ));
    }

    for filename in known_pipeline_output_filenames() {
        let path = out_dir.join(filename);
        if !path.exists() {
            continue;
        }
        if !path.is_file() {
            return Err(format!("expected regular file: {}", path.display()));
        }
        roots.push(rootbundle::NamedRoot {
            label: format!("file-sha256/{filename}"),
            root: sha256_file(&path)?,
        });
    }

    roots.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(roots)
}

fn root_bundle_payload_from_dir(
    out_dir: &Path,
    network_magic: [u8; 4],
    chain_anchor: rootbundle::ChainAnchor,
    muhash_display_hex: &str,
    index_bins_per_table: u32,
    chunk_bins_per_table: u32,
    onion_entry_size: u32,
    issued_at: i64,
) -> Result<rootbundle::RootBundlePayload, String> {
    let params = rootbundle::BuildParamsV1::current_snapshot(
        index_bins_per_table,
        chunk_bins_per_table,
        onion_entry_size,
    );
    Ok(rootbundle::RootBundlePayload {
        network_magic,
        build_kind: rootbundle::BuildKind::Snapshot,
        from_anchor: rootbundle::ChainAnchor {
            block_hash: [0u8; 32],
            height: 0,
        },
        anchor: chain_anchor,
        utxo_muhash: parse_muhash_display_hex(muhash_display_hex)?,
        dust_threshold_sats: dbpipeline::DUST_THRESHOLD_SATS,
        max_utxos_per_spk: dbpipeline::MAX_UTXOS_PER_SPK as u32,
        params_hash: params.params_hash(),
        issued_at,
        roots: collect_payload_roots(out_dir)?,
    })
}

fn write_payload_file(
    payload: &rootbundle::RootBundlePayload,
    path: &Path,
) -> Result<(usize, [u8; 32]), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create output directory {}: {e}",
                parent.display()
            )
        })?;
    }
    let bytes = payload
        .encode()
        .map_err(|e| format!("failed to encode payload: {e}"))?;
    let sha256 = Sha256::digest(&bytes).into();
    let mut writer =
        File::create_new(path).map_err(|e| format!("failed to create {}: {e}", path.display()))?;
    writer
        .write_all(&bytes)
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    writer
        .flush()
        .map_err(|e| format!("failed to flush {}: {e}", path.display()))?;
    Ok((bytes.len(), sha256))
}

pub fn build_root_bundle_payload(
    out_dir: &str,
    network_magic_hex: &str,
    chain_anchor_path: &str,
    muhash_display_hex: &str,
    index_bins_per_table: &str,
    chunk_bins_per_table: &str,
    onion_entry_size: &str,
    issued_at: &str,
    out_payload: &str,
) -> ExitCode {
    let result = (|| {
        let network_magic = parse_hex_array::<4>(network_magic_hex, "network-magic-hex")?;
        let chain_anchor = rootbundle::ChainAnchor::load(chain_anchor_path)
            .map_err(|e| format!("failed to read chain anchor {chain_anchor_path}: {e}"))?;
        let index_bins_per_table = parse_u32_arg(index_bins_per_table, "index-bins-per-table")?;
        let chunk_bins_per_table = parse_u32_arg(chunk_bins_per_table, "chunk-bins-per-table")?;
        let onion_entry_size = parse_u32_arg(onion_entry_size, "onion-entry-size")?;
        let issued_at = parse_i64_arg(issued_at, "issued-at-unix")?;
        let payload = root_bundle_payload_from_dir(
            Path::new(out_dir),
            network_magic,
            chain_anchor,
            muhash_display_hex,
            index_bins_per_table,
            chunk_bins_per_table,
            onion_entry_size,
            issued_at,
        )?;
        let (payload_bytes, payload_sha256) = write_payload_file(&payload, Path::new(out_payload))?;
        Ok::<_, String>((payload, payload_bytes, payload_sha256))
    })();

    match result {
        Ok((payload, payload_bytes, payload_sha256)) => {
            println!("network_magic={}", hex::encode(payload.network_magic));
            println!("anchor_height={}", payload.anchor.height);
            println!(
                "anchor_hash={}",
                display_hash_hex(&payload.anchor.block_hash)
            );
            println!("muhash={muhash_display_hex}");
            println!("params_hash={}", hex::encode(payload.params_hash));
            println!("root_entries={}", payload.roots.len());
            for root in &payload.roots {
                println!("root:{}={}", root.label, hex::encode(root.root));
            }
            println!("payload_bytes={payload_bytes}");
            println!("payload_sha256={}", hex::encode(payload_sha256));
            println!("payload_path={out_payload}");
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
    use std::{env, fs};

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        let mut dir = env::temp_dir();
        dir.push(format!(
            "pir-attested-builder-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn build_root_bundle_payload_collects_roots_and_file_hashes() {
        let dir = unique_temp_dir("root-bundle-payload");
        let chain_anchor = dir.join("chain_anchor.bin");
        let out_payload = dir.join("root_bundle_payload.bin");
        let bucket_root = [0x22u8; 32];
        let onion_root = [0x33u8; 32];
        fs::write(
            dir.join(dbpipeline::MERKLE_BUCKET_ROOT_FILENAME),
            bucket_root,
        )
        .unwrap();
        fs::write(dir.join(dbpipeline::ONION_MERKLE_ROOT_FILENAME), onion_root).unwrap();
        fs::write(dir.join("onion_shared_ntt.bin"), [1u8, 2, 3, 4]).unwrap();
        let mut anchor_bytes = [0u8; rootbundle::CHAIN_ANCHOR_BYTES];
        anchor_bytes[..32].copy_from_slice(&[0xabu8; 32]);
        anchor_bytes[32..].copy_from_slice(&123u32.to_le_bytes());
        fs::write(&chain_anchor, anchor_bytes).unwrap();

        let display_muhash = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let payload = root_bundle_payload_from_dir(
            &dir,
            [0xfa, 0xbf, 0xb5, 0xda],
            rootbundle::ChainAnchor::load(&chain_anchor).unwrap(),
            display_muhash,
            8,
            16,
            dbpipeline::DEFAULT_ONION_ENTRY_SIZE as u32,
            1_800_000_000,
        )
        .unwrap();
        let (payload_bytes, payload_sha256) = write_payload_file(&payload, &out_payload).unwrap();
        let decoded =
            rootbundle::RootBundlePayload::decode(&fs::read(&out_payload).unwrap()).unwrap();

        assert_eq!(decoded, payload);
        assert_eq!(payload.anchor.height, 123);
        assert_eq!(payload.network_magic, [0xfa, 0xbf, 0xb5, 0xda]);
        assert_eq!(payload.utxo_muhash[0], 0x1f);
        assert_eq!(payload.utxo_muhash[31], 0x00);
        assert_eq!(payload.root("merkle/bucket/super_root"), Some(&bucket_root));
        assert_eq!(payload.root("merkle/onion/super_root"), Some(&onion_root));
        assert_eq!(
            payload.root("file-sha256/onion_shared_ntt.bin"),
            Some(&Sha256::digest([1u8, 2, 3, 4]).into())
        );
        assert!(payload_bytes > 0);
        let expected_payload_sha256: [u8; 32] =
            Sha256::digest(fs::read(out_payload).unwrap()).into();
        assert_eq!(payload_sha256, expected_payload_sha256);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn build_root_bundle_payload_requires_a_super_root() {
        let dir = unique_temp_dir("root-bundle-no-root");
        fs::write(dir.join("onion_shared_ntt.bin"), [1u8]).unwrap();
        let err = collect_payload_roots(&dir).expect_err("missing super root should fail");
        assert!(err.contains(dbpipeline::MERKLE_BUCKET_ROOT_FILENAME));
        fs::remove_dir_all(dir).unwrap();
    }
}
