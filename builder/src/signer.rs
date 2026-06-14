use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

pub trait BundleSigner {
    fn sign_root_bundle(
        &self,
        payload: &rootbundle::RootBundlePayload,
    ) -> Result<rootbundle::BundleSignature, String>;
}

pub struct LocalFileSigner {
    signing_key: SigningKey,
}

impl LocalFileSigner {
    fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    fn load(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path)
            .map_err(|e| format!("failed to read builder key {}: {e}", path.display()))?;
        Ok(Self::from_seed(parse_seed_file(&bytes, path)?))
    }

    fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl BundleSigner for LocalFileSigner {
    fn sign_root_bundle(
        &self,
        payload: &rootbundle::RootBundlePayload,
    ) -> Result<rootbundle::BundleSignature, String> {
        rootbundle::sign_root_bundle(payload, &self.signing_key)
            .map_err(|e| format!("failed to sign root bundle: {e}"))
    }
}

fn parse_seed_file(bytes: &[u8], path: &Path) -> Result<[u8; 32], String> {
    if bytes.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        return Ok(seed);
    }

    let text = std::str::from_utf8(bytes).map_err(|_| {
        format!(
            "builder key {} must be raw 32 bytes or UTF-8 key metadata",
            path.display()
        )
    })?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(hex) = line
            .strip_prefix("secret_seed_hex=")
            .or_else(|| line.strip_prefix("seed_hex="))
            .or_else(|| line.strip_prefix("secret_key_hex="))
        {
            return parse_hex_seed(hex.trim(), path);
        }
        if line.len() == 64 && line.bytes().all(|b| b.is_ascii_hexdigit()) {
            return parse_hex_seed(line, path);
        }
    }
    Err(format!(
        "builder key {} did not contain secret_seed_hex=<64 hex chars>",
        path.display()
    ))
}

fn parse_hex_seed(hex_seed: &str, path: &Path) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_seed.trim_start_matches("0x"))
        .map_err(|e| format!("bad hex seed in {}: {e}", path.display()))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "seed in {} must be 32 bytes, got {}",
            path.display(),
            bytes.len()
        )
    })
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

fn create_new_secret_file(path: &Path) -> Result<File, String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create output directory {}: {e}",
                parent.display()
            )
        })?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .map_err(|e| format!("failed to create {}: {e}", path.display()))
}

fn write_local_key_file(path: &Path, seed: [u8; 32]) -> Result<LocalFileSigner, String> {
    let signer = LocalFileSigner::from_seed(seed);
    let mut writer = create_new_secret_file(path)?;
    writeln!(
        writer,
        "# BitcoinPIR attested-builder local Ed25519 seed v1"
    )
    .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    writeln!(writer, "secret_seed_hex={}", hex::encode(seed))
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    writeln!(
        writer,
        "public_key_hex={}",
        hex::encode(signer.public_key())
    )
    .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    writer
        .flush()
        .map_err(|e| format!("failed to flush {}: {e}", path.display()))?;
    Ok(signer)
}

pub fn generate_builder_key(out_key_file: &str) -> ExitCode {
    let mut seed = [0u8; 32];
    if let Err(e) = getrandom::getrandom(&mut seed) {
        eprintln!("error: failed to read OS randomness: {e}");
        return ExitCode::from(1);
    }

    match write_local_key_file(Path::new(out_key_file), seed) {
        Ok(signer) => {
            println!("key_kind=local-ed25519-seed-v1");
            println!("public_key={}", hex::encode(signer.public_key()));
            println!("key_path={out_key_file}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

struct SignBundleReport {
    signer_pubkey: [u8; 32],
    signature: [u8; 64],
    payload_roots: usize,
    bundle_bytes: usize,
    bundle_sha256: [u8; 32],
}

fn sign_root_bundle_files(
    payload_path: &Path,
    key_path: &Path,
    out_bundle_path: &Path,
) -> Result<SignBundleReport, String> {
    let payload_bytes = fs::read(payload_path)
        .map_err(|e| format!("failed to read payload {}: {e}", payload_path.display()))?;
    let payload = rootbundle::RootBundlePayload::decode(&payload_bytes)
        .map_err(|e| format!("failed to decode payload {}: {e}", payload_path.display()))?;
    let signer = LocalFileSigner::load(key_path)?;
    let signature = signer.sign_root_bundle(&payload)?;
    let bundle = rootbundle::SignedRootBundle {
        payload,
        signatures: vec![signature.clone()],
    };
    let bytes = bundle
        .encode()
        .map_err(|e| format!("failed to encode signed bundle: {e}"))?;
    let bundle_sha256 = Sha256::digest(&bytes).into();
    let mut writer = create_new_file(out_bundle_path)?;
    writer
        .write_all(&bytes)
        .map_err(|e| format!("failed to write {}: {e}", out_bundle_path.display()))?;
    writer
        .flush()
        .map_err(|e| format!("failed to flush {}: {e}", out_bundle_path.display()))?;
    Ok(SignBundleReport {
        signer_pubkey: signature.signer_pubkey,
        signature: signature.signature,
        payload_roots: bundle.payload.roots.len(),
        bundle_bytes: bytes.len(),
        bundle_sha256,
    })
}

pub fn sign_root_bundle(payload: &str, key_file: &str, out_bundle: &str) -> ExitCode {
    match sign_root_bundle_files(
        Path::new(payload),
        Path::new(key_file),
        Path::new(out_bundle),
    ) {
        Ok(report) => {
            println!("signer_kind=local-file");
            println!("signer_pubkey={}", hex::encode(report.signer_pubkey));
            println!("signature={}", hex::encode(report.signature));
            println!("payload_roots={}", report.payload_roots);
            println!("bundle_bytes={}", report.bundle_bytes);
            println!("bundle_sha256={}", hex::encode(report.bundle_sha256));
            println!("bundle_path={out_bundle}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug)]
struct VerifyBundleReport {
    bundle: rootbundle::SignedRootBundle,
    valid_signatures: usize,
    threshold: usize,
    trusted_keys: usize,
    bundle_bytes: usize,
    bundle_sha256: [u8; 32],
}

fn parse_pubkey_hex(hex_key: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_key.trim_start_matches("0x"))
        .map_err(|e| format!("{label} must be 32-byte hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{label} must be 32 bytes, got {}", bytes.len()))
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

fn verify_root_bundle_file(
    bundle_path: &Path,
    threshold: usize,
    trusted_pubkeys: &[[u8; 32]],
) -> Result<VerifyBundleReport, String> {
    if threshold == 0 {
        return Err("threshold must be >= 1".to_owned());
    }
    if trusted_pubkeys.is_empty() {
        return Err("at least one trusted pubkey is required".to_owned());
    }
    if threshold > trusted_pubkeys.len() {
        return Err(format!(
            "threshold {threshold} exceeds trusted key count {}",
            trusted_pubkeys.len()
        ));
    }

    let bytes = fs::read(bundle_path)
        .map_err(|e| format!("failed to read bundle {}: {e}", bundle_path.display()))?;
    let bundle = rootbundle::SignedRootBundle::decode(&bytes)
        .map_err(|e| format!("failed to decode bundle {}: {e}", bundle_path.display()))?;
    let valid_signatures = bundle
        .verify_quorum(trusted_pubkeys, threshold)
        .map_err(|e| format!("bundle quorum verification failed: {e}"))?;
    Ok(VerifyBundleReport {
        bundle,
        valid_signatures,
        threshold,
        trusted_keys: trusted_pubkeys.len(),
        bundle_bytes: bytes.len(),
        bundle_sha256: Sha256::digest(&bytes).into(),
    })
}

pub fn verify_root_bundle(
    bundle_path: &str,
    threshold: &str,
    trusted_pubkeys: &[String],
) -> ExitCode {
    let threshold = match threshold.parse::<usize>() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("error: threshold must be a positive integer: {threshold}");
            return ExitCode::from(2);
        }
    };

    let trusted = match trusted_pubkeys
        .iter()
        .enumerate()
        .map(|(i, key)| parse_pubkey_hex(key, &format!("trusted-pubkey-hex[{}]", i + 1)))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    match verify_root_bundle_file(Path::new(bundle_path), threshold, &trusted) {
        Ok(report) => {
            let payload = &report.bundle.payload;
            println!("status=ok");
            println!("valid_signatures={}", report.valid_signatures);
            println!("threshold={}", report.threshold);
            println!("trusted_keys={}", report.trusted_keys);
            println!("bundle_signatures={}", report.bundle.signatures.len());
            for sig in &report.bundle.signatures {
                println!("signer_pubkey={}", hex::encode(sig.signer_pubkey));
            }
            println!("network_magic={}", hex::encode(payload.network_magic));
            println!("build_kind={}", build_kind_label(payload.build_kind));
            println!("from_anchor_height={}", payload.from_anchor.height);
            println!(
                "from_anchor_hash={}",
                display_hash_hex(&payload.from_anchor.block_hash)
            );
            println!("anchor_height={}", payload.anchor.height);
            println!(
                "anchor_hash={}",
                display_hash_hex(&payload.anchor.block_hash)
            );
            println!("muhash={}", display_hash_hex(&payload.utxo_muhash));
            println!("dust_threshold_sats={}", payload.dust_threshold_sats);
            println!("max_utxos_per_spk={}", payload.max_utxos_per_spk);
            println!("params_hash={}", hex::encode(payload.params_hash));
            println!("issued_at={}", payload.issued_at);
            println!("root_entries={}", payload.roots.len());
            for root in &payload.roots {
                println!("root:{}={}", root.label, hex::encode(root.root));
            }
            println!("bundle_bytes={}", report.bundle_bytes);
            println!("bundle_sha256={}", hex::encode(report.bundle_sha256));
            println!("bundle_path={bundle_path}");
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

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "pir-attested-builder-signer-{name}-{}-{}",
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
                height: 123,
            },
            utxo_muhash: [0xcd; 32],
            dust_threshold_sats: dbpipeline::DUST_THRESHOLD_SATS,
            max_utxos_per_spk: dbpipeline::MAX_UTXOS_PER_SPK as u32,
            params_hash: rootbundle::BuildParamsV1::current_snapshot(8, 16, 3_328).params_hash(),
            issued_at: 1_800_000_000,
            roots: vec![rootbundle::NamedRoot {
                label: "merkle/onion/super_root".into(),
                root: [0x11; 32],
            }],
        }
    }

    #[test]
    fn local_seed_file_signs_bundle() {
        let dir = unique_temp_dir("bundle");
        let key = dir.join("builder.key");
        let payload = dir.join("payload.bin");
        let bundle = dir.join("bundle.bin");
        let signer = write_local_key_file(&key, [7u8; 32]).unwrap();
        fs::write(&payload, test_payload().encode().unwrap()).unwrap();

        let report = sign_root_bundle_files(&payload, &key, &bundle).unwrap();
        let decoded = rootbundle::SignedRootBundle::decode(&fs::read(&bundle).unwrap()).unwrap();

        assert_eq!(report.signer_pubkey, signer.public_key());
        assert_eq!(decoded.signatures.len(), 1);
        assert_eq!(decoded.verify_quorum(&[signer.public_key()], 1), Ok(1));
        assert!(report.bundle_bytes > 0);
        let expected_bundle_sha256: [u8; 32] = Sha256::digest(fs::read(&bundle).unwrap()).into();
        assert_eq!(report.bundle_sha256, expected_bundle_sha256);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verify_root_bundle_file_enforces_threshold_and_trusted_keys() {
        let dir = unique_temp_dir("verify-bundle");
        let key1 = dir.join("builder1.key");
        let key2 = dir.join("builder2.key");
        let payload = dir.join("payload.bin");
        let bundle1 = dir.join("bundle1.bin");
        let signer1 = write_local_key_file(&key1, [7u8; 32]).unwrap();
        let signer2 = write_local_key_file(&key2, [8u8; 32]).unwrap();
        fs::write(&payload, test_payload().encode().unwrap()).unwrap();
        sign_root_bundle_files(&payload, &key1, &bundle1).unwrap();

        let trusted = [signer1.public_key(), signer2.public_key()];
        let report = verify_root_bundle_file(&bundle1, 1, &trusted).unwrap();
        assert_eq!(report.valid_signatures, 1);
        assert_eq!(report.threshold, 1);
        assert_eq!(report.trusted_keys, 2);

        let err = verify_root_bundle_file(&bundle1, 2, &trusted).unwrap_err();
        assert!(err.contains("quorum not met"));

        let err = verify_root_bundle_file(&bundle1, 1, &[signer2.public_key()]).unwrap_err();
        assert!(err.contains("quorum not met"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn key_file_parser_accepts_plain_hex_seed() {
        let dir = unique_temp_dir("hex-key");
        let key = dir.join("builder.key");
        fs::write(&key, hex::encode([9u8; 32])).unwrap();
        let signer = LocalFileSigner::load(&key).unwrap();
        assert_eq!(
            signer.public_key(),
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
