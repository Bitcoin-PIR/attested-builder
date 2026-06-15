use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::ExitCode;

use sha2::{Digest, Sha256};

const EVIDENCE_DOMAIN: &[u8] = b"BitcoinPIR/attested-builder/build-evidence/v1\0";
const REPORT_DATA_DOMAIN: &[u8] = b"BitcoinPIR/attested-builder/build-evidence/report-data/v1\0";
const EVIDENCE_VERSION: u16 = 1;
const MAX_STRING_LEN: usize = 4096;
const MAX_MEASUREMENT_LEN: usize = 4096;
const SEV_SNP_REPORT_DATA_OFFSET: usize = 0x50;
const SEV_SNP_REPORT_DATA_LEN: usize = 64;
const SEV_SNP_REPORT_LEN: usize = 1184;

#[derive(Clone, Debug, PartialEq, Eq)]
struct BuildEvidence {
    builder_git_commit: String,
    builder_binary_sha256: [u8; 32],
    tee_platform: String,
    tee_image_measurement: Vec<u8>,
    core_version: String,
    snapshot_sha256: [u8; 32],
    snapshot_bytes: u64,
    network_magic: [u8; 4],
    build_kind: rootbundle::BuildKind,
    from_anchor: rootbundle::ChainAnchor,
    anchor: rootbundle::ChainAnchor,
    utxo_muhash: [u8; 32],
    dust_threshold_sats: u64,
    max_utxos_per_spk: u32,
    params_hash: [u8; 32],
    index_bins_per_table: u32,
    chunk_bins_per_table: u32,
    onion_entry_size: u32,
    bucket_super_root: [u8; 32],
    onion_super_root: [u8; 32],
    root_bundle_payload_sha256: [u8; 32],
    signed_root_bundle_sha256: Option<[u8; 32]>,
    database_manifest_sha256: [u8; 32],
    all_artifacts_manifest_sha256: [u8; 32],
    server_db_manifest_sha256: [u8; 32],
}

impl BuildEvidence {
    fn encode(&self) -> Result<Vec<u8>, String> {
        validate_metadata_string("builder_git_commit", &self.builder_git_commit)?;
        validate_metadata_string("tee_platform", &self.tee_platform)?;
        validate_metadata_string("core_version", &self.core_version)?;
        if self.tee_image_measurement.len() > MAX_MEASUREMENT_LEN {
            return Err(format!(
                "tee_image_measurement too large: {} bytes",
                self.tee_image_measurement.len()
            ));
        }

        let mut out = Vec::with_capacity(512 + self.tee_image_measurement.len());
        put_u16(&mut out, EVIDENCE_VERSION);
        put_string(&mut out, &self.builder_git_commit)?;
        put_arr(&mut out, &self.builder_binary_sha256);
        put_string(&mut out, &self.tee_platform)?;
        put_bytes_with_u16_len(&mut out, &self.tee_image_measurement)?;
        put_string(&mut out, &self.core_version)?;
        put_arr(&mut out, &self.snapshot_sha256);
        put_u64(&mut out, self.snapshot_bytes);
        put_arr(&mut out, &self.network_magic);
        out.push(build_kind_to_byte(self.build_kind));
        put_anchor(&mut out, self.from_anchor);
        put_anchor(&mut out, self.anchor);
        put_arr(&mut out, &self.utxo_muhash);
        put_u64(&mut out, self.dust_threshold_sats);
        put_u32(&mut out, self.max_utxos_per_spk);
        put_arr(&mut out, &self.params_hash);
        put_u32(&mut out, self.index_bins_per_table);
        put_u32(&mut out, self.chunk_bins_per_table);
        put_u32(&mut out, self.onion_entry_size);
        put_arr(&mut out, &self.bucket_super_root);
        put_arr(&mut out, &self.onion_super_root);
        put_arr(&mut out, &self.root_bundle_payload_sha256);
        match self.signed_root_bundle_sha256 {
            Some(h) => {
                out.push(1);
                put_arr(&mut out, &h);
            }
            None => out.push(0),
        }
        put_arr(&mut out, &self.database_manifest_sha256);
        put_arr(&mut out, &self.all_artifacts_manifest_sha256);
        put_arr(&mut out, &self.server_db_manifest_sha256);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let cur = &mut &bytes[..];
        let version = take_u16(cur, "version")?;
        if version != EVIDENCE_VERSION {
            return Err(format!("unsupported evidence version: {version}"));
        }
        let builder_git_commit = take_string(cur, "builder_git_commit")?;
        let builder_binary_sha256 = take_arr::<32>(cur, "builder_binary_sha256")?;
        let tee_platform = take_string(cur, "tee_platform")?;
        let tee_image_measurement = take_bytes_with_u16_len(cur, "tee_image_measurement")?;
        let core_version = take_string(cur, "core_version")?;
        let snapshot_sha256 = take_arr::<32>(cur, "snapshot_sha256")?;
        let snapshot_bytes = take_u64(cur, "snapshot_bytes")?;
        let network_magic = take_arr::<4>(cur, "network_magic")?;
        let build_kind = byte_to_build_kind(take_u8(cur, "build_kind")?)?;
        let from_anchor = take_anchor(cur, "from_anchor")?;
        let anchor = take_anchor(cur, "anchor")?;
        let utxo_muhash = take_arr::<32>(cur, "utxo_muhash")?;
        let dust_threshold_sats = take_u64(cur, "dust_threshold_sats")?;
        let max_utxos_per_spk = take_u32(cur, "max_utxos_per_spk")?;
        let params_hash = take_arr::<32>(cur, "params_hash")?;
        let index_bins_per_table = take_u32(cur, "index_bins_per_table")?;
        let chunk_bins_per_table = take_u32(cur, "chunk_bins_per_table")?;
        let onion_entry_size = take_u32(cur, "onion_entry_size")?;
        let bucket_super_root = take_arr::<32>(cur, "bucket_super_root")?;
        let onion_super_root = take_arr::<32>(cur, "onion_super_root")?;
        let root_bundle_payload_sha256 = take_arr::<32>(cur, "root_bundle_payload_sha256")?;
        let signed_root_bundle_sha256 = match take_u8(cur, "has_signed_root_bundle")? {
            0 => None,
            1 => Some(take_arr::<32>(cur, "signed_root_bundle_sha256")?),
            _ => return Err("bad signed root bundle option tag".into()),
        };
        let database_manifest_sha256 = take_arr::<32>(cur, "database_manifest_sha256")?;
        let all_artifacts_manifest_sha256 = take_arr::<32>(cur, "all_artifacts_manifest_sha256")?;
        let server_db_manifest_sha256 = take_arr::<32>(cur, "server_db_manifest_sha256")?;
        if !cur.is_empty() {
            return Err("trailing bytes in build evidence".into());
        }
        let evidence = Self {
            builder_git_commit,
            builder_binary_sha256,
            tee_platform,
            tee_image_measurement,
            core_version,
            snapshot_sha256,
            snapshot_bytes,
            network_magic,
            build_kind,
            from_anchor,
            anchor,
            utxo_muhash,
            dust_threshold_sats,
            max_utxos_per_spk,
            params_hash,
            index_bins_per_table,
            chunk_bins_per_table,
            onion_entry_size,
            bucket_super_root,
            onion_super_root,
            root_bundle_payload_sha256,
            signed_root_bundle_sha256,
            database_manifest_sha256,
            all_artifacts_manifest_sha256,
            server_db_manifest_sha256,
        };
        validate_metadata_string("builder_git_commit", &evidence.builder_git_commit)?;
        validate_metadata_string("tee_platform", &evidence.tee_platform)?;
        validate_metadata_string("core_version", &evidence.core_version)?;
        if evidence.tee_image_measurement.len() > MAX_MEASUREMENT_LEN {
            return Err("tee_image_measurement too large".into());
        }
        Ok(evidence)
    }

    fn evidence_digest(&self) -> Result<[u8; 32], String> {
        evidence_digest(&self.encode()?)
    }

    fn evidence_file_sha256(&self) -> Result<[u8; 32], String> {
        Ok(sha256_bytes(&self.encode()?))
    }

    fn report_data(&self) -> Result<[u8; 64], String> {
        report_data_for_evidence_bytes(&self.encode()?)
    }
}

pub fn write_build_evidence(
    out_dir: &str,
    snapshot: &str,
    core_version: &str,
    builder_git_commit: &str,
    builder_binary: &str,
    tee_platform: &str,
    tee_image_measurement_hex_or_none: &str,
    out_evidence: &str,
) -> ExitCode {
    let result = (|| {
        let out_dir = Path::new(out_dir);
        let snapshot = Path::new(snapshot);
        let builder_binary = Path::new(builder_binary);
        let out_evidence = Path::new(out_evidence);
        let payload_path = out_dir.join("root-bundle-payload.bin");
        let payload_bytes = fs::read(&payload_path)
            .map_err(|e| format!("failed to read {}: {e}", payload_path.display()))?;
        let payload = rootbundle::RootBundlePayload::decode(&payload_bytes)
            .map_err(|e| format!("failed to decode {}: {e}", payload_path.display()))?;
        let (snapshot_sha256, snapshot_bytes) = sha256_file(snapshot)?;
        let (builder_binary_sha256, _) = sha256_file(builder_binary)?;
        let root_bundle_payload_sha256 = sha256_bytes(&payload_bytes);
        let signed_root_bundle_sha256 =
            optional_sha256_file(&out_dir.join("signed-root-bundle.bin"))?;
        let database_manifest_sha256 = sha256_file_32(&out_dir.join("database.manifest.sha256"))?;
        let all_artifacts_manifest_sha256 =
            sha256_file_32(&out_dir.join("all-artifacts.manifest.sha256"))?;
        let server_db_manifest_sha256 = sha256_file_32(&out_dir.join("server-db/MANIFEST.toml"))?;
        let bucket_super_root = *payload
            .root("merkle/bucket/super_root")
            .ok_or("root-bundle payload missing merkle/bucket/super_root")?;
        let onion_super_root = *payload
            .root("merkle/onion/super_root")
            .ok_or("root-bundle payload missing merkle/onion/super_root")?;
        let evidence = BuildEvidence {
            builder_git_commit: builder_git_commit.to_owned(),
            builder_binary_sha256,
            tee_platform: tee_platform.to_owned(),
            tee_image_measurement: parse_optional_hex_bytes(
                tee_image_measurement_hex_or_none,
                "tee-image-measurement-hex-or-none",
            )?,
            core_version: core_version.to_owned(),
            snapshot_sha256,
            snapshot_bytes,
            network_magic: payload.network_magic,
            build_kind: payload.build_kind,
            from_anchor: payload.from_anchor,
            anchor: payload.anchor,
            utxo_muhash: payload.utxo_muhash,
            dust_threshold_sats: payload.dust_threshold_sats,
            max_utxos_per_spk: payload.max_utxos_per_spk,
            params_hash: payload.params_hash,
            index_bins_per_table: 0,
            chunk_bins_per_table: 0,
            onion_entry_size: 0,
            bucket_super_root,
            onion_super_root,
            root_bundle_payload_sha256,
            signed_root_bundle_sha256,
            database_manifest_sha256,
            all_artifacts_manifest_sha256,
            server_db_manifest_sha256,
        };
        let evidence = evidence.with_layout_from_summary(out_dir)?;
        let encoded = evidence.encode()?;
        create_new_parent(out_evidence)?;
        let mut writer = File::create_new(out_evidence)
            .map_err(|e| format!("failed to create {}: {e}", out_evidence.display()))?;
        writer
            .write_all(&encoded)
            .map_err(|e| format!("failed to write {}: {e}", out_evidence.display()))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush {}: {e}", out_evidence.display()))?;
        Ok::<_, String>(evidence)
    })();

    match result {
        Ok(evidence) => {
            print_evidence_report(&evidence, Some(out_evidence));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

pub fn inspect_build_evidence(evidence_path: &str) -> ExitCode {
    match load_evidence(Path::new(evidence_path)) {
        Ok(evidence) => {
            print_evidence_report(&evidence, Some(evidence_path));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

pub fn write_tee_report_data(evidence_path: &str, out_report_data: &str) -> ExitCode {
    match load_evidence(Path::new(evidence_path)).and_then(|evidence| {
        let report_data = evidence.report_data()?;
        let out = Path::new(out_report_data);
        create_new_parent(out)?;
        fs::write(out, report_data)
            .map_err(|e| format!("failed to write {}: {e}", out.display()))?;
        Ok((evidence, report_data))
    }) {
        Ok((evidence, report_data)) => {
            println!(
                "evidence_file_sha256={}",
                hex::encode(evidence.evidence_file_sha256().unwrap())
            );
            println!(
                "evidence_digest={}",
                hex::encode(evidence.evidence_digest().unwrap())
            );
            println!("report_data={}", hex::encode(report_data));
            println!("report_data_path={out_report_data}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

pub fn verify_tee_report_data(evidence_path: &str, report_data_hex_or_file: &str) -> ExitCode {
    match load_evidence(Path::new(evidence_path)).and_then(|evidence| {
        let expected = evidence.report_data()?;
        let actual = read_report_data_hex_or_file(report_data_hex_or_file)?;
        if expected != actual {
            return Err(format!(
                "REPORT_DATA mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            ));
        }
        Ok((evidence, actual))
    }) {
        Ok((evidence, report_data)) => {
            println!("status=ok");
            println!(
                "evidence_file_sha256={}",
                hex::encode(evidence.evidence_file_sha256().unwrap())
            );
            println!(
                "evidence_digest={}",
                hex::encode(evidence.evidence_digest().unwrap())
            );
            println!("report_data={}", hex::encode(report_data));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

pub fn verify_build_evidence(evidence_path: &str, args: &[String]) -> ExitCode {
    match verify_build_evidence_inner(Path::new(evidence_path), args) {
        Ok(evidence) => {
            println!("status=ok");
            print_evidence_report(&evidence, Some(evidence_path));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

pub fn emit_sev_snp_quote(
    evidence_path: &str,
    out_report: &str,
    out_report_data: Option<&String>,
) -> ExitCode {
    match load_evidence(Path::new(evidence_path)).and_then(|evidence| {
        let report_data = evidence.report_data()?;
        let report = fetch_sev_snp_report(report_data)?;
        let out_report = Path::new(out_report);
        create_new_parent(out_report)?;
        fs::write(out_report, &report)
            .map_err(|e| format!("failed to write {}: {e}", out_report.display()))?;
        if let Some(path) = out_report_data {
            let out = Path::new(path);
            create_new_parent(out)?;
            fs::write(out, report_data)
                .map_err(|e| format!("failed to write {}: {e}", out.display()))?;
        }
        Ok((evidence, report, report_data))
    }) {
        Ok((evidence, report, report_data)) => {
            println!("status=ok");
            println!(
                "evidence_file_sha256={}",
                hex::encode(evidence.evidence_file_sha256().unwrap())
            );
            println!(
                "evidence_digest={}",
                hex::encode(evidence.evidence_digest().unwrap())
            );
            println!("report_data={}", hex::encode(report_data));
            println!("sev_snp_report_bytes={}", report.len());
            println!(
                "sev_snp_report_sha256={}",
                hex::encode(sha256_bytes(&report))
            );
            println!("sev_snp_report_path={out_report}");
            if let Some(path) = out_report_data {
                println!("report_data_path={path}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn verify_build_evidence_inner(path: &Path, args: &[String]) -> Result<BuildEvidence, String> {
    let evidence = load_evidence(path)?;
    let mut i = 0usize;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--snapshot" => {
                let (actual, bytes) = sha256_file(Path::new(value))?;
                expect_eq(
                    "snapshot_sha256",
                    &hex::encode(evidence.snapshot_sha256),
                    &hex::encode(actual),
                )?;
                if evidence.snapshot_bytes != bytes {
                    return Err(format!(
                        "snapshot_bytes mismatch: expected {}, got {}",
                        evidence.snapshot_bytes, bytes
                    ));
                }
            }
            "--builder-bin" => {
                let actual = sha256_file_32(Path::new(value))?;
                expect_eq(
                    "builder_binary_sha256",
                    &hex::encode(evidence.builder_binary_sha256),
                    &hex::encode(actual),
                )?;
            }
            "--payload" => {
                let actual = sha256_file_32(Path::new(value))?;
                expect_eq(
                    "root_bundle_payload_sha256",
                    &hex::encode(evidence.root_bundle_payload_sha256),
                    &hex::encode(actual),
                )?;
            }
            "--database-manifest" => {
                let actual = sha256_file_32(Path::new(value))?;
                expect_eq(
                    "database_manifest_sha256",
                    &hex::encode(evidence.database_manifest_sha256),
                    &hex::encode(actual),
                )?;
            }
            "--all-artifacts-manifest" => {
                let actual = sha256_file_32(Path::new(value))?;
                expect_eq(
                    "all_artifacts_manifest_sha256",
                    &hex::encode(evidence.all_artifacts_manifest_sha256),
                    &hex::encode(actual),
                )?;
            }
            "--server-db-manifest" => {
                let actual = sha256_file_32(Path::new(value))?;
                expect_eq(
                    "server_db_manifest_sha256",
                    &hex::encode(evidence.server_db_manifest_sha256),
                    &hex::encode(actual),
                )?;
            }
            "--expected-muhash" => expect_eq(
                "muhash",
                &display_hash_hex(&evidence.utxo_muhash),
                &normalize_hex(value, "expected-muhash")?,
            )?,
            "--expected-anchor-height" => {
                let expected = value
                    .parse::<u32>()
                    .map_err(|_| format!("bad --expected-anchor-height: {value}"))?;
                if evidence.anchor.height != expected {
                    return Err(format!(
                        "anchor_height mismatch: expected {}, got {}",
                        expected, evidence.anchor.height
                    ));
                }
            }
            "--expected-anchor-hash" => expect_eq(
                "anchor_hash",
                &display_hash_hex(&evidence.anchor.block_hash),
                &normalize_hex(value, "expected-anchor-hash")?,
            )?,
            "--expected-database-manifest-sha256" => expect_eq(
                "database_manifest_sha256",
                &hex::encode(evidence.database_manifest_sha256),
                &normalize_hex(value, "expected-database-manifest-sha256")?,
            )?,
            "--expected-all-artifacts-manifest-sha256" => expect_eq(
                "all_artifacts_manifest_sha256",
                &hex::encode(evidence.all_artifacts_manifest_sha256),
                &normalize_hex(value, "expected-all-artifacts-manifest-sha256")?,
            )?,
            "--expected-server-db-manifest-sha256" => expect_eq(
                "server_db_manifest_sha256",
                &hex::encode(evidence.server_db_manifest_sha256),
                &normalize_hex(value, "expected-server-db-manifest-sha256")?,
            )?,
            "--expected-report-data" => {
                let actual = evidence.report_data()?;
                let expected = parse_hex_array::<64>(value, "expected-report-data")?;
                if actual != expected {
                    return Err(format!(
                        "report_data mismatch: expected {}, got {}",
                        hex::encode(expected),
                        hex::encode(actual)
                    ));
                }
            }
            "--sev-snp-report" => {
                let report = fs::read(value)
                    .map_err(|e| format!("failed to read SEV-SNP report {value}: {e}"))?;
                let report_data = extract_sev_snp_report_data(&report)?;
                let expected = evidence.report_data()?;
                if report_data != expected {
                    return Err(format!(
                        "SEV-SNP REPORT_DATA mismatch: expected {}, got {}",
                        hex::encode(expected),
                        hex::encode(report_data)
                    ));
                }
            }
            other => return Err(format!("unknown verify-build-evidence flag: {other}")),
        }
        i += 2;
    }
    Ok(evidence)
}

fn print_evidence_report(evidence: &BuildEvidence, evidence_path: Option<&str>) {
    let evidence_file_sha256 = evidence
        .evidence_file_sha256()
        .expect("encoding already validated");
    let evidence_digest = evidence
        .evidence_digest()
        .expect("encoding already validated");
    let report_data = evidence.report_data().expect("encoding already validated");
    println!("evidence_version={EVIDENCE_VERSION}");
    if let Some(path) = evidence_path {
        println!("evidence_path={path}");
    }
    println!("evidence_file_sha256={}", hex::encode(evidence_file_sha256));
    println!("evidence_digest={}", hex::encode(evidence_digest));
    println!("report_data={}", hex::encode(report_data));
    println!("builder_git_commit={}", evidence.builder_git_commit);
    println!(
        "builder_binary_sha256={}",
        hex::encode(evidence.builder_binary_sha256)
    );
    println!("tee_platform={}", evidence.tee_platform);
    println!(
        "tee_image_measurement={}",
        if evidence.tee_image_measurement.is_empty() {
            "none".to_owned()
        } else {
            hex::encode(&evidence.tee_image_measurement)
        }
    );
    println!("core_version={}", evidence.core_version);
    println!("snapshot_bytes={}", evidence.snapshot_bytes);
    println!("snapshot_sha256={}", hex::encode(evidence.snapshot_sha256));
    println!("network_magic={}", hex::encode(evidence.network_magic));
    println!("build_kind={}", build_kind_label(evidence.build_kind));
    println!("from_anchor_height={}", evidence.from_anchor.height);
    println!(
        "from_anchor_hash={}",
        display_hash_hex(&evidence.from_anchor.block_hash)
    );
    println!("anchor_height={}", evidence.anchor.height);
    println!(
        "anchor_hash={}",
        display_hash_hex(&evidence.anchor.block_hash)
    );
    println!("muhash={}", display_hash_hex(&evidence.utxo_muhash));
    println!("dust_threshold_sats={}", evidence.dust_threshold_sats);
    println!("max_utxos_per_spk={}", evidence.max_utxos_per_spk);
    println!("params_hash={}", hex::encode(evidence.params_hash));
    println!("index_bins_per_table={}", evidence.index_bins_per_table);
    println!("chunk_bins_per_table={}", evidence.chunk_bins_per_table);
    println!("onion_entry_size={}", evidence.onion_entry_size);
    println!(
        "bucket_super_root={}",
        hex::encode(evidence.bucket_super_root)
    );
    println!(
        "onion_super_root={}",
        hex::encode(evidence.onion_super_root)
    );
    println!(
        "root_bundle_payload_sha256={}",
        hex::encode(evidence.root_bundle_payload_sha256)
    );
    if let Some(h) = evidence.signed_root_bundle_sha256 {
        println!("signed_root_bundle_sha256={}", hex::encode(h));
    } else {
        println!("signed_root_bundle_sha256=none");
    }
    println!(
        "database_manifest_sha256={}",
        hex::encode(evidence.database_manifest_sha256)
    );
    println!(
        "all_artifacts_manifest_sha256={}",
        hex::encode(evidence.all_artifacts_manifest_sha256)
    );
    println!(
        "server_db_manifest_sha256={}",
        hex::encode(evidence.server_db_manifest_sha256)
    );
}

impl BuildEvidence {
    fn with_layout_from_summary(mut self, out_dir: &Path) -> Result<Self, String> {
        let summary = out_dir.join("build-summary.txt");
        self.index_bins_per_table = read_summary_u32(&summary, "index_bins_per_table")?
            .or(read_summary_u32(
                &out_dir.join("logs/03-build-index-cuckoo.out"),
                "bins_per_table",
            )?)
            .unwrap_or(self.index_bins_per_table);
        self.chunk_bins_per_table = read_summary_u32(&summary, "chunk_bins_per_table")?
            .or(read_summary_u32(
                &out_dir.join("logs/04-build-chunk-cuckoo.out"),
                "bins_per_table",
            )?)
            .unwrap_or(self.chunk_bins_per_table);
        self.onion_entry_size =
            read_summary_u32(&out_dir.join("build.env"), "onion_entry_size")?.unwrap_or(0);
        if self.index_bins_per_table == 0 {
            return Err(
                "could not determine index_bins_per_table from build-summary.txt or stage logs"
                    .into(),
            );
        }
        if self.chunk_bins_per_table == 0 {
            return Err(
                "could not determine chunk_bins_per_table from build-summary.txt or stage logs"
                    .into(),
            );
        }
        if self.onion_entry_size == 0 {
            return Err("could not determine onion_entry_size from build.env".into());
        }
        Ok(self)
    }
}

fn read_summary_u32(path: &Path, key: &str) -> Result<Option<u32>, String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Ok(None);
    };
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(key).and_then(|s| s.strip_prefix('=')) {
            let n = value
                .parse::<u32>()
                .map_err(|_| format!("bad {key} value in {}: {value}", path.display()))?;
            return Ok(Some(n));
        }
    }
    Ok(None)
}

fn load_evidence(path: &Path) -> Result<BuildEvidence, String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    BuildEvidence::decode(&bytes)
}

fn evidence_digest(evidence_bytes: &[u8]) -> Result<[u8; 32], String> {
    let mut h = Sha256::new();
    h.update(EVIDENCE_DOMAIN);
    h.update(evidence_bytes);
    Ok(h.finalize().into())
}

fn report_data_for_evidence_bytes(evidence_bytes: &[u8]) -> Result<[u8; 64], String> {
    let evidence_hash = evidence_digest(evidence_bytes)?;
    let mut high = Sha256::new();
    high.update(REPORT_DATA_DOMAIN);
    high.update(evidence_hash);
    let high: [u8; 32] = high.finalize().into();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&evidence_hash);
    out[32..].copy_from_slice(&high);
    Ok(out)
}

fn validate_metadata_string(name: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_STRING_LEN {
        return Err(format!("{name} too long: {} bytes", value.len()));
    }
    if value.bytes().any(|b| b == b'\n' || b == b'\r' || b == 0) {
        return Err(format!("{name} must not contain newline or NUL"));
    }
    Ok(())
}

fn put_u16(out: &mut Vec<u8>, n: u16) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_arr<const N: usize>(out: &mut Vec<u8>, bytes: &[u8; N]) {
    out.extend_from_slice(bytes);
}

fn put_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    validate_metadata_string("string", value)?;
    put_bytes_with_u16_len(out, value.as_bytes())
}

fn put_bytes_with_u16_len(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let len: u16 = bytes
        .len()
        .try_into()
        .map_err(|_| format!("byte field too large: {} bytes", bytes.len()))?;
    put_u16(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_anchor(out: &mut Vec<u8>, anchor: rootbundle::ChainAnchor) {
    out.extend_from_slice(&anchor.block_hash);
    put_u32(out, anchor.height);
}

fn take<'a>(cur: &mut &'a [u8], n: usize, what: &str) -> Result<&'a [u8], String> {
    if cur.len() < n {
        return Err(format!("truncated {what}"));
    }
    let (head, rest) = cur.split_at(n);
    *cur = rest;
    Ok(head)
}

fn take_arr<const N: usize>(cur: &mut &[u8], what: &str) -> Result<[u8; N], String> {
    Ok(take(cur, N, what)?.try_into().unwrap())
}

fn take_u8(cur: &mut &[u8], what: &str) -> Result<u8, String> {
    Ok(take_arr::<1>(cur, what)?[0])
}

fn take_u16(cur: &mut &[u8], what: &str) -> Result<u16, String> {
    Ok(u16::from_le_bytes(take_arr::<2>(cur, what)?))
}

fn take_u32(cur: &mut &[u8], what: &str) -> Result<u32, String> {
    Ok(u32::from_le_bytes(take_arr::<4>(cur, what)?))
}

fn take_u64(cur: &mut &[u8], what: &str) -> Result<u64, String> {
    Ok(u64::from_le_bytes(take_arr::<8>(cur, what)?))
}

fn take_string(cur: &mut &[u8], what: &str) -> Result<String, String> {
    let bytes = take_bytes_with_u16_len(cur, what)?;
    let value = String::from_utf8(bytes).map_err(|_| format!("{what} is not UTF-8"))?;
    validate_metadata_string(what, &value)?;
    Ok(value)
}

fn take_bytes_with_u16_len(cur: &mut &[u8], what: &str) -> Result<Vec<u8>, String> {
    let len = take_u16(cur, what)? as usize;
    Ok(take(cur, len, what)?.to_vec())
}

fn take_anchor(cur: &mut &[u8], what: &str) -> Result<rootbundle::ChainAnchor, String> {
    Ok(rootbundle::ChainAnchor {
        block_hash: take_arr::<32>(cur, what)?,
        height: take_u32(cur, what)?,
    })
}

fn build_kind_to_byte(kind: rootbundle::BuildKind) -> u8 {
    match kind {
        rootbundle::BuildKind::Snapshot => 0,
        rootbundle::BuildKind::Delta => 1,
    }
}

fn byte_to_build_kind(b: u8) -> Result<rootbundle::BuildKind, String> {
    match b {
        0 => Ok(rootbundle::BuildKind::Snapshot),
        1 => Ok(rootbundle::BuildKind::Delta),
        _ => Err(format!("unknown build kind: {b}")),
    }
}

fn build_kind_label(kind: rootbundle::BuildKind) -> &'static str {
    match kind {
        rootbundle::BuildKind::Snapshot => "snapshot",
        rootbundle::BuildKind::Delta => "delta",
    }
}

fn display_hash_hex(internal: &[u8; 32]) -> String {
    let mut h = *internal;
    h.reverse();
    hex::encode(h)
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

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

fn sha256_file_32(path: &Path) -> Result<[u8; 32], String> {
    sha256_file(path).map(|(h, _)| h)
}

fn optional_sha256_file(path: &Path) -> Result<Option<[u8; 32]>, String> {
    if path.exists() {
        sha256_file_32(path).map(Some)
    } else {
        Ok(None)
    }
}

fn create_new_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create output directory {}: {e}",
                parent.display()
            )
        })?;
    }
    Ok(())
}

fn parse_optional_hex_bytes(s: &str, label: &str) -> Result<Vec<u8>, String> {
    if matches!(s, "" | "-" | "none" | "NONE") {
        return Ok(Vec::new());
    }
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| format!("{label} must be hex, none, or -: {e}"))?;
    if bytes.len() > MAX_MEASUREMENT_LEN {
        return Err(format!("{label} too large: {} bytes", bytes.len()));
    }
    Ok(bytes)
}

fn parse_hex_array<const N: usize>(s: &str, label: &str) -> Result<[u8; N], String> {
    let bytes =
        hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("{label} must be hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{label} must be {N} bytes, got {}", bytes.len()))
}

fn normalize_hex(s: &str, label: &str) -> Result<String, String> {
    let s = s.trim_start_matches("0x");
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{label} must be even-length hex"));
    }
    Ok(s.to_ascii_lowercase())
}

fn expect_eq(label: &str, expected: &str, actual: &str) -> Result<(), String> {
    if expected.eq_ignore_ascii_case(actual) {
        Ok(())
    } else {
        Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ))
    }
}

fn read_report_data_hex_or_file(s: &str) -> Result<[u8; 64], String> {
    let path = Path::new(s);
    if path.exists() {
        let bytes =
            fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        return bytes.try_into().map_err(|bytes: Vec<u8>| {
            format!(
                "REPORT_DATA file {} must be 64 bytes, got {}",
                path.display(),
                bytes.len()
            )
        });
    }
    parse_hex_array::<64>(s, "report-data-hex-or-file")
}

fn extract_sev_snp_report_data(report: &[u8]) -> Result<[u8; 64], String> {
    if report.len() < SEV_SNP_REPORT_DATA_OFFSET + SEV_SNP_REPORT_DATA_LEN {
        return Err(format!(
            "SEV-SNP report too short for REPORT_DATA: {} bytes",
            report.len()
        ));
    }
    Ok(
        report[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + SEV_SNP_REPORT_DATA_LEN]
            .try_into()
            .unwrap(),
    )
}

#[cfg(unix)]
fn fetch_sev_snp_report(user_data: [u8; 64]) -> Result<Vec<u8>, String> {
    const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";
    const SNP_GET_REPORT_IOCTL: libc::c_ulong = 0xc020_5300;

    #[repr(C)]
    struct SnpGuestRequestIoctl {
        msg_version: u8,
        _pad: [u8; 7],
        req_data: u64,
        resp_data: u64,
        exitinfo2: u64,
    }

    #[repr(C)]
    struct SnpReportReq {
        user_data: [u8; 64],
        vmpl: u32,
        _rsvd: [u8; 28],
    }

    #[repr(C)]
    struct SnpReportResp {
        data: [u8; 4000],
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(SEV_GUEST_DEVICE)
        .map_err(|e| format!("failed to open {SEV_GUEST_DEVICE}: {e}"))?;
    let mut req = SnpReportReq {
        user_data,
        vmpl: 0,
        _rsvd: [0u8; 28],
    };
    let mut resp = SnpReportResp { data: [0u8; 4000] };
    let mut wrap = SnpGuestRequestIoctl {
        msg_version: 1,
        _pad: [0u8; 7],
        req_data: &mut req as *mut _ as u64,
        resp_data: &mut resp as *mut _ as u64,
        exitinfo2: 0,
    };

    let rc = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            SNP_GET_REPORT_IOCTL,
            &mut wrap as *mut SnpGuestRequestIoctl,
        )
    };
    if rc != 0 {
        return Err(format!(
            "SNP_GET_REPORT ioctl failed: {} (exitinfo2=0x{:x})",
            std::io::Error::last_os_error(),
            wrap.exitinfo2
        ));
    }
    const KERNEL_HEADER_LEN: usize = 32;
    Ok(resp.data[KERNEL_HEADER_LEN..KERNEL_HEADER_LEN + SEV_SNP_REPORT_LEN].to_vec())
}

#[cfg(not(unix))]
fn fetch_sev_snp_report(_user_data: [u8; 64]) -> Result<Vec<u8>, String> {
    Err("emit-sev-snp-quote is only supported on Unix-like systems".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evidence() -> BuildEvidence {
        BuildEvidence {
            builder_git_commit: "abc123".into(),
            builder_binary_sha256: [1u8; 32],
            tee_platform: "sev-snp".into(),
            tee_image_measurement: vec![2u8; 48],
            core_version: "Satoshi:31.0.0".into(),
            snapshot_sha256: [3u8; 32],
            snapshot_bytes: 1234,
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            build_kind: rootbundle::BuildKind::Snapshot,
            from_anchor: rootbundle::ChainAnchor {
                block_hash: [0u8; 32],
                height: 0,
            },
            anchor: rootbundle::ChainAnchor {
                block_hash: [4u8; 32],
                height: 953_383,
            },
            utxo_muhash: [5u8; 32],
            dust_threshold_sats: 576,
            max_utxos_per_spk: 100,
            params_hash: [6u8; 32],
            index_bins_per_table: 570_712,
            chunk_bins_per_table: 1_074_267,
            onion_entry_size: 3328,
            bucket_super_root: [7u8; 32],
            onion_super_root: [8u8; 32],
            root_bundle_payload_sha256: [9u8; 32],
            signed_root_bundle_sha256: Some([10u8; 32]),
            database_manifest_sha256: [11u8; 32],
            all_artifacts_manifest_sha256: [12u8; 32],
            server_db_manifest_sha256: [13u8; 32],
        }
    }

    #[test]
    fn evidence_roundtrip() {
        let evidence = sample_evidence();
        let encoded = evidence.encode().unwrap();
        assert_eq!(BuildEvidence::decode(&encoded).unwrap(), evidence);
    }

    #[test]
    fn report_data_is_full_64_byte_binding() {
        let evidence = sample_evidence();
        let encoded = evidence.encode().unwrap();
        let evidence_hash = evidence_digest(&encoded).unwrap();
        let report_data = evidence.report_data().unwrap();
        assert_eq!(&report_data[..32], &evidence_hash);
        assert_ne!(&report_data[32..], &[0u8; 32]);

        let mut changed = evidence.clone();
        changed.server_db_manifest_sha256 = [99u8; 32];
        assert_ne!(report_data, changed.report_data().unwrap());
    }

    #[test]
    fn rejects_newline_metadata() {
        let mut evidence = sample_evidence();
        evidence.core_version = "bad\nversion".into();
        assert!(evidence.encode().unwrap_err().contains("newline"));
    }
}
