use std::fmt;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

pub const SIBLING_ROWS_INDEX_MAGIC: u64 = 0xBA7C_0E52_0000_0000;
pub const SIBLING_ROWS_DATA_MAGIC: u64 = 0xBA7C_0E52_0000_0001;
pub const SIBLING_DB_INDEX_MAGIC: u64 = 0xBA7C_0E51_0000_0000;
pub const SIBLING_DB_DATA_MAGIC: u64 = 0xBA7C_0E51_0000_0001;
pub const SIBLING_ROWS_HEADER_SIZE: usize = 24;
pub const ONION_SAVE_DB_HEADER_SIZE: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiblingKind {
    Index,
    Data,
}

impl SiblingKind {
    pub fn rows_magic(self) -> u64 {
        match self {
            Self::Index => SIBLING_ROWS_INDEX_MAGIC,
            Self::Data => SIBLING_ROWS_DATA_MAGIC,
        }
    }

    pub fn db_magic(self) -> u64 {
        match self {
            Self::Index => SIBLING_DB_INDEX_MAGIC,
            Self::Data => SIBLING_DB_DATA_MAGIC,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Index => "index",
            Self::Data => "data",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiblingRowsMeta {
    pub kind: SiblingKind,
    pub k: u32,
    pub arity: u32,
    pub rows_per_group: u32,
    pub row_bytes: u32,
}

impl SiblingRowsMeta {
    pub fn body_len(self) -> Result<usize, Error> {
        let k = self.k as usize;
        let rows_per_group = self.rows_per_group as usize;
        let row_bytes = self.row_bytes as usize;
        k.checked_mul(rows_per_group)
            .and_then(|n| n.checked_mul(row_bytes))
            .ok_or(Error::IntegerOverflow("sibling rows body length"))
    }

    pub fn output_header_len(self) -> usize {
        SIBLING_ROWS_HEADER_SIZE
    }

    pub fn output_len_with_blob(self, blob_len: usize) -> Result<usize, Error> {
        (self.k as usize)
            .checked_mul(blob_len)
            .and_then(|body| self.output_header_len().checked_add(body))
            .ok_or(Error::IntegerOverflow("sibling DB output length"))
    }
}

#[derive(Debug)]
pub struct ParsedSiblingRows<'a> {
    pub meta: SiblingRowsMeta,
    body: &'a [u8],
}

impl<'a> ParsedSiblingRows<'a> {
    pub fn group_rows(&self, group: usize) -> Result<&'a [u8], Error> {
        if group >= self.meta.k as usize {
            return Err(Error::InvalidGroup {
                group,
                k: self.meta.k as usize,
            });
        }
        let rows_per_group = self.meta.rows_per_group as usize;
        let row_bytes = self.meta.row_bytes as usize;
        let group_len = rows_per_group
            .checked_mul(row_bytes)
            .ok_or(Error::IntegerOverflow("group sibling rows length"))?;
        let start = group
            .checked_mul(group_len)
            .ok_or(Error::IntegerOverflow("group sibling rows offset"))?;
        Ok(&self.body[start..start + group_len])
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    UnknownMagic(u64),
    TooShort { len: usize },
    SizeMismatch { expected: usize, actual: usize },
    InvalidGroup { group: usize, k: usize },
    InvalidRowsPerGroup(u32),
    InvalidArity { arity: u32, row_bytes: u32 },
    InvalidOnionShape(String),
    IntegerOverflow(&'static str),
    FfiUnavailable,
    FfiFailed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::UnknownMagic(magic) => write!(f, "unknown sibling rows magic: 0x{magic:016x}"),
            Self::TooShort { len } => write!(f, "sibling rows file too short: {len} bytes"),
            Self::SizeMismatch { expected, actual } => {
                write!(
                    f,
                    "sibling rows size mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidGroup { group, k } => {
                write!(f, "invalid group {group}; file contains {k} groups")
            }
            Self::InvalidRowsPerGroup(rows) => {
                write!(
                    f,
                    "rows_per_group must be non-zero for OnionPIR preprocessing, got {rows}"
                )
            }
            Self::InvalidArity { arity, row_bytes } => {
                write!(
                    f,
                    "row_bytes ({row_bytes}) must equal arity * 32 ({arity} * 32)"
                )
            }
            Self::InvalidOnionShape(msg) => write!(f, "{msg}"),
            Self::IntegerOverflow(what) => write!(f, "integer overflow while computing {what}"),
            Self::FfiUnavailable => write!(
                f,
                "OnionPIR FFI support is disabled; rebuild with `--features ffi`"
            ),
            Self::FfiFailed(op) => write!(f, "OnionPIR FFI call failed: {op}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn parse_sibling_rows(data: &[u8]) -> Result<ParsedSiblingRows<'_>, Error> {
    if data.len() < SIBLING_ROWS_HEADER_SIZE {
        return Err(Error::TooShort { len: data.len() });
    }

    let magic = read_u64_le(data, 0);
    let kind = match magic {
        SIBLING_ROWS_INDEX_MAGIC => SiblingKind::Index,
        SIBLING_ROWS_DATA_MAGIC => SiblingKind::Data,
        other => return Err(Error::UnknownMagic(other)),
    };
    let meta = SiblingRowsMeta {
        kind,
        k: read_u32_le(data, 8),
        arity: read_u32_le(data, 12),
        rows_per_group: read_u32_le(data, 16),
        row_bytes: read_u32_le(data, 20),
    };
    if meta.row_bytes != meta.arity.saturating_mul(32) {
        return Err(Error::InvalidArity {
            arity: meta.arity,
            row_bytes: meta.row_bytes,
        });
    }
    let expected = SIBLING_ROWS_HEADER_SIZE
        .checked_add(meta.body_len()?)
        .ok_or(Error::IntegerOverflow("sibling rows file length"))?;
    if data.len() != expected {
        return Err(Error::SizeMismatch {
            expected,
            actual: data.len(),
        });
    }
    Ok(ParsedSiblingRows {
        meta,
        body: &data[SIBLING_ROWS_HEADER_SIZE..],
    })
}

pub fn inspect_sibling_rows_file(path: impl AsRef<Path>) -> Result<SiblingRowsMeta, Error> {
    let data = std::fs::read(path)?;
    Ok(parse_sibling_rows(&data)?.meta)
}

pub fn preprocess_sibling_rows_file(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<SiblingDbReport, Error> {
    let data = std::fs::read(input)?;
    let parsed = parse_sibling_rows(&data)?;
    preprocess_sibling_rows(parsed, output)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiblingDbReport {
    pub kind: SiblingKind,
    pub k: u32,
    pub arity: u32,
    pub rows_per_group: u32,
    pub blob_len: u32,
    pub output_bytes: u64,
}

pub fn bits_per_coeff(entry_size: usize, poly_degree: usize) -> Option<u32> {
    if poly_degree == 0 {
        return None;
    }
    let total_bits = entry_size.checked_mul(8)?;
    if total_bits % poly_degree != 0 {
        return None;
    }
    Some((total_bits / poly_degree) as u32)
}

pub fn pack_bytes_into_coefficients(
    bytes: &[u8],
    entry_size: usize,
    poly_degree: usize,
) -> Vec<u64> {
    let bpc = bits_per_coeff(entry_size, poly_degree)
        .expect("entry_size * 8 must be a multiple of poly_degree");
    let mut out = vec![0u64; poly_degree];
    let mut buffer: u128 = 0;
    let mut offset: u32 = 0;
    let mut coeff_idx: usize = 0;
    let take = bytes.len().min(entry_size);
    for &b in &bytes[..take] {
        buffer |= (b as u128) << offset;
        offset += 8;
        while offset >= bpc {
            let mask: u128 = (1u128 << bpc) - 1;
            if coeff_idx >= poly_degree {
                return out;
            }
            out[coeff_idx] = (buffer & mask) as u64;
            coeff_idx += 1;
            buffer >>= bpc;
            offset -= bpc;
        }
    }
    if offset > 0 && coeff_idx < poly_degree {
        let mask: u128 = (1u128 << bpc) - 1;
        out[coeff_idx] = (buffer & mask) as u64;
    }
    out
}

pub fn preprocess_sibling_rows(
    parsed: ParsedSiblingRows<'_>,
    output: impl AsRef<Path>,
) -> Result<SiblingDbReport, Error> {
    if parsed.meta.rows_per_group == 0 {
        return write_consolidated_sibling_db(parsed.meta, &[], output);
    }

    preprocess_nonempty_sibling_rows(parsed, output)
}

#[cfg(feature = "ffi")]
fn preprocess_nonempty_sibling_rows(
    parsed: ParsedSiblingRows<'_>,
    output: impl AsRef<Path>,
) -> Result<SiblingDbReport, Error> {
    debug_assert_ne!(parsed.meta.rows_per_group, 0);

    let p = onionpir::params_info(parsed.meta.rows_per_group as u64);
    if p.num_plaintexts != parsed.meta.rows_per_group as u64 {
        return Err(Error::InvalidOnionShape(format!(
            "OnionPIR shaped {} sibling DB to {} plaintexts, expected exactly {}",
            parsed.meta.kind.label(),
            p.num_plaintexts,
            parsed.meta.rows_per_group
        )));
    }
    if p.entry_size != parsed.meta.row_bytes as u64 {
        return Err(Error::InvalidOnionShape(format!(
            "OnionPIR entry_size {} != sibling row_bytes {}",
            p.entry_size, parsed.meta.row_bytes
        )));
    }

    let mut blobs = Vec::with_capacity(parsed.meta.k as usize);
    for group in 0..parsed.meta.k as usize {
        blobs.push(preprocess_one_group(
            parsed.group_rows(group)?,
            parsed.meta.rows_per_group as usize,
            parsed.meta.row_bytes as usize,
            p.poly_degree as usize,
        )?);
    }

    write_consolidated_sibling_db(parsed.meta, &blobs, output)
}

#[cfg(not(feature = "ffi"))]
fn preprocess_nonempty_sibling_rows(
    _parsed: ParsedSiblingRows<'_>,
    _output: impl AsRef<Path>,
) -> Result<SiblingDbReport, Error> {
    Err(Error::FfiUnavailable)
}

#[cfg(feature = "ffi")]
fn preprocess_one_group(
    group_rows: &[u8],
    rows_per_group: usize,
    row_bytes: usize,
    poly_degree: usize,
) -> Result<Vec<u8>, Error> {
    let mut all_coeffs = Vec::with_capacity(rows_per_group * poly_degree);
    for row in group_rows.chunks_exact(row_bytes) {
        let coeffs = pack_bytes_into_coefficients(row, row_bytes, poly_degree);
        all_coeffs.extend_from_slice(&coeffs);
    }

    let mut server = onionpir::Server::new(rows_per_group as u64);
    if !server.push_plaintexts(&all_coeffs, rows_per_group as u64, 0, &[]) {
        return Err(Error::FfiFailed("push_plaintexts"));
    }
    let temp = temp_save_path()?;
    let temp_str = temp.to_string_lossy();
    if !server.save_db(&temp_str) {
        let _ = std::fs::remove_file(&temp);
        return Err(Error::FfiFailed("save_db"));
    }
    let blob = std::fs::read(&temp)?;
    let _ = std::fs::remove_file(&temp);
    if blob.len() < ONION_SAVE_DB_HEADER_SIZE {
        return Err(Error::InvalidOnionShape(format!(
            "save_db blob too short: {} bytes",
            blob.len()
        )));
    }
    Ok(blob)
}

#[cfg(feature = "ffi")]
fn temp_save_path() -> Result<std::path::PathBuf, Error> {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidOnionShape("system clock is before unix epoch".to_string()))?
        .as_nanos();
    path.push(format!("pir-onionffi-{pid}-{nanos}.savetmp"));
    Ok(path)
}

fn write_consolidated_sibling_db(
    meta: SiblingRowsMeta,
    blobs: &[Vec<u8>],
    output: impl AsRef<Path>,
) -> Result<SiblingDbReport, Error> {
    let blob_len = match blobs.first() {
        Some(first) => first.len(),
        None if meta.rows_per_group == 0 => 0,
        None => return Err(Error::InvalidRowsPerGroup(meta.rows_per_group)),
    };
    for blob in blobs {
        if blob.len() != blob_len {
            return Err(Error::InvalidOnionShape(format!(
                "per-group sibling DB blob length drifted: expected {}, got {}",
                blob_len,
                blob.len()
            )));
        }
    }
    let blob_len_u32 = u32::try_from(blob_len).map_err(|_| {
        Error::InvalidOnionShape(format!("blob length does not fit u32: {blob_len}"))
    })?;
    let output_bytes = meta.output_len_with_blob(blob_len)? as u64;

    let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, File::create_new(output)?);
    writer.write_all(&meta.kind.db_magic().to_le_bytes())?;
    writer.write_all(&meta.k.to_le_bytes())?;
    writer.write_all(&meta.arity.to_le_bytes())?;
    writer.write_all(&meta.rows_per_group.to_le_bytes())?;
    writer.write_all(&blob_len_u32.to_le_bytes())?;
    for blob in blobs {
        writer.write_all(blob)?;
    }
    writer.flush()?;

    Ok(SiblingDbReport {
        kind: meta.kind,
        k: meta.k,
        arity: meta.arity,
        rows_per_group: meta.rows_per_group,
        blob_len: blob_len_u32,
        output_bytes,
    })
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sibling_rows_header_and_group_slices() {
        let mut data = Vec::new();
        data.extend_from_slice(&SIBLING_ROWS_DATA_MAGIC.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&64u32.to_le_bytes());
        data.extend_from_slice(&vec![0x11; 3 * 64]);
        data.extend_from_slice(&vec![0x22; 3 * 64]);

        let parsed = parse_sibling_rows(&data).unwrap();
        assert_eq!(parsed.meta.kind, SiblingKind::Data);
        assert_eq!(parsed.meta.k, 2);
        assert_eq!(parsed.meta.arity, 2);
        assert_eq!(parsed.meta.rows_per_group, 3);
        assert_eq!(parsed.group_rows(0).unwrap(), &vec![0x11; 3 * 64]);
        assert_eq!(parsed.group_rows(1).unwrap(), &vec![0x22; 3 * 64]);
    }

    #[test]
    fn parse_sibling_rows_rejects_wrong_size() {
        let mut data = Vec::new();
        data.extend_from_slice(&SIBLING_ROWS_INDEX_MAGIC.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&64u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 63]);

        assert!(matches!(
            parse_sibling_rows(&data),
            Err(Error::SizeMismatch {
                expected: 88,
                actual: 87
            })
        ));
    }

    #[test]
    fn pack_bytes_matches_little_endian_bitstream() {
        let coeffs = pack_bytes_into_coefficients(&[0b1010_1100, 0b0000_0011], 2, 4);
        assert_eq!(bits_per_coeff(2, 4), Some(4));
        assert_eq!(coeffs, vec![0b1100, 0b1010, 0b0011, 0]);
    }

    #[test]
    fn default_onion_shape_bits_per_coeff_is_stable() {
        assert_eq!(bits_per_coeff(3328, 2048), Some(13));
        let payload: Vec<u8> = (0..=255).cycle().take(3328).collect();
        let coeffs = pack_bytes_into_coefficients(&payload, 3328, 2048);
        assert_eq!(coeffs.len(), 2048);
        assert_eq!(coeffs[0], 256);
        assert_ne!(coeffs[1], 0);
    }

    #[test]
    fn preprocess_empty_rows_writes_header_without_ffi() {
        let mut data = Vec::new();
        data.extend_from_slice(&SIBLING_ROWS_INDEX_MAGIC.to_le_bytes());
        data.extend_from_slice(&75u32.to_le_bytes());
        data.extend_from_slice(&104u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&3328u32.to_le_bytes());
        let parsed = parse_sibling_rows(&data).unwrap();
        let out = temp_test_path("empty-sib-db");
        let _ = std::fs::remove_file(&out);

        let report = preprocess_sibling_rows(parsed, &out).unwrap();
        let bytes = std::fs::read(&out).unwrap();
        let _ = std::fs::remove_file(&out);

        assert_eq!(report.kind, SiblingKind::Index);
        assert_eq!(report.k, 75);
        assert_eq!(report.rows_per_group, 0);
        assert_eq!(report.blob_len, 0);
        assert_eq!(report.output_bytes, 24);
        assert_eq!(bytes.len(), 24);
        assert_eq!(read_u64_le(&bytes, 0), SIBLING_DB_INDEX_MAGIC);
        assert_eq!(read_u32_le(&bytes, 8), 75);
        assert_eq!(read_u32_le(&bytes, 12), 104);
        assert_eq!(read_u32_le(&bytes, 16), 0);
        assert_eq!(read_u32_le(&bytes, 20), 0);
    }

    fn temp_test_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "pir-onionffi-test-{name}-{}-{nanos}",
            std::process::id()
        ));
        path
    }
}
