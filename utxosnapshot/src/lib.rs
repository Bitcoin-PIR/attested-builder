//! Bitcoin Core `dumptxoutset` v2 parser plus MuHash verifier.
//!
//! Bitcoin Core's v2 snapshot stores coins in compressed form, but
//! `gettxoutsetinfo muhash` does **not** hash that compressed encoding.
//! Core v31's `kernel/coinstats.cpp::TxOutSer` preimage is:
//!
//! `COutPoint || uint32(height * 2 + coinbase) || CTxOut`
//!
//! where `CTxOut` is normal transaction-output serialization:
//! `amount i64 little-endian || CompactSize(scriptPubKey.len) || scriptPubKey`.

use coremuhash::MuHash3072;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

pub const SNAPSHOT_MAGIC: [u8; 5] = [b'u', b't', b'x', b'o', 0xff];
pub const SNAPSHOT_VERSION_V2: u16 = 2;
pub const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
pub const REGTEST_MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];
pub const TESTNET3_MAGIC: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];
pub const SIGNET_MAGIC: [u8; 4] = [0x0a, 0x03, 0xcf, 0x40];

const NUM_SPECIAL_SCRIPTS: u64 = 6;
const MAX_SCRIPT_SIZE: u64 = 10_000;

#[derive(Debug)]
pub enum SnapshotError {
    Io(io::Error),
    BadMagic([u8; 5]),
    UnsupportedVersion(u16),
    Truncated(&'static str),
    NonMinimalCompactSize,
    NonMinimalVarInt,
    InvalidCode(u64),
    VoutTooLarge(u64),
    ScriptTooLarge(u64),
    InvalidCompressedPubkey,
    CoinCountMismatch { expected: u64, actual: u64 },
    TrailingBytes,
    BadExpectedMuhash(String),
    MuhashMismatch { expected: String, actual: String },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::Io(e) => write!(f, "I/O error: {e}"),
            SnapshotError::BadMagic(m) => write!(f, "bad snapshot magic: {}", hex::encode(m)),
            SnapshotError::UnsupportedVersion(v) => write!(f, "unsupported snapshot version: {v}"),
            SnapshotError::Truncated(what) => write!(f, "truncated {what}"),
            SnapshotError::NonMinimalCompactSize => write!(f, "non-minimal CompactSize"),
            SnapshotError::NonMinimalVarInt => write!(f, "non-minimal VARINT"),
            SnapshotError::InvalidCode(code) => write!(f, "invalid coin code: {code}"),
            SnapshotError::VoutTooLarge(vout) => write!(f, "vout too large for COutPoint: {vout}"),
            SnapshotError::ScriptTooLarge(size) => write!(f, "compressed script too large: {size}"),
            SnapshotError::InvalidCompressedPubkey => {
                write!(f, "invalid compressed secp256k1 pubkey")
            }
            SnapshotError::CoinCountMismatch { expected, actual } => {
                write!(
                    f,
                    "coin count mismatch: expected {expected}, parsed {actual}"
                )
            }
            SnapshotError::TrailingBytes => write!(f, "trailing bytes after declared coin count"),
            SnapshotError::BadExpectedMuhash(s) => write!(f, "bad expected muhash hex: {s}"),
            SnapshotError::MuhashMismatch { expected, actual } => {
                write!(f, "muhash mismatch: expected {expected}, actual {actual}")
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<io::Error> for SnapshotError {
    fn from(e: io::Error) -> Self {
        SnapshotError::Io(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotHeader {
    pub network_magic: [u8; 4],
    /// Internal byte order, as stored in the snapshot file.
    pub base_hash: [u8; 32],
    pub coin_count: u64,
}

impl SnapshotHeader {
    pub fn base_hash_display_hex(&self) -> String {
        display_hash_hex(&self.base_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    /// Transaction id bytes in Bitcoin consensus/internal byte order.
    pub txid: [u8; 32],
    pub vout: u32,
    pub height: u32,
    pub is_coinbase: bool,
    pub amount_sats: u64,
    pub script_pubkey: Vec<u8>,
}

impl Coin {
    pub fn muhash_preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(36 + 4 + 8 + 9 + self.script_pubkey.len());
        out.extend_from_slice(&self.txid);
        out.extend_from_slice(&self.vout.to_le_bytes());
        let code = self.height * 2 + u32::from(self.is_coinbase);
        out.extend_from_slice(&code.to_le_bytes());
        out.extend_from_slice(&(self.amount_sats as i64).to_le_bytes());
        encode_compact_size(self.script_pubkey.len() as u64, &mut out);
        out.extend_from_slice(&self.script_pubkey);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuhashReport {
    pub header: SnapshotHeader,
    pub coins: u64,
    pub muhash_display_hex: String,
}

pub struct SnapshotReader<R> {
    reader: R,
    header: SnapshotHeader,
    parsed: u64,
    state: TxidState,
}

#[derive(Clone, Copy)]
enum TxidState {
    NeedTxid,
    HaveTxid { txid: [u8; 32], remaining: u64 },
}

impl SnapshotReader<BufReader<File>> {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SnapshotError> {
        let file = File::open(path)?;
        Self::new(BufReader::new(file))
    }
}

impl<R: Read> SnapshotReader<R> {
    pub fn new(mut reader: R) -> Result<Self, SnapshotError> {
        let mut magic = [0u8; 5];
        read_exact(&mut reader, &mut magic, "snapshot magic")?;
        if magic != SNAPSHOT_MAGIC {
            return Err(SnapshotError::BadMagic(magic));
        }

        let version = read_u16_le(&mut reader, "snapshot version")?;
        if version != SNAPSHOT_VERSION_V2 {
            return Err(SnapshotError::UnsupportedVersion(version));
        }

        let mut network_magic = [0u8; 4];
        read_exact(&mut reader, &mut network_magic, "network magic")?;
        let mut base_hash = [0u8; 32];
        read_exact(&mut reader, &mut base_hash, "base hash")?;
        let coin_count = read_u64_le(&mut reader, "coin count")?;

        Ok(Self {
            reader,
            header: SnapshotHeader {
                network_magic,
                base_hash,
                coin_count,
            },
            parsed: 0,
            state: TxidState::NeedTxid,
        })
    }

    pub fn header(&self) -> &SnapshotHeader {
        &self.header
    }

    pub fn next_coin(&mut self) -> Result<Option<Coin>, SnapshotError> {
        if self.parsed == self.header.coin_count {
            let mut b = [0u8; 1];
            return match self.reader.read(&mut b) {
                Ok(0) => Ok(None),
                Ok(_) => Err(SnapshotError::TrailingBytes),
                Err(e) => Err(SnapshotError::Io(e)),
            };
        }

        let (txid, vout) = match self.state {
            TxidState::NeedTxid => {
                let mut txid = [0u8; 32];
                read_exact(&mut self.reader, &mut txid, "txid")?;
                let count = read_compact_size(&mut self.reader)?;
                let vout = read_compact_size(&mut self.reader)?;
                if count > 1 {
                    self.state = TxidState::HaveTxid {
                        txid,
                        remaining: count - 1,
                    };
                }
                (txid, checked_vout(vout)?)
            }
            TxidState::HaveTxid { txid, remaining } => {
                let vout = read_compact_size(&mut self.reader)?;
                if remaining == 1 {
                    self.state = TxidState::NeedTxid;
                } else {
                    self.state = TxidState::HaveTxid {
                        txid,
                        remaining: remaining - 1,
                    };
                }
                (txid, checked_vout(vout)?)
            }
        };

        let (code, _) = read_varint_with_bytes(&mut self.reader)?;
        let code_u32 = u32::try_from(code).map_err(|_| SnapshotError::InvalidCode(code))?;
        let height = code_u32 >> 1;
        let is_coinbase = (code_u32 & 1) == 1;

        let (compressed_amount, _) = read_varint_with_bytes(&mut self.reader)?;
        let amount_sats = decompress_amount(compressed_amount);
        let script_pubkey = read_script_pubkey(&mut self.reader)?;

        self.parsed += 1;
        Ok(Some(Coin {
            txid,
            vout,
            height,
            is_coinbase,
            amount_sats,
            script_pubkey,
        }))
    }

    pub fn finish(self) -> Result<(), SnapshotError> {
        if self.parsed == self.header.coin_count {
            Ok(())
        } else {
            Err(SnapshotError::CoinCountMismatch {
                expected: self.header.coin_count,
                actual: self.parsed,
            })
        }
    }
}

pub fn compute_muhash(path: impl AsRef<Path>) -> Result<MuhashReport, SnapshotError> {
    let mut snapshot = SnapshotReader::open(path)?;
    let header = snapshot.header().clone();
    let mut muhash = MuHash3072::new();
    while let Some(coin) = snapshot.next_coin()? {
        muhash.insert(&coin.muhash_preimage());
    }
    snapshot.finish()?;
    Ok(MuhashReport {
        coins: header.coin_count,
        header,
        muhash_display_hex: muhash.digest_display_hex(),
    })
}

pub fn verify_muhash(
    path: impl AsRef<Path>,
    expected_display_hex: &str,
) -> Result<MuhashReport, SnapshotError> {
    if expected_display_hex.len() != 64
        || !expected_display_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(SnapshotError::BadExpectedMuhash(
            expected_display_hex.to_owned(),
        ));
    }
    let report = compute_muhash(path)?;
    if !report
        .muhash_display_hex
        .eq_ignore_ascii_case(expected_display_hex)
    {
        return Err(SnapshotError::MuhashMismatch {
            expected: expected_display_hex.to_ascii_lowercase(),
            actual: report.muhash_display_hex,
        });
    }
    Ok(report)
}

pub fn display_hash_hex(internal: &[u8; 32]) -> String {
    let mut h = *internal;
    h.reverse();
    hex::encode(h)
}

fn checked_vout(vout: u64) -> Result<u32, SnapshotError> {
    u32::try_from(vout).map_err(|_| SnapshotError::VoutTooLarge(vout))
}

fn read_exact<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    what: &'static str,
) -> Result<(), SnapshotError> {
    reader.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            SnapshotError::Truncated(what)
        } else {
            SnapshotError::Io(e)
        }
    })
}

fn read_u16_le<R: Read>(reader: &mut R, what: &'static str) -> Result<u16, SnapshotError> {
    let mut b = [0u8; 2];
    read_exact(reader, &mut b, what)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u64_le<R: Read>(reader: &mut R, what: &'static str) -> Result<u64, SnapshotError> {
    let mut b = [0u8; 8];
    read_exact(reader, &mut b, what)?;
    Ok(u64::from_le_bytes(b))
}

fn read_compact_size<R: Read>(reader: &mut R) -> Result<u64, SnapshotError> {
    let mut tag = [0u8; 1];
    read_exact(reader, &mut tag, "CompactSize")?;
    match tag[0] {
        n @ 0..=252 => Ok(n as u64),
        253 => {
            let mut b = [0u8; 2];
            read_exact(reader, &mut b, "CompactSize u16")?;
            let n = u16::from_le_bytes(b) as u64;
            if n < 253 {
                Err(SnapshotError::NonMinimalCompactSize)
            } else {
                Ok(n)
            }
        }
        254 => {
            let mut b = [0u8; 4];
            read_exact(reader, &mut b, "CompactSize u32")?;
            let n = u32::from_le_bytes(b) as u64;
            if n <= u16::MAX as u64 {
                Err(SnapshotError::NonMinimalCompactSize)
            } else {
                Ok(n)
            }
        }
        255 => {
            let mut b = [0u8; 8];
            read_exact(reader, &mut b, "CompactSize u64")?;
            let n = u64::from_le_bytes(b);
            if n <= u32::MAX as u64 {
                Err(SnapshotError::NonMinimalCompactSize)
            } else {
                Ok(n)
            }
        }
    }
}

fn encode_compact_size(n: u64, out: &mut Vec<u8>) {
    if n < 253 {
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(253);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(254);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(255);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn read_varint_with_bytes<R: Read>(reader: &mut R) -> Result<(u64, Vec<u8>), SnapshotError> {
    let mut n: u64 = 0;
    let mut bytes = Vec::with_capacity(5);
    loop {
        let mut b = [0u8; 1];
        read_exact(reader, &mut b, "VARINT")?;
        bytes.push(b[0]);
        if n > u64::MAX >> 7 {
            return Err(SnapshotError::NonMinimalVarInt);
        }
        n = (n << 7) | ((b[0] & 0x7f) as u64);
        if (b[0] & 0x80) != 0 {
            if n == u64::MAX {
                return Err(SnapshotError::NonMinimalVarInt);
            }
            n += 1;
        } else {
            return Ok((n, bytes));
        }
    }
}

fn read_script_pubkey<R: Read>(reader: &mut R) -> Result<Vec<u8>, SnapshotError> {
    let (size, _) = read_varint_with_bytes(reader)?;
    match size {
        0 => {
            let mut hash = [0u8; 20];
            read_exact(reader, &mut hash, "p2pkh hash")?;
            let mut script = Vec::with_capacity(25);
            script.extend_from_slice(&[0x76, 0xa9, 0x14]);
            script.extend_from_slice(&hash);
            script.extend_from_slice(&[0x88, 0xac]);
            Ok(script)
        }
        1 => {
            let mut hash = [0u8; 20];
            read_exact(reader, &mut hash, "p2sh hash")?;
            let mut script = Vec::with_capacity(23);
            script.extend_from_slice(&[0xa9, 0x14]);
            script.extend_from_slice(&hash);
            script.push(0x87);
            Ok(script)
        }
        2 | 3 => {
            let mut x = [0u8; 32];
            read_exact(reader, &mut x, "compressed p2pk x")?;
            let mut script = Vec::with_capacity(35);
            script.push(0x21);
            script.push(size as u8);
            script.extend_from_slice(&x);
            script.push(0xac);
            Ok(script)
        }
        4 | 5 => {
            let mut x = [0u8; 32];
            read_exact(reader, &mut x, "uncompressed p2pk x")?;
            let mut compressed = [0u8; 33];
            compressed[0] = (size - 2) as u8;
            compressed[1..].copy_from_slice(&x);
            let public_key = k256::PublicKey::from_sec1_bytes(&compressed)
                .map_err(|_| SnapshotError::InvalidCompressedPubkey)?;
            let encoded = public_key.to_encoded_point(false);
            let uncompressed = encoded.as_bytes();
            if uncompressed.len() != 65 {
                return Err(SnapshotError::InvalidCompressedPubkey);
            }
            let mut script = Vec::with_capacity(67);
            script.push(0x41);
            script.extend_from_slice(uncompressed);
            script.push(0xac);
            Ok(script)
        }
        n => {
            let len = n - NUM_SPECIAL_SCRIPTS;
            if len > MAX_SCRIPT_SIZE {
                return Err(SnapshotError::ScriptTooLarge(len));
            }
            let mut script = vec![0u8; len as usize];
            read_exact(reader, &mut script, "raw script")?;
            Ok(script)
        }
    }
}

pub fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    x -= 1;
    let mut e = x % 10;
    x /= 10;

    let mut n = if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        x * 10 + d
    } else {
        x + 1
    };

    while e > 0 {
        n *= 10;
        e -= 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGTEST_FIXTURE: &str = "../fixtures/txoutset_regtest_111.dat";
    const REGTEST_MUHASH: &str = "5b93564046e31a3798231c767eb24e45dd818b77ae022cbe8861e2af9d4a8c09";

    #[test]
    fn reads_regtest_fixture_header() {
        let snapshot = SnapshotReader::open(REGTEST_FIXTURE).expect("open fixture");
        let header = snapshot.header();
        assert_eq!(header.network_magic, REGTEST_MAGIC);
        assert_eq!(header.coin_count, 115);
        assert_eq!(
            header.base_hash_display_hex(),
            "4e4003e955a41b187ad32e26fc837a98ca284df84ca3bbea19e6d164b3ebb3e7"
        );
    }

    #[test]
    fn regtest_fixture_muhash_matches_core() {
        let report = verify_muhash(REGTEST_FIXTURE, REGTEST_MUHASH).expect("verify muhash");
        assert_eq!(report.coins, 115);
        assert_eq!(report.muhash_display_hex, REGTEST_MUHASH);
    }

    #[test]
    fn core_varint_vectors() {
        let cases = [
            (0, &[0x00][..]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x00]),
            (255, &[0x80, 0x7f]),
            (256, &[0x81, 0x00]),
            (16_383, &[0xfe, 0x7f]),
            (16_384, &[0xff, 0x00]),
            (16_511, &[0xff, 0x7f]),
            (65_535, &[0x82, 0xfe, 0x7f]),
            (1u64 << 32, &[0x8e, 0xfe, 0xfe, 0xff, 0x00]),
        ];
        for (n, bytes) in cases {
            let (got, encoded) = read_varint_with_bytes(&mut &bytes[..]).expect("decode");
            assert_eq!(got, n);
            assert_eq!(encoded, bytes);
        }
    }

    #[test]
    fn amount_decompression_vectors() {
        for sats in [0, 1, 7, 9, 10, 90, 100, 200, 800, 900, 1000, 5_000_000_000] {
            assert_eq!(decompress_amount(compress_amount_for_test(sats)), sats);
        }
    }

    fn compress_amount_for_test(mut n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let mut e = 0;
        while n % 10 == 0 && e < 9 {
            n /= 10;
            e += 1;
        }
        if e < 9 {
            let d = n % 10;
            n /= 10;
            1 + (n * 9 + d - 1) * 10 + e
        } else {
            1 + (n - 1) * 10 + 9
        }
    }
}
