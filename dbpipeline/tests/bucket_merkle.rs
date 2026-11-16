use dbpipeline::*;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

// Frozen from the pre-streaming implementation, before changing the reader or
// writer. These cover every output byte, including sibling padding and headers.
const GOLDEN: &[(&str, &str)] = &[
    (
        "merkle_bucket_chunk_sib_L0.bin",
        "2c3675ee4cfc5f4530681c3310e868ea26da5eeebfc6236c801473a05ec92e46",
    ),
    (
        "merkle_bucket_index_sib_L0.bin",
        "58bc7db269072b4147bdaccb728646dd4c54988ad6dd1f049c86edf9e4526977",
    ),
    (
        "merkle_bucket_root.bin",
        "a777060c27458f801d707233ddd0356bdc053bbf2b97d2d64136301e8b3bdbf5",
    ),
    (
        "merkle_bucket_roots.bin",
        "65a86dbdd60af91aad3680d7ed49896651813306dc0a3d79b17f37b6ad4234fc",
    ),
    (
        "merkle_bucket_tree_tops.bin",
        "80c31b96dfeb2f2a0c8a17e26378f1352bd9005d585ca89ab99bcc4a90520f01",
    ),
];
const SUPER_ROOT: &str = "65a86dbdd60af91aad3680d7ed49896651813306dc0a3d79b17f37b6ad4234fc";

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_table(path: &Path, index: bool, anchor_bytes: usize) {
    let (magic, k, slots, slot_size, header_size) = if index {
        (
            INDEX_CUCKOO_MAGIC,
            INDEX_K,
            INDEX_SLOTS_PER_BIN,
            INDEX_SLOT_SIZE,
            INDEX_CUCKOO_HEADER_SIZE,
        )
    } else {
        (
            CHUNK_CUCKOO_MAGIC,
            CHUNK_K,
            CHUNK_SLOTS_PER_BIN,
            CHUNK_SLOT_SIZE,
            CHUNK_CUCKOO_HEADER_SIZE,
        )
    };
    let magic = magic
        ^ match anchor_bytes {
            0 => 0,
            CHAIN_ANCHOR_BYTES => ANCHOR_MAGIC_SNAPSHOT_XOR,
            DELTA_ANCHOR_BYTES => ANCHOR_MAGIC_DELTA_XOR,
            _ => unreachable!(),
        };
    let mut header = vec![0xa5; header_size + anchor_bytes];
    header[..8].copy_from_slice(&magic.to_le_bytes());
    header[8..12].copy_from_slice(&(k as u32).to_le_bytes());
    header[12..16].copy_from_slice(&(slots as u32).to_le_bytes());
    // One more than the tree-top cutoff exercises sibling files and partial rows.
    header[16..20].copy_from_slice(&8193u32.to_le_bytes());
    header[20..24].copy_from_slice(&3u32.to_le_bytes());
    let mut writer = BufWriter::new(File::create(path).unwrap());
    writer.write_all(&header).unwrap();
    let mut bin = vec![0; slots * slot_size];
    for group in 0..k {
        for bucket in 0..8193usize {
            for (offset, byte) in bin.iter_mut().enumerate() {
                *byte = (group * 17 + bucket * 31 + offset * 7) as u8;
            }
            writer.write_all(&bin).unwrap();
        }
    }
    writer.flush().unwrap();
}

#[test]
fn bucket_merkle_compatibility() {
    let dir = std::env::temp_dir().join(format!("bpir-bucket-merkle-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let fixture = Fixture(dir);
    let index = fixture.0.join("index.bin");
    let chunk = fixture.0.join("chunk.bin");
    for anchor_bytes in [0, CHAIN_ANCHOR_BYTES, DELTA_ANCHOR_BYTES] {
        write_table(&index, true, anchor_bytes);
        write_table(&chunk, false, anchor_bytes);
        let out = fixture.0.join(format!("merkle-{anchor_bytes}"));
        let report = build_bucket_merkle(&index, &chunk, &out).unwrap();
        assert_eq!(hex::encode(report.super_root), SUPER_ROOT);
        assert_eq!(report.index_sibling_levels, vec![1025]);
        assert_eq!(report.chunk_sibling_levels, vec![1025]);
        assert_eq!(fs::read_dir(&out).unwrap().count(), GOLDEN.len());
        for &(name, hash) in GOLDEN {
            assert_eq!(
                hex::encode(Sha256::digest(fs::read(out.join(name)).unwrap())),
                hash,
                "{name}, anchor_bytes={anchor_bytes}",
            );
        }
        assert_eq!(
            report.tree_tops_file_bytes,
            fs::metadata(out.join(MERKLE_BUCKET_TREE_TOPS_FILENAME))
                .unwrap()
                .len()
        );
        assert_eq!(
            report.roots_file_bytes,
            ((INDEX_K + CHUNK_K) * MERKLE_HASH_SIZE) as u64
        );
    }

    let out = fixture.0.join("root-only");
    let report = build_bucket_merkle_with_options(
        &index,
        &chunk,
        &out,
        &BucketMerkleOptions { root_only: true },
    )
    .unwrap();
    assert_eq!(hex::encode(report.super_root), SUPER_ROOT);
    assert_eq!(report.tree_tops_file_bytes, 0);
    assert_eq!(report.roots_file_bytes, 0);
    assert_eq!(fs::read_dir(&out).unwrap().count(), 1);

    // Reject malformed/truncated input before publishing any output files.
    let chunk_len = fs::metadata(&chunk).unwrap().len();
    for length in [chunk_len - 1, chunk_len + 1] {
        File::options()
            .write(true)
            .open(&chunk)
            .unwrap()
            .set_len(length)
            .unwrap();
        let out = fixture.0.join(format!("bad-body-{length}"));
        assert!(matches!(
            build_bucket_merkle(&index, &chunk, &out),
            Err(PipelineError::InvalidCuckooBody { .. })
        ));
        assert_eq!(fs::read_dir(out).unwrap().count(), 0);
    }
    fs::write(&index, b"short header").unwrap();
    let out = fixture.0.join("bad-header");
    assert!(matches!(
        build_bucket_merkle(&index, &chunk, &out),
        Err(PipelineError::InvalidCuckooHeader { .. })
    ));
    assert_eq!(fs::read_dir(out).unwrap().count(), 0);
}
