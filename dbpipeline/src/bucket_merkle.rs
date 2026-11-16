//! Sequential bucket hashing; only one group's Merkle tree is retained at a time.

use super::*;
use std::io::{Seek, SeekFrom};

pub(super) struct Input {
    reader: BufReader<File>,
    pub(super) meta: CuckooTableMeta,
    bin_size: usize,
}

impl Input {
    pub(super) fn open(
        path: &Path,
        magic: u64,
        header_size: usize,
        k: usize,
        slots: usize,
        hashes: usize,
        slot_size: usize,
    ) -> Result<Self, PipelineError> {
        let mut file = File::open(path)?;
        let mut header = Vec::new();
        (&mut file)
            .take((header_size + DELTA_ANCHOR_BYTES) as u64)
            .read_to_end(&mut header)?;
        let meta = parse_cuckoo_meta(path, &header, magic, header_size, k, slots, hashes)?;
        let bin_size = slots * slot_size;
        validate_cuckoo_body(path, file.metadata()?.len() as usize, &meta, k, bin_size)?;
        file.seek(SeekFrom::Start(meta.header_size as u64))?;
        Ok(Self {
            reader: BufReader::with_capacity(1024 * 1024, file),
            meta,
            bin_size,
        })
    }

    fn read_tree(&mut self) -> Result<PerGroupTree, PipelineError> {
        let mut bin = vec![0; self.bin_size];
        let mut leaves = Vec::with_capacity(self.meta.bins_per_table);
        for bin_index in 0..self.meta.bins_per_table {
            self.reader.read_exact(&mut bin)?;
            leaves.push(compute_bin_leaf_hash(bin_index as u32, &bin));
        }
        Ok(build_merkle_group_tree(leaves, MERKLE_ARITY))
    }
}

pub(super) fn build(
    index: &mut Input,
    chunk: &mut Input,
    out_dir: &Path,
    index_sibling_levels: &[usize],
    chunk_sibling_levels: &[usize],
    options: &BucketMerkleOptions,
) -> Result<BucketMerkleBuildReport, PipelineError> {
    let tops_path = temp_path(&out_dir.join(MERKLE_BUCKET_TREE_TOPS_FILENAME));
    let mut tops = if options.root_only {
        None
    } else {
        let mut writer = BufWriter::with_capacity(1024 * 1024, File::create_new(&tops_path)?);
        writer.write_all(&((INDEX_K + CHUNK_K) as u32).to_le_bytes())?;
        Some(writer)
    };
    let mut roots = Vec::with_capacity(INDEX_K + CHUNK_K);

    for (input, sibling_levels, k, table_type) in [
        (&mut *index, index_sibling_levels, INDEX_K, 0),
        (&mut *chunk, chunk_sibling_levels, CHUNK_K, 1),
    ] {
        let mut siblings = Vec::new();
        if !options.root_only {
            for (level, &rows) in sibling_levels.iter().enumerate() {
                let name = if table_type == 0 {
                    merkle_index_sibling_filename(level)
                } else {
                    merkle_chunk_sibling_filename(level)
                };
                let mut writer = BufWriter::with_capacity(
                    64 * 1024,
                    File::create_new(temp_path(&out_dir.join(name)))?,
                );
                writer.write_all(&bucket_sib_magic(table_type, level as u8).to_le_bytes())?;
                writer.write_all(&(k as u32).to_le_bytes())?;
                writer.write_all(&1u32.to_le_bytes())?;
                writer.write_all(&(rows as u32).to_le_bytes())?;
                writer.write_all(&0u32.to_le_bytes())?;
                writer.write_all(&0u64.to_le_bytes())?;
                siblings.push(writer);
            }
        }

        for _ in 0..k {
            let tree = input.read_tree()?;
            for (level, writer) in siblings.iter_mut().enumerate() {
                let hashes = &tree.levels[level];
                for row in 0..sibling_levels[level] {
                    for child in 0..MERKLE_ARITY {
                        let hash = hashes.get(row * MERKLE_ARITY + child).unwrap_or(&ZERO_HASH);
                        writer.write_all(hash)?;
                    }
                }
            }
            if let Some(writer) = &mut tops {
                write_one_tree_top(writer, &tree, sibling_levels.len())?;
            }
            roots.push(tree.root);
        }
        for writer in &mut siblings {
            writer.flush()?;
        }
    }

    let tree_tops_file_bytes = if let Some(mut writer) = tops {
        writer.flush()?;
        std::fs::metadata(&tops_path)?.len()
    } else {
        0
    };
    let roots_file_bytes = if options.root_only {
        0
    } else {
        let roots_path = temp_path(&out_dir.join(MERKLE_BUCKET_ROOTS_FILENAME));
        write_roots(&roots_path, &roots)?;
        std::fs::metadata(&roots_path)?.len()
    };
    let mut super_preimage = Vec::with_capacity(roots.len() * MERKLE_HASH_SIZE);
    for root in &roots {
        super_preimage.extend_from_slice(root);
    }
    let super_root = sha256(&super_preimage);
    std::fs::write(
        temp_path(&out_dir.join(MERKLE_BUCKET_ROOT_FILENAME)),
        super_root,
    )?;

    Ok(BucketMerkleBuildReport {
        index_bins_per_table: index.meta.bins_per_table as u32,
        chunk_bins_per_table: chunk.meta.bins_per_table as u32,
        index_sibling_levels: index_sibling_levels.iter().map(|&n| n as u32).collect(),
        chunk_sibling_levels: chunk_sibling_levels.iter().map(|&n| n as u32).collect(),
        tree_count: (INDEX_K + CHUNK_K) as u32,
        tree_tops_file_bytes,
        roots_file_bytes,
        super_root,
    })
}
