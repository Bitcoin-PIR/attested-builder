//! Bounded FFI transforms scattered into the existing coefficient-major table.

use super::*;

// At the pinned 2048/u64 shape this limits the FFI table to about 64 MiB.
const MAX_BATCH_ENTRIES: usize = 4096;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(super) fn write(
    input: &Path,
    output: &Path,
    options: &DataNttOptions,
    params: &onionpir::ParamsInfo,
    input_entries: u64,
    output_bytes: u64,
) -> Result<(), Error> {
    let mut input = BufReader::with_capacity(4 * 1024 * 1024, File::open(input)?);
    let path = temp_save_path_near(output)?;
    std::fs::create_dir(&path)?;
    let scratch = Scratch(path);
    let saved = scratch.0.join("batch.bin");
    let mut output_file = File::create_new(output)?;
    let result = (|| {
        // Newly extended file regions read as zero. In particular, do not copy
        // the pinned FFI's uninitialized shape-padding slots. Empty input still
        // uses params_info(0)'s default shape, but needs no server allocation.
        output_file.set_len(output_bytes)?;
        if input_entries == 0 {
            return Ok(());
        }
        // Keep the output tile large enough for efficient scattered writes.
        // push_batch_entries controls packing/push memory independently.
        let batch_size = MAX_BATCH_ENTRIES.min(input_entries as usize);
        let batch_params = onionpir::params_info(batch_size as u64);
        if batch_params.entry_size != params.entry_size
            || batch_params.poly_degree != params.poly_degree
            || batch_params.coeff_val_cnt != params.coeff_val_cnt
            || batch_params.rns_mod_count != params.rns_mod_count
            || batch_params.num_plaintexts < batch_size as u64
        {
            return Err(Error::InvalidOnionShape(
                "batch NTT parameters differ".into(),
            ));
        }
        let mut server = onionpir::Server::new(batch_size as u64);
        let row_bytes = batch_params.num_plaintexts as usize * 8;
        let mut row = vec![0; row_bytes];
        let mut entry_id = 0;
        while entry_id < input_entries {
            let count = batch_size.min((input_entries - entry_id) as usize);
            // Each polynomial's NTT depends only on the fixed cryptographic
            // parameters, not the number of entries or its database index.
            let mut pushed = 0;
            while pushed < count {
                let push_count = options.push_batch_entries.min(count - pushed);
                let mut raw = vec![0; push_count * params.entry_size as usize];
                input.read_exact(&mut raw)?;
                let mut coeffs = Vec::with_capacity(push_count * params.poly_degree as usize);
                for entry in raw.chunks_exact(params.entry_size as usize) {
                    coeffs.extend(pack_bytes_into_coefficients(
                        entry,
                        params.entry_size as usize,
                        params.poly_degree as usize,
                    ));
                }
                if !server.push_plaintexts(&coeffs, push_count as u64, pushed as u64, &[]) {
                    return Err(Error::FfiFailed("push_plaintexts"));
                }
                pushed += push_count;
            }
            if !server.save_db(&saved.to_string_lossy()) {
                return Err(Error::FfiFailed("save_db"));
            }
            let mut batch = BufReader::with_capacity(256 * 1024, File::open(&saved)?);
            validate_header(&mut batch, &batch_params)?;
            for coefficient in 0..params.coeff_val_cnt {
                batch.read_exact(&mut row)?;
                let offset = (coefficient * params.num_plaintexts + entry_id) * 8;
                output_file.seek(SeekFrom::Start(offset))?;
                output_file.write_all(&row[..count * 8])?;
            }
            entry_id += count as u64;
        }
        output_file.flush()?;
        Ok(())
    })();
    drop(output_file);
    if result.is_err() {
        let _ = std::fs::remove_file(output);
    }
    result
}

fn validate_header(
    batch: &mut BufReader<File>,
    params: &onionpir::ParamsInfo,
) -> Result<(), Error> {
    let payload_bytes = params.num_plaintexts * params.coeff_val_cnt * 8;
    let expected = [
        0x4F50_4952_5632_5F44u64,
        1,
        0,
        params.num_plaintexts,
        params.coeff_val_cnt,
        payload_bytes,
    ];
    let mut header = [0; ONION_SAVE_DB_HEADER_SIZE];
    batch.read_exact(&mut header)?;
    if header
        .chunks_exact(8)
        .zip(expected)
        .any(|(bytes, value)| u64::from_le_bytes(bytes.try_into().unwrap()) != value)
        || batch.get_ref().metadata()?.len() != ONION_SAVE_DB_HEADER_SIZE as u64 + payload_bytes
    {
        return Err(Error::InvalidOnionShape(
            "save_db header/size mismatch: expected standard coefficient-major u64 layout".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
