//! Fixed-width external sorting with bounded runs and merge fan-in.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

pub(super) struct Scratch(pub(super) PathBuf);

impl Scratch {
    pub(super) fn new(output: &Path) -> io::Result<Self> {
        let mut name = output.as_os_str().to_os_string();
        name.push(".sort");
        let path = PathBuf::from(name);
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub run_bytes: usize,
    pub fan_in: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            run_bytes: 64 * 1024 * 1024,
            fan_in: 16,
        }
    }
}

pub(super) fn reader(path: &Path) -> io::Result<BufReader<File>> {
    Ok(BufReader::with_capacity(256 * 1024, File::open(path)?))
}

pub(super) fn writer(path: &Path) -> io::Result<BufWriter<File>> {
    Ok(BufWriter::with_capacity(
        256 * 1024,
        File::create_new(path)?,
    ))
}

pub(super) fn read_record<const N: usize>(input: &mut impl BufRead) -> io::Result<Option<[u8; N]>> {
    if input.fill_buf()?.is_empty() {
        return Ok(None);
    }
    let mut record = [0; N];
    input.read_exact(&mut record)?;
    Ok(Some(record))
}

pub(super) struct Sorter<const N: usize> {
    dir: PathBuf,
    prefix: &'static str,
    limits: Limits,
    records: Vec<[u8; N]>,
    runs: Vec<PathBuf>,
}

impl<const N: usize> Sorter<N> {
    pub fn new(dir: &Path, prefix: &'static str, limits: Limits) -> Self {
        assert!(limits.run_bytes >= N && limits.fan_in >= 2);
        Self {
            dir: dir.to_path_buf(),
            prefix,
            limits,
            records: Vec::with_capacity(limits.run_bytes / N),
            runs: Vec::new(),
        }
    }

    pub fn push(&mut self, record: [u8; N]) -> io::Result<()> {
        self.records.push(record);
        if self.records.len() == self.limits.run_bytes / N {
            self.flush_run()?;
        }
        Ok(())
    }

    fn flush_run(&mut self) -> io::Result<()> {
        self.records.sort_unstable();
        let path = self
            .dir
            .join(format!("{}-0-{}", self.prefix, self.runs.len()));
        let mut output = writer(&path)?;
        for record in &self.records {
            output.write_all(record)?;
        }
        output.flush()?;
        self.runs.push(path);
        self.records.clear();
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<PathBuf> {
        if !self.records.is_empty() || self.runs.is_empty() {
            self.flush_run()?;
        }
        drop(self.records);
        let mut pass = 1;
        while self.runs.len() > 1 {
            let mut next = Vec::new();
            for (group, runs) in self.runs.chunks(self.limits.fan_in).enumerate() {
                if runs.len() == 1 {
                    next.push(runs[0].clone());
                    continue;
                }
                let path = self.dir.join(format!("{}-{pass}-{group}", self.prefix));
                merge::<N>(runs, &path)?;
                for run in runs {
                    fs::remove_file(run)?;
                }
                next.push(path);
            }
            self.runs = next;
            pass += 1;
        }
        Ok(self.runs.pop().unwrap())
    }
}

fn merge<const N: usize>(runs: &[PathBuf], path: &Path) -> io::Result<()> {
    let mut inputs: Vec<_> = runs.iter().map(|p| reader(p)).collect::<io::Result<_>>()?;
    let mut heap = BinaryHeap::new();
    for (i, input) in inputs.iter_mut().enumerate() {
        if let Some(record) = read_record::<N>(input)? {
            heap.push(Reverse((record, i)));
        }
    }
    let mut output = writer(path)?;
    while let Some(Reverse((record, i))) = heap.pop() {
        output.write_all(&record)?;
        if let Some(next) = read_record::<N>(&mut inputs[i])? {
            heap.push(Reverse((next, i)));
        }
    }
    output.flush()
}
