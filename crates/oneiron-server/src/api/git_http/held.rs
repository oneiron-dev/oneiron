//! A push's status report, held while its landing is journaled.
//!
//! The report grows with the refs a push names, and a push may name any
//! number of them (rule 5), so holding it is never refused for its size. It
//! stays in memory up to a bound sized from the machine's memory and goes on
//! in a file in the vault's door root past it. The file's name is removed
//! before a byte is written, so nothing else can open it, and it is gone once
//! the exchange drops it. Only the disk itself refuses: a write that fails, or
//! a name that cannot be removed, ends the push as a held failure.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

pub(super) struct HeldBytes {
    memory: Vec<u8>,
    file: Option<BufWriter<File>>,
    /// Bytes held in memory before the rest goes to disk.
    limit: usize,
    /// Where the rest goes; `None` when the door root could not be resolved,
    /// so a report past memory fails as a held failure.
    dir: Option<PathBuf>,
}

impl HeldBytes {
    pub(super) fn new(limit: usize, dir: Option<PathBuf>) -> Self {
        Self {
            memory: Vec::new(),
            file: None,
            limit,
            dir,
        }
    }

    /// An empty holder with the same memory bound and spill directory.
    pub(super) fn sibling(&self) -> Self {
        Self::new(self.limit, self.dir.clone())
    }

    /// Everything held, from its first byte.
    pub(super) fn reader(&mut self) -> io::Result<Box<dyn Read + '_>> {
        match &mut self.file {
            Some(file) => {
                file.flush()?;
                let file = file.get_mut();
                file.seek(SeekFrom::Start(0))?;
                Ok(Box::new(BufReader::new(file)))
            }
            None => Ok(Box::new(self.memory.as_slice())),
        }
    }
}

impl Write for HeldBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(file) = &mut self.file {
            return file.write(bytes);
        }
        if bytes.len() <= self.limit.saturating_sub(self.memory.len()) {
            self.memory.extend_from_slice(bytes);
            return Ok(bytes.len());
        }
        let dir = self
            .dir
            .as_ref()
            .ok_or_else(|| io::Error::other("no directory to hold a status report in"))?;
        // Removing the name is checked, never assumed: a name left behind
        // would keep the report findable after the exchange.
        let (file, name) = tempfile::NamedTempFile::new_in(dir)?.into_parts();
        name.close()?;
        let mut file = BufWriter::new(file);
        file.write_all(&std::mem::take(&mut self.memory))?;
        file.write_all(bytes)?;
        self.file = Some(file);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().map_or(Ok(()), Write::flush)
    }
}
