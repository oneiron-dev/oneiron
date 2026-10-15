//! Bytes of one exchange held whole before they move on: a push's command
//! section, read ahead of the backend to refuse a push certificate, and the
//! server's copy of a push's status report, held while its landing is
//! journaled.
//!
//! Both grow with the refs a push names, and a push may name any number of
//! them (rule 5), so holding them is never refused for their size. They stay
//! in memory up to a bound and go on in an unnamed file in the vault's door
//! root past it. The file is checked to have no name before a byte is
//! written, so nothing else can open it, and it is gone once its holder drops
//! it. Only the disk itself refuses: a write that fails, or a file that keeps
//! a name, fails the write.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Bytes held in memory up to a bound and in an unnamed file past it.
pub struct HeldBytes {
    memory: Vec<u8>,
    file: Option<BufWriter<File>>,
    /// Bytes held, wherever they are.
    len: u64,
    /// Bytes held in memory before the rest goes to disk.
    limit: usize,
    /// Where the rest goes; `None` when the door root could not be resolved,
    /// so bytes past memory fail to write.
    dir: Option<PathBuf>,
}

impl HeldBytes {
    /// Holds up to `limit` bytes in memory and the rest in an unnamed file in
    /// `dir` (normally [`origin_door_root`](super::origin_door_root)).
    #[must_use]
    pub fn new(limit: usize, dir: Option<PathBuf>) -> Self {
        Self {
            memory: Vec::new(),
            file: None,
            len: 0,
            limit,
            dir,
        }
    }

    /// An empty holder with the same memory bound and spill directory.
    #[must_use]
    pub fn sibling(&self) -> Self {
        Self::new(self.limit, self.dir.clone())
    }

    /// How many bytes are held.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Everything held, from its first byte.
    ///
    /// # Errors
    ///
    /// Flushing or rewinding the file the bytes spilled to.
    pub fn reader(&mut self) -> io::Result<Box<dyn Read + Send + '_>> {
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
            let written = file.write(bytes)?;
            self.len += written as u64;
            return Ok(written);
        }
        if bytes.len() <= self.limit.saturating_sub(self.memory.len()) {
            self.memory.extend_from_slice(bytes);
            self.len += bytes.len() as u64;
            return Ok(bytes.len());
        }
        let dir = self
            .dir
            .as_ref()
            .ok_or_else(|| io::Error::other("no directory to hold bytes in"))?;
        let file = tempfile::tempfile_in(dir)?;
        // Anonymity is checked on the open file, never assumed from a name's
        // removal: a file another name still links would keep the bytes
        // after the exchange.
        #[cfg(unix)]
        if std::os::unix::fs::MetadataExt::nlink(&file.metadata()?) != 0 {
            return Err(io::Error::other("the held bytes' file is still linked"));
        }
        let mut file = BufWriter::new(file);
        file.write_all(&std::mem::take(&mut self.memory))?;
        file.write_all(bytes)?;
        self.file = Some(file);
        self.len += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().map_or(Ok(()), Write::flush)
    }
}
