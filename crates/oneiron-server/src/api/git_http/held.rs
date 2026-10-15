//! A push's status report, held while its landing is journaled.
//!
//! The report grows with the refs a push names, and a push may name any
//! number of them (rule 5), so holding it is never refused for its size. It
//! stays in memory up to a bound sized from the machine's memory and goes on
//! in an unnamed file in the vault's door root past it. The file has no name
//! anything else can open, and it is gone once the exchange drops it. Only
//! the disk itself refuses: a write that fails ends the push as a held
//! failure.

use axum::body::{Body, Bytes};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use tokio::io::AsyncReadExt;

/// The largest piece a held report is streamed back in.
const HELD_BODY_PIECE: usize = 64 * 1024;

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

    /// The held bytes as a response body: from memory whole, from disk in
    /// pieces. The file goes with the body.
    pub(super) fn into_body(self) -> io::Result<Body> {
        let Some(file) = self.file else {
            return Ok(Body::from(self.memory));
        };
        let mut file = file.into_inner().map_err(io::IntoInnerError::into_error)?;
        file.seek(SeekFrom::Start(0))?;
        let file = tokio::fs::File::from_std(file);
        let pieces = futures_util::stream::try_unfold(file, |mut file| async move {
            let mut piece = vec![0; HELD_BODY_PIECE];
            let read = file.read(&mut piece).await?;
            if read == 0 {
                return Ok::<_, io::Error>(None);
            }
            piece.truncate(read);
            Ok(Some((Bytes::from(piece), file)))
        });
        Ok(Body::from_stream(pieces))
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
        let mut file = BufWriter::new(tempfile::tempfile_in(dir)?);
        file.write_all(&std::mem::take(&mut self.memory))?;
        file.write_all(bytes)?;
        self.file = Some(file);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().map_or(Ok(()), Write::flush)
    }
}
