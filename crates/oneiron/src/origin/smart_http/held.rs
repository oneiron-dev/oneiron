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
//! it. Only the disk refuses: a write to the file that would take the disk
//! below the floor its host keeps ([`SpillFloor`]), a write that fails, or a
//! file that keeps a name, fails the write.
//!
//! A wiping holder ([`HeldBytes::wiping`]) holds bytes that must not
//! outlive it, a marked push's plans (FIX 8030): its memory grows into a
//! fresh buffer and wipes the old one, reads back unbuffered, and on drop
//! wipes its memory and its file's buffer and overwrites the file with
//! zeros before truncating it.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;

use zeroize::Zeroize;

/// The free disk a host keeps under what its exchanges hold past memory:
/// asked before each write reaches a holder's file. The write claims nothing,
/// so writes asking at the same moment can each pass it by their own bytes.
pub trait SpillFloor: Send + Sync {
    /// Whether `bytes` more may be written and still leave the floor free.
    fn has_room_for(&self, bytes: u64) -> bool;

    /// A directory on the disk this floor measures, for a spool that names
    /// none of its own; `None` names none, and such a spool goes in the
    /// host's temp dir.
    fn spool_dir(&self) -> Option<PathBuf> {
        None
    }
}

/// Why a write to a holder's file was refused: the disk is at its host's
/// [`SpillFloor`]. It comes as an [`io::ErrorKind::StorageFull`] error, so a
/// caller that looks for it can tell the floor from a full disk.
#[derive(Debug)]
pub struct AtDiskFloor;

impl AtDiskFloor {
    /// Whether `error` is this refusal.
    #[must_use]
    pub fn is_in(error: &io::Error) -> bool {
        matches!(error.get_ref(), Some(inner) if inner.is::<Self>())
    }
}

impl std::fmt::Display for AtDiskFloor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the disk is at its free-space floor")
    }
}

impl std::error::Error for AtDiskFloor {}

/// Bytes held in memory up to a bound and in an unnamed file past it.
pub struct HeldBytes {
    memory: Vec<u8>,
    file: Option<BufWriter<FloorFile>>,
    /// Bytes held, wherever they are.
    len: u64,
    /// Bytes held in memory before the rest goes to disk.
    limit: usize,
    /// Where the rest goes; `None` when the door root could not be resolved,
    /// so bytes past memory fail to write.
    dir: Option<PathBuf>,
    /// The floor every write to the file keeps; `None` keeps none.
    floor: Option<Arc<dyn SpillFloor>>,
    /// Whether no copy of the bytes outlives the holder.
    wipe: bool,
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
            floor: None,
            wipe: false,
        }
    }

    /// This holder, leaving no copy of its bytes in memory or on disk once
    /// it drops (FIX 8030).
    #[must_use]
    pub fn wiping(mut self) -> Self {
        self.wipe = true;
        self
    }

    /// This holder, keeping `floor` under every write to its file.
    #[must_use]
    pub fn with_floor(mut self, floor: Option<Arc<dyn SpillFloor>>) -> Self {
        self.floor = floor;
        self
    }

    /// An empty holder with the same memory bound, spill directory and floor.
    #[must_use]
    pub fn sibling(&self) -> Self {
        let mut sibling = Self::new(self.limit, self.dir.clone()).with_floor(self.floor.clone());
        sibling.wipe = self.wipe;
        sibling
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
                let file = &mut file.get_mut().file;
                file.seek(SeekFrom::Start(0))?;
                if self.wipe {
                    return Ok(Box::new(file));
                }
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
            if self.wipe && self.memory.capacity() - self.memory.len() < bytes.len() {
                // A grown buffer would free the old one unwiped.
                let wanted = (self.memory.len() + bytes.len())
                    .max(self.memory.capacity().saturating_mul(2))
                    .min(self.limit);
                let mut grown = Vec::with_capacity(wanted);
                grown.extend_from_slice(&self.memory);
                std::mem::replace(&mut self.memory, grown).zeroize();
            }
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
        // Held before a byte reaches it, so a failed write still drops
        // through this holder's wipe.
        let file = self.file.insert(BufWriter::new(FloorFile {
            file,
            floor: self.floor.clone(),
        }));
        let mut spilled = std::mem::take(&mut self.memory);
        let moved = file
            .write_all(&spilled)
            .and_then(|()| file.write_all(bytes));
        if self.wipe {
            spilled.zeroize();
        }
        moved?;
        self.len += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().map_or(Ok(()), Write::flush)
    }
}

impl Drop for HeldBytes {
    fn drop(&mut self) {
        if !self.wipe {
            return;
        }
        self.memory.zeroize();
        let Some(file) = self.file.take() else {
            return;
        };
        let (file, buffered) = file.into_parts();
        match buffered {
            Ok(mut buffered) => buffered.zeroize(),
            Err(panicked) => panicked.into_inner().zeroize(),
        }
        if let Err(error) = overwrite_then_truncate(file.file) {
            tracing::warn!(%error, "a wiping holder's file was not overwritten");
        }
    }
}

/// Writes zeros over every byte `file` holds, then truncates it, so the
/// disk keeps none of them once the unnamed file is gone.
fn overwrite_then_truncate(mut file: File) -> io::Result<()> {
    const ZEROS: [u8; 8192] = [0; 8192];
    let mut left = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    while left > 0 {
        let step = usize::try_from(left).map_or(ZEROS.len(), |left| left.min(ZEROS.len()));
        file.write_all(&ZEROS[..step])?;
        left -= step as u64;
    }
    file.sync_data()?;
    file.set_len(0)
}

/// A holder's file, under its buffer: every write that reaches the file,
/// a buffer's drain on flush, read-back or drop included, asks the floor for
/// its bytes first.
struct FloorFile {
    file: File,
    floor: Option<Arc<dyn SpillFloor>>,
}

impl Write for FloorFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .floor
            .as_ref()
            .is_some_and(|floor| !floor.has_room_for(bytes.len() as u64))
        {
            return Err(io::Error::new(io::ErrorKind::StorageFull, AtDiskFloor));
        }
        self.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
