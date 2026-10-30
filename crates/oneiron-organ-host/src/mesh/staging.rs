//! Bytes one mesh connection stages, each way (FIX 6193). Each staged object
//! is spilled to an unnamed file of its own as its pieces come in, or as it
//! is offered, so what a connection stages takes disk, not memory, and no
//! count or size of it is refused (Rule 5). A call reads its inputs back
//! into memory after leasing them from the machine's floor (`serve.rs`).

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron_organ_protocol::{ByteBuf, Hash32};

use super::{Carried, INLINE, PIECE};

/// One staged object: its unnamed file and the bytes written to it.
#[derive(Debug)]
struct Spilled {
    file: File,
    len: u64,
}

/// Bytes a connection staged, each way.
#[derive(Debug)]
pub(crate) struct Staging {
    /// Where spill files are made: the host's measured spool disk when its
    /// vault was lent one, else the system's temporary directory.
    dir: PathBuf,
    /// Objects the peer put, by hash, their pieces in order.
    incoming: Mutex<HashMap<Hash32, Spilled>>,
    /// Objects this side named in a reply, for the peer to get.
    outgoing: Mutex<HashMap<Hash32, Arc<Spilled>>>,
}

impl Staging {
    /// Staging whose spill files are made in `dir`.
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            incoming: Mutex::default(),
            outgoing: Mutex::default(),
        }
    }

    /// A new unnamed file in the spill directory: readable by this process
    /// alone, and unlinked at once, so it goes when its last handle closes.
    fn spill_file(&self) -> Result<File, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = self.dir.join(format!(
                "oneiron-organ-mesh-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => {
                    std::fs::remove_file(&path).map_err(spill_error)?;
                    return Ok(file);
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(spill_error(err)),
            }
        }
    }

    /// Takes one piece the peer put. Pieces of one hash come in order.
    pub(crate) fn put(
        &self,
        hash: Hash32,
        total: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), String> {
        let mut incoming = lock(&self.incoming);
        let held = match incoming.entry(hash) {
            Entry::Occupied(held) => held.into_mut(),
            Entry::Vacant(vacant) => vacant.insert(Spilled {
                file: self.spill_file()?,
                len: 0,
            }),
        };
        if held.len == total && offset == 0 {
            // Already whole: the same bytes, put again.
            return Ok(());
        }
        if held.len != offset || offset.saturating_add(bytes.len() as u64) > total {
            return Err("a staged piece out of order".into());
        }
        held.file.write_all_at(bytes, offset).map_err(spill_error)?;
        held.len += bytes.len() as u64;
        Ok(())
    }

    /// The bytes `carried` names: inline, or put whole and matching its hash,
    /// read back from their file, which stays for a later call naming them.
    pub(crate) fn take(&self, carried: &Carried) -> Result<Vec<u8>, String> {
        match carried {
            Carried::Inline(bytes) => Ok(bytes.to_vec()),
            Carried::Staged { hash, len } => {
                let incoming = lock(&self.incoming);
                let held = incoming
                    .get(hash)
                    .filter(|held| held.len == *len)
                    .ok_or("staged bytes missing or incomplete")?;
                let mut bytes =
                    vec![0; usize::try_from(*len).map_err(|_| "staged bytes too long")?];
                held.file
                    .read_exact_at(&mut bytes, 0)
                    .map_err(spill_error)?;
                if Hash32::of(&bytes) != *hash {
                    return Err("staged bytes do not match their hash".into());
                }
                Ok(bytes)
            }
        }
    }

    /// Names bytes for a reply: inline when small, else spilled to a file of
    /// their own for the peer to get in pieces.
    pub(crate) fn offer(&self, bytes: &[u8]) -> Result<Carried, String> {
        if bytes.len() <= INLINE {
            return Ok(Carried::Inline(ByteBuf::from(bytes.to_vec())));
        }
        let hash = Hash32::of(bytes);
        let len = bytes.len() as u64;
        let file = self.spill_file()?;
        file.write_all_at(bytes, 0).map_err(spill_error)?;
        lock(&self.outgoing).insert(hash, Arc::new(Spilled { file, len }));
        Ok(Carried::Staged { hash, len })
    }

    /// One piece of bytes this side offered, read from their file.
    pub(crate) fn piece(&self, hash: Hash32, offset: u64) -> Result<ByteBuf, String> {
        let spilled = lock(&self.outgoing)
            .get(&hash)
            .cloned()
            .ok_or("no such staged bytes")?;
        if offset >= spilled.len {
            return Err("a piece past the end".into());
        }
        let end = offset.saturating_add(PIECE as u64).min(spilled.len);
        let mut bytes = vec![0; usize::try_from(end - offset).map_err(|_| "a piece too long")?];
        spilled
            .file
            .read_exact_at(&mut bytes, offset)
            .map_err(spill_error)?;
        Ok(ByteBuf::from(bytes))
    }
}

/// A spill file's failure, as the peer reads it.
fn spill_error(err: io::Error) -> String {
    format!("staging spill: {err}")
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
