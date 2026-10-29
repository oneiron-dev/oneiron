//! Voice bytes that outgrow memory, spilled (FIX 3728): a live hearing's
//! queued, held and replayed audio, and the voice wires' inbound frames,
//! held in memory up to the result-body inline bound
//! (`[limits] code_result_inline_bytes`) and past it in the substrate's
//! never-published spill, as one render's PCM is (voxcpm2's `PcmSpool`):
//! a temp file in the vault's body directory, sealed under a key held in
//! memory only on a sealed vault, its name unlinked as soon as it opens.
//! No row ever names it, and it goes when its last descriptor drops.
//! Nothing is refused or dropped for its size (Rule 5): a spill that
//! cannot be written keeps its bytes in memory instead, and a spill that
//! left the disk below `[limits] code_result_disk_floor_bytes` asks that
//! row's question and serves all the same.

use crate::Vault;
use crate::error::Result;
use crate::limit_ask::EngineLimit;
use crate::store::{BodyDir, BodyFile, BodySpill};

/// Where a hearing's or a wire's bytes spill: the vault's body directory
/// and its inline bound. One spool per hearing or connection; the queues
/// it feeds keep their own count of the bytes still held inline against
/// the same bound.
pub struct AudioSpool {
    /// No directory (it would not open) spills nothing: every payload is
    /// held in memory, served as it was before spilling existed.
    dir: Option<BodyDir>,
    inline_limit: u64,
}

impl AudioSpool {
    /// A spool into `vault`'s body directory, spilling past its
    /// result-body inline bound.
    ///
    /// # Errors
    ///
    /// The body directory's own.
    pub fn new(vault: &Vault) -> Result<Self> {
        Ok(Self {
            dir: Some(vault.store.body_dir()?),
            inline_limit: vault.code_result_inline_bytes(),
        })
    }

    /// A spool that spills nothing, for a body directory that would not
    /// open: the hearing or connection it feeds is still served, its
    /// bytes held in memory as they always were.
    #[must_use]
    pub fn unspilled(vault: &Vault) -> Self {
        Self {
            dir: None,
            inline_limit: vault.code_result_inline_bytes(),
        }
    }

    /// The most bytes one queue holds in memory before it spills.
    #[must_use]
    pub fn inline_limit(&self) -> u64 {
        self.inline_limit
    }

    /// Takes one whole payload: in memory, or spilled when `spill` asks.
    /// A spill that cannot be written keeps the payload in memory: audio
    /// is never refused or dropped because the disk would not take it.
    pub fn take(&self, vault: &Vault, bytes: Vec<u8>, spill: bool) -> SpilledAudio {
        if spill && !bytes.is_empty() && self.dir.is_some() {
            match self.spill(&bytes) {
                Ok(file) => {
                    self.ask_floor(vault);
                    return SpilledAudio {
                        len: bytes.len() as u64,
                        skip: 0,
                        stored: Stored::Spilled(file),
                    };
                }
                Err(error) => {
                    tracing::warn!(%error, "audio kept in memory; its spill was not written");
                }
            }
        }
        SpilledAudio::inline(bytes)
    }

    /// `bytes` in an unnamed spill, read through its descriptor.
    fn spill(&self, bytes: &[u8]) -> Result<BodyFile> {
        // Only called with a directory (`take` checks); `None` here keeps
        // the payload in memory through `take`'s error arm.
        let Some(dir) = &self.dir else {
            return Err(crate::error::Error::InvariantViolation(
                "an unspilled spool has no spill directory",
            ));
        };
        let mut spill = BodySpill::ephemeral(dir)?;
        // Unnamed at once: only this descriptor reaches the file from
        // here, and a crash leaves nothing behind.
        dir.discard(spill.temp());
        spill.write(bytes)?;
        let digest = *blake3::hash(bytes).as_bytes();
        spill.finish(&digest, bytes.len() as u64)?.reader()
    }

    /// A spill that left the disk below its floor asks, and serves.
    fn ask_floor(&self, vault: &Vault) {
        if let Some(dir) = &self.dir
            && let Ok(free_bytes) = dir.free_bytes()
        {
            vault
                .limit_watch()
                .floor(EngineLimit::CodeResultDiskFloorBytes, free_bytes);
        }
    }
}

enum Stored {
    Inline(Vec<u8>),
    /// The unlinked spill, read through its descriptor.
    Spilled(BodyFile),
}

/// One audio payload a queue holds: its bytes in memory, or spilled past
/// the queue's inline bound. Bytes made final leave from the front
/// without the rest being read back.
pub struct SpilledAudio {
    /// The payload's whole length; `skip` of it has left from the front.
    len: u64,
    skip: u64,
    stored: Stored,
}

impl SpilledAudio {
    /// A payload held in memory whole.
    #[must_use]
    pub fn inline(bytes: Vec<u8>) -> Self {
        Self {
            len: bytes.len() as u64,
            skip: 0,
            stored: Stored::Inline(bytes),
        }
    }

    /// The bytes still held: the payload past what left from the front.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len - self.skip
    }

    /// Whether nothing is still held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes this payload holds in memory now, for its queue's count
    /// against the inline bound; nothing once spilled.
    #[must_use]
    pub fn inline_bytes(&self) -> u64 {
        match &self.stored {
            Stored::Inline(_) => self.len(),
            Stored::Spilled(_) => 0,
        }
    }

    /// The bytes still held, read back whole.
    ///
    /// # Errors
    ///
    /// A spilled payload's read error.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        match &self.stored {
            Stored::Inline(bytes) => Ok(bytes[self.skip as usize..].to_vec()),
            Stored::Spilled(file) => {
                file.read_range(self.skip, usize::try_from(self.len()).unwrap_or(usize::MAX))
            }
        }
    }

    /// Lets `count` bytes at the front go, unread: audio made final.
    pub fn trim_front(&mut self, count: u64) {
        self.skip = self.skip.saturating_add(count).min(self.len);
    }

    /// The front `count` bytes still held, read back; the rest stays.
    ///
    /// # Errors
    ///
    /// A spilled payload's read error.
    pub fn split_front(&mut self, count: u64) -> Result<Vec<u8>> {
        let count = count.min(self.len());
        let front = match &self.stored {
            Stored::Inline(bytes) => {
                bytes[self.skip as usize..(self.skip + count) as usize].to_vec()
            }
            Stored::Spilled(file) => {
                file.read_range(self.skip, usize::try_from(count).unwrap_or(usize::MAX))?
            }
        };
        self.skip += count;
        Ok(front)
    }
}

/// One inbound frame as it arrives: in memory up to the spool's inline
/// bound, past it into an unlinked spill, and read back whole when its
/// newline comes. The partial frame a cancelled read leaves stays in the
/// frame, spilled or not.
pub struct SpilledFrame {
    inline: Vec<u8>,
    spill: Option<BodySpill>,
    /// A spill that would not open: the frame stays in memory from here.
    spill_refused: bool,
    hasher: blake3::Hasher,
    len: u64,
}

impl SpilledFrame {
    /// A frame with nothing in it yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inline: Vec::new(),
            spill: None,
            spill_refused: false,
            hasher: blake3::Hasher::new(),
            len: 0,
        }
    }

    /// Whether the frame holds nothing yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Takes the frame's next bytes, spilling through `spool` once they
    /// pass its inline bound. A spill that cannot open leaves the frame
    /// in memory, still served; one that fails after it opened is this
    /// read's error, as a socket's is.
    ///
    /// # Errors
    ///
    /// An opened spill's write error.
    pub fn append(&mut self, spool: &AudioSpool, bytes: &[u8]) -> Result<()> {
        self.hasher.update(bytes);
        self.len = self.len.saturating_add(bytes.len() as u64);
        if let Some(spill) = &mut self.spill {
            return spill.write(bytes);
        }
        if self.spill_refused
            || (self.inline.len() as u64).saturating_add(bytes.len() as u64) <= spool.inline_limit
        {
            self.inline.extend_from_slice(bytes);
            return Ok(());
        }
        let Some(dir) = &spool.dir else {
            self.inline.extend_from_slice(bytes);
            return Ok(());
        };
        match BodySpill::ephemeral(dir) {
            Ok(mut spill) => {
                dir.discard(spill.temp());
                if let Err(error) = spill.write(&self.inline).and_then(|()| spill.write(bytes)) {
                    // The bytes are still here whole; keep them so.
                    tracing::warn!(%error, "frame kept in memory; its spill was not written");
                    self.spill_refused = true;
                    self.inline.extend_from_slice(bytes);
                    return Ok(());
                }
                self.inline = Vec::new();
                self.spill = Some(spill);
                Ok(())
            }
            Err(error) => {
                tracing::warn!(%error, "frame kept in memory; its spill did not open");
                self.spill_refused = true;
                self.inline.extend_from_slice(bytes);
                Ok(())
            }
        }
    }

    /// The whole frame: its bytes, or read back from its spill. A spill
    /// that left `vault`'s disk below its floor asks, and serves.
    ///
    /// # Errors
    ///
    /// The spill's seal or read error.
    pub fn finish(self, spool: &AudioSpool, vault: &Vault) -> Result<Vec<u8>> {
        match self.spill {
            None => Ok(self.inline),
            Some(spill) => {
                let digest = *self.hasher.finalize().as_bytes();
                let reader = spill.finish(&digest, self.len)?.reader()?;
                let bytes =
                    reader.read_range(0, usize::try_from(self.len).unwrap_or(usize::MAX))?;
                spool.ask_floor(vault);
                Ok(bytes)
            }
        }
    }
}

impl Default for SpilledFrame {
    fn default() -> Self {
        Self::new()
    }
}
