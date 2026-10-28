//! One render's PCM16LE result as it streams in from the worker (C058), here
//! and on the own-server VoxCPM2 speech rung (FIX 6122).
//! It is kept in memory up to the result-body inline bound
//! (`[limits] code_result_inline_bytes`). Past that bound it spills, as it
//! streams, through the result-body substrate's never-published spill: a
//! temp file in the vault's body directory, sealed under a key held in
//! memory only on a sealed vault. The temp name is unlinked as soon as the
//! spill opens. From then on only this process's descriptor reaches the
//! file, and the file goes when its body drops. No row, pin or custody key
//! ever names it, so no kept copy of the speech outlives its playback.
//! Nothing is refused for its length (Rule 5). A playback reads the result
//! back one window at a time.

use crate::Vault;
use crate::error::Result;
use crate::limit_ask::EngineLimit;
use crate::store::{BodyDir, BodyFile, BodySpill, LINE_INDEX_BLOCK_BYTES};

use super::invalid;

/// PCM bytes one playback window reads at once: the body store's own
/// frame, an even count, so each window holds whole samples.
pub(super) const PCM_WINDOW_BYTES: usize = LINE_INDEX_BLOCK_BYTES as usize;

/// One render submission's complete PCM16LE result, in memory or spilled.
pub struct VoxCpm2PcmBody {
    len: u64,
    stored: StoredPcm,
}

enum StoredPcm {
    Inline(Vec<u8>),
    /// The unlinked spill, read through its descriptor.
    Spilled(BodyFile),
}

impl From<Vec<u8>> for VoxCpm2PcmBody {
    /// A result held in memory whole.
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            len: bytes.len() as u64,
            stored: StoredPcm::Inline(bytes),
        }
    }
}

impl VoxCpm2PcmBody {
    /// The result's length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the result holds no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Up to `len` bytes from `offset`, cut at the result's end; none from
    /// its end on.
    pub(super) fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        if offset >= self.len {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(len as u64).min(self.len);
        let take = usize::try_from(end - offset).map_err(|_| invalid("PCM window"))?;
        match &self.stored {
            StoredPcm::Inline(bytes) => {
                let start = usize::try_from(offset).map_err(|_| invalid("PCM window"))?;
                Ok(bytes[start..start + take].to_vec())
            }
            StoredPcm::Spilled(file) => file.read_range(offset, take),
        }
    }

    /// Appends the whole result to `out`, a playback window at a time, so a
    /// spilled one is never read into a buffer of its own first.
    ///
    /// # Errors
    ///
    /// A spilled result's read error.
    pub fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut offset = 0;
        while offset < self.len {
            let window = self.read(offset, PCM_WINDOW_BYTES)?;
            offset = offset.saturating_add(window.len() as u64);
            out.extend_from_slice(&window);
        }
        Ok(())
    }
}

/// Takes one render's PCM as it streams: in memory up to the inline bound,
/// past it into an unlinked spill.
pub struct PcmSpool {
    dir: BodyDir,
    inline_limit: u64,
    inline: Vec<u8>,
    spill: Option<BodySpill>,
    hasher: blake3::Hasher,
    len: u64,
}

impl PcmSpool {
    /// A spool into `vault`'s body directory, spilling past its result-body
    /// inline bound.
    ///
    /// # Errors
    ///
    /// The body directory's own.
    pub fn new(vault: &Vault) -> Result<Self> {
        Ok(Self {
            dir: vault.store.body_dir()?,
            inline_limit: vault.code_result_inline_bytes(),
            inline: Vec::new(),
            spill: None,
            hasher: blake3::Hasher::new(),
            len: 0,
        })
    }

    /// Takes the result's next bytes.
    ///
    /// # Errors
    ///
    /// The spill's write error.
    pub fn write(&mut self, frame: &[u8]) -> Result<()> {
        self.hasher.update(frame);
        self.len = self.len.saturating_add(frame.len() as u64);
        if let Some(spill) = &mut self.spill {
            return spill.write(frame);
        }
        if (self.inline.len() as u64).saturating_add(frame.len() as u64) <= self.inline_limit {
            self.inline.extend_from_slice(frame);
            return Ok(());
        }
        let mut spill = BodySpill::ephemeral(&self.dir)?;
        // Unnamed at once: only this descriptor reaches the file from here,
        // and a crash leaves nothing behind.
        self.dir.discard(spill.temp());
        spill.write(&self.inline)?;
        spill.write(frame)?;
        self.inline = Vec::new();
        self.spill = Some(spill);
        Ok(())
    }

    /// The whole result: its bytes, or a reader over its spill. A spill
    /// that left `vault`'s disk below `[limits] code_result_disk_floor_bytes`
    /// asks that row's question, and plays all the same.
    ///
    /// # Errors
    ///
    /// The spill's seal or reopen error.
    pub fn finish(self, vault: &Vault) -> Result<VoxCpm2PcmBody> {
        let stored = match self.spill {
            None => StoredPcm::Inline(self.inline),
            Some(spill) => {
                let digest = *self.hasher.finalize().as_bytes();
                let reader = spill.finish(&digest, self.len)?.reader()?;
                if let Ok(free_bytes) = self.dir.free_bytes() {
                    vault
                        .limit_watch()
                        .floor(EngineLimit::CodeResultDiskFloorBytes, free_bytes);
                }
                StoredPcm::Spilled(reader)
            }
        };
        Ok(VoxCpm2PcmBody {
            len: self.len,
            stored,
        })
    }
}
