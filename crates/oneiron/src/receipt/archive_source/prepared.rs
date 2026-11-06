//! Frozen canonical receipt bytes held outside the all-sources preparation vector.
use std::io::{self, Read, Write};

use super::codec::{ID_DOMAIN, ReceiptArchive};
use crate::{
    entity_id::{ENTITY_ID_LEN, EntityId},
    error::{Error, Result},
    store::{AssetBodyFacts, BodyDir, BodyFile, BodySpill, LINE_INDEX_BLOCK_BYTES},
};

/// An unlinked native temp, sealed under an in-memory key on a sealed vault.
/// It is not a published body file and needs no persistent body instance.
pub(super) struct PreparedReceiptArchive {
    file: BodyFile,
    len: u64,
    digest: [u8; 32],
}

impl PreparedReceiptArchive {
    pub(super) fn new(dir: &BodyDir, archive: &ReceiptArchive) -> Result<Self> {
        let mut spill = BodySpill::ephemeral(dir)?;
        let _temp = TempArchive {
            dir,
            name: spill.temp().to_owned(),
        };
        let mut out = ArchiveWriter {
            spill: &mut spill,
            hasher: blake3::Hasher::new(),
            len: 0,
            error: None,
        };
        let encoded = archive.write_canonical(&mut out);
        if let Some(error) = out.error.take() {
            return Err(error);
        }
        encoded?;
        let len = out.len;
        let digest = *out.hasher.finalize().as_bytes();
        let spilled = spill.finish(&digest, len)?;
        // The descriptor and ephemeral key survive unlinking the temp name.
        let file = spilled.reader()?;
        Ok(Self { file, len, digest })
    }

    /// The same domain, salt and one length-prefixed part as id_of_bytes.
    pub(super) fn id(&self) -> Result<EntityId> {
        for salt in 0_u64..=u64::MAX {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ID_DOMAIN);
            hasher.update(&salt.to_le_bytes());
            hasher.update(&self.len.to_le_bytes());
            let mut body_hash = blake3::Hasher::new();
            let mut at = 0;
            while at < self.len {
                let take = (self.len - at).min(u64::from(LINE_INDEX_BLOCK_BYTES)) as usize;
                let bytes = self.file.read_range(at, take)?;
                hasher.update(&bytes);
                body_hash.update(&bytes);
                at += take as u64;
            }
            if *body_hash.finalize().as_bytes() != self.digest {
                return Err(Error::CorruptedIndex("prepared receipt archive digest"));
            }
            let hash = hasher.finalize();
            let mut id = [0_u8; ENTITY_ID_LEN];
            id.copy_from_slice(&hash.as_bytes()[..ENTITY_ID_LEN]);
            if let Ok(id) = EntityId::from_bytes(id) {
                return Ok(id);
            }
        }
        Err(Error::InvariantViolation(
            "codebase deterministic entity id exhausted salt space",
        ))
    }

    pub(super) fn check_facts(&self, facts: AssetBodyFacts) -> Result<()> {
        if facts.len != self.len || facts.blake3 != self.digest {
            return Err(Error::CorruptedIndex("prepared receipt archive digest"));
        }
        Ok(())
    }

    pub(super) fn reader(&self) -> impl Read + '_ {
        ArchiveReader {
            archive: self,
            at: 0,
        }
    }
}

struct TempArchive<'a> {
    dir: &'a BodyDir,
    name: String,
}

impl Drop for TempArchive<'_> {
    fn drop(&mut self) {
        self.dir.discard(&self.name);
    }
}

struct ArchiveWriter<'a> {
    spill: &'a mut BodySpill,
    hasher: blake3::Hasher,
    len: u64,
    error: Option<Error>,
}

impl Write for ArchiveWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(len) = self.len.checked_add(bytes.len() as u64) else {
            self.error = Some(Error::ArithmeticOverflow("receipt archive length"));
            return Err(io::ErrorKind::InvalidData.into());
        };
        if let Err(error) = self.spill.write(bytes) {
            self.error = Some(error);
            return Err(io::ErrorKind::Other.into());
        }
        self.hasher.update(bytes);
        self.len = len;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ArchiveReader<'a> {
    archive: &'a PreparedReceiptArchive,
    at: u64,
}

impl Read for ArchiveReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let take = usize::try_from(self.archive.len - self.at)
            .unwrap_or(usize::MAX)
            .min(out.len());
        if take == 0 {
            return Ok(0);
        }
        let bytes = self
            .archive
            .file
            .read_range(self.at, take)
            .map_err(io::Error::other)?;
        out[..take].copy_from_slice(&bytes);
        self.at += take as u64;
        Ok(take)
    }
}
