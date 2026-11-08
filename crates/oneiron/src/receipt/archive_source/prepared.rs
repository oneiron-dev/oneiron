//! Canonical receipt preparation in one native, unlinked temporary body.
use std::io::{self, Read, Write};

use super::codec::{ID_DOMAIN, ReceiptArchive};
use crate::{
    entity_id::{ENTITY_ID_LEN, EntityId},
    error::{Error, Result},
    store::{AssetBodyFacts, BodyDir, BodyFile, BodySpill, LINE_INDEX_BLOCK_BYTES},
};

/// One native temp for the whole restore, not one open file per source.
/// A sealed vault uses an in-memory ephemeral key, never a body instance.
pub(super) struct ReceiptArchivePreparation {
    dir: BodyDir,
    temp: String,
    spill: Option<BodySpill>,
    hash: blake3::Hasher,
    len: u64,
}

pub(super) struct PreparedReceiptArchive {
    pub(super) id: EntityId,
    offset: u64,
    len: u64,
    digest: [u8; 32],
}

pub(super) struct PreparedReceiptBytes {
    file: BodyFile,
}

impl ReceiptArchivePreparation {
    pub(super) fn new(dir: BodyDir) -> Result<Self> {
        let spill = BodySpill::ephemeral(&dir)?;
        Ok(Self {
            temp: spill.temp().to_owned(),
            dir,
            spill: Some(spill),
            hash: blake3::Hasher::new(),
            len: 0,
        })
    }

    pub(super) fn push(&mut self, archive: &ReceiptArchive) -> Result<PreparedReceiptArchive> {
        // The canonical serializer reads this owned, validated data tree,
        // not an archive file. Count its frame before hashing that frame.
        let mut count = CountBytes(0);
        archive.write_canonical(&mut count)?;
        let len = count.0;
        let mut identity = framed_id(0, len);
        let mut out = ArchiveWriter {
            spill: self.spill.as_mut().ok_or(Error::InvariantViolation(
                "receipt preparation already finished",
            ))?,
            whole: &mut self.hash,
            identity: &mut identity,
            body: blake3::Hasher::new(),
            len: 0,
            error: None,
        };
        let encoded = archive.write_canonical(&mut out);
        if let Some(error) = out.error.take() {
            return Err(error);
        }
        encoded?;
        if out.len != len {
            return Err(Error::CorruptedIndex("prepared receipt archive length"));
        }
        let digest = *out.body.finalize().as_bytes();
        let offset = self.len;
        self.len = self.len.checked_add(len).ok_or(Error::ArithmeticOverflow(
            "receipt archive preparation length",
        ))?;
        let mut first = Some(identity);
        for salt in 0_u64..=u64::MAX {
            let hash = match first.take() {
                Some(hash) => hash,
                None => {
                    let mut hash = framed_id(salt, len);
                    archive.write_canonical(&mut HashBytes(&mut hash))?;
                    hash
                }
            };
            let hash = hash.finalize();
            let mut id = [0_u8; ENTITY_ID_LEN];
            id.copy_from_slice(&hash.as_bytes()[..ENTITY_ID_LEN]);
            if let Ok(id) = EntityId::from_bytes(id) {
                return Ok(PreparedReceiptArchive {
                    id,
                    offset,
                    len,
                    digest,
                });
            }
        }
        Err(Error::InvariantViolation(
            "codebase deterministic entity id exhausted salt space",
        ))
    }

    pub(super) fn finish(mut self) -> Result<PreparedReceiptBytes> {
        let digest = *self.hash.finalize().as_bytes();
        let spill = self.spill.take().ok_or(Error::InvariantViolation(
            "receipt preparation already finished",
        ))?;
        let spilled = spill.finish(&digest, self.len)?;
        let file = spilled.reader()?;
        let mut hash = blake3::Hasher::new();
        let mut at = 0;
        while at < self.len {
            let take = (self.len - at).min(u64::from(LINE_INDEX_BLOCK_BYTES)) as usize;
            hash.update(&file.read_range(at, take)?);
            at += take as u64;
        }
        if *hash.finalize().as_bytes() != digest {
            return Err(Error::CorruptedIndex("prepared receipt archive digest"));
        }
        // Drop unlinks the name; this descriptor and its ephemeral key survive.
        Ok(PreparedReceiptBytes { file })
    }
}

impl Drop for ReceiptArchivePreparation {
    fn drop(&mut self) {
        self.dir.discard(&self.temp);
    }
}

impl PreparedReceiptArchive {
    pub(super) fn check_facts(&self, facts: AssetBodyFacts) -> Result<()> {
        if facts.len != self.len || facts.blake3 != self.digest {
            return Err(Error::CorruptedIndex("prepared receipt archive digest"));
        }
        Ok(())
    }
}

impl PreparedReceiptBytes {
    pub(super) fn reader<'a>(&'a self, archive: &'a PreparedReceiptArchive) -> impl Read + 'a {
        ArchiveReader {
            file: &self.file,
            archive,
            at: 0,
        }
    }
}

fn framed_id(salt: u64, len: u64) -> blake3::Hasher {
    let mut hash = blake3::Hasher::new();
    hash.update(ID_DOMAIN);
    hash.update(&salt.to_le_bytes());
    hash.update(&len.to_le_bytes());
    hash
}

struct CountBytes(u64);

impl Write for CountBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len() as u64)
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct HashBytes<'a>(&'a mut blake3::Hasher);

impl Write for HashBytes<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ArchiveWriter<'a> {
    spill: &'a mut BodySpill,
    whole: &'a mut blake3::Hasher,
    identity: &'a mut blake3::Hasher,
    body: blake3::Hasher,
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
        self.whole.update(bytes);
        self.identity.update(bytes);
        self.body.update(bytes);
        self.len = len;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ArchiveReader<'a> {
    file: &'a BodyFile,
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
            .file
            .read_range(self.archive.offset + self.at, take)
            .map_err(io::Error::other)?;
        out[..take].copy_from_slice(&bytes);
        self.at += take as u64;
        Ok(take)
    }
}
