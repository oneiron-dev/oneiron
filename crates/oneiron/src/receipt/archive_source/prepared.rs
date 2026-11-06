//! Canonical receipt preparation in one native, unlinked temporary body.
use std::io::{self, Read, Seek, SeekFrom, Write};

use super::codec::ReceiptArchive;
use crate::{
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
        let mut out = ArchiveWriter {
            spill: self.spill.as_mut().ok_or(Error::InvariantViolation(
                "receipt preparation already finished",
            ))?,
            whole: &mut self.hash,
            body: blake3::Hasher::new(),
            len: 0,
            error: None,
        };
        let encoded = archive.write_canonical(&mut out);
        if let Some(error) = out.error.take() {
            return Err(error);
        }
        encoded?;
        let len = out.len;
        let digest = *out.body.finalize().as_bytes();
        let offset = self.len;
        self.len = self.len.checked_add(len).ok_or(Error::ArithmeticOverflow(
            "receipt archive preparation length",
        ))?;
        Ok(PreparedReceiptArchive {
            offset,
            len,
            digest,
        })
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
    pub(super) fn reader<'a>(
        &'a self,
        archive: &'a PreparedReceiptArchive,
    ) -> impl Read + Seek + 'a {
        ArchiveReader {
            file: &self.file,
            archive,
            at: 0,
        }
    }
}

struct ArchiveWriter<'a> {
    spill: &'a mut BodySpill,
    whole: &'a mut blake3::Hasher,
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

impl Seek for ArchiveReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let at = match from {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::Current(delta) => self.at.checked_add_signed(delta),
            SeekFrom::End(delta) => self.archive.len.checked_add_signed(delta),
        }
        .filter(|at| *at <= self.archive.len)
        .ok_or(io::ErrorKind::InvalidInput)?;
        self.at = at;
        Ok(at)
    }
}
