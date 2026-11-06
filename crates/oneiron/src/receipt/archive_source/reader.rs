//! Canonical receipt bytes read from one frozen, seekable source.
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};

use super::codec::{ID_DOMAIN, MAGIC, ReceiptArchive, invalid};
use crate::{
    entity_id::{ENTITY_ID_LEN, EntityId},
    error::{Error, Result},
    store::LINE_INDEX_BLOCK_BYTES,
};

pub(super) fn decode_reader(reader: impl Read + Seek) -> Result<Option<ReceiptArchive>> {
    let mut reader = BufReader::with_capacity(LINE_INDEX_BLOCK_BYTES as usize, reader);
    let start = reader.stream_position()?;
    let mut magic = [0; MAGIC.len()];
    match reader.read_exact(&mut magic) {
        Ok(()) if magic.as_slice() == MAGIC => {}
        Ok(()) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let row: ReceiptArchive = rmp_serde::from_read(&mut reader).map_err(|error| match error {
        rmp_serde::decode::Error::InvalidMarkerRead(error)
        | rmp_serde::decode::Error::InvalidDataRead(error)
            if error.kind() != io::ErrorKind::UnexpectedEof =>
        {
            error.into()
        }
        _ => invalid(),
    })?;
    reader.seek(SeekFrom::Start(start))?;
    let mut same = SameReader {
        reader: &mut reader,
        frame: vec![0; LINE_INDEX_BLOCK_BYTES as usize],
        error: None,
    };
    let encoded = row.write_canonical(&mut same);
    if let Some(error) = same.error.take() {
        return Err(error.into());
    }
    encoded?;
    let mut tail = [0];
    if same.reader.read(&mut tail)? != 0 {
        return Err(invalid());
    }
    Ok(Some(row))
}

/// Hash the bytes from the reader's current position to its end with the
/// same domain, salt and length frame used by the native slice identity.
pub(super) fn id_of_reader(mut reader: impl Read + Seek) -> Result<EntityId> {
    let start = reader.stream_position()?;
    let len =
        reader
            .seek(SeekFrom::End(0))?
            .checked_sub(start)
            .ok_or(Error::InvariantViolation(
                "receipt reader ends before its start",
            ))?;
    let mut frame = vec![0; LINE_INDEX_BLOCK_BYTES as usize];
    for salt in 0_u64..=u64::MAX {
        reader.seek(SeekFrom::Start(start))?;
        let mut hash = framed_id(salt, len);
        let mut left = len;
        while left != 0 {
            let take = left.min(frame.len() as u64) as usize;
            reader.read_exact(&mut frame[..take])?;
            hash.update(&frame[..take]);
            left -= take as u64;
        }
        let hash = hash.finalize();
        let mut id = [0; ENTITY_ID_LEN];
        id.copy_from_slice(&hash.as_bytes()[..ENTITY_ID_LEN]);
        if let Ok(id) = EntityId::from_bytes(id) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "codebase deterministic entity id exhausted salt space",
    ))
}

pub(super) fn framed_id(salt: u64, len: u64) -> blake3::Hasher {
    let mut hash = blake3::Hasher::new();
    hash.update(ID_DOMAIN);
    hash.update(&salt.to_le_bytes());
    hash.update(&len.to_le_bytes());
    hash
}

struct SameReader<'a, R> {
    reader: &'a mut R,
    frame: Vec<u8>,
    error: Option<io::Error>,
}

impl<R: Read> Write for SameReader<'_, R> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for expected in bytes.chunks(self.frame.len()) {
            let actual = &mut self.frame[..expected.len()];
            if let Err(error) = self.reader.read_exact(actual) {
                if error.kind() != io::ErrorKind::UnexpectedEof {
                    self.error = Some(error);
                }
                return Err(io::ErrorKind::InvalidData.into());
            }
            if actual != expected {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct BodyRangeReader<'a> {
    file: &'a crate::store::BodyFile,
    offset: u64,
    len: u64,
    at: u64,
}

impl<'a> BodyRangeReader<'a> {
    pub(super) fn new(file: &'a crate::store::BodyFile, offset: u64, len: u64) -> Self {
        Self {
            file,
            offset,
            len,
            at: 0,
        }
    }
}

impl Read for BodyRangeReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let take = usize::try_from(self.len - self.at)
            .unwrap_or(usize::MAX)
            .min(out.len());
        if take == 0 {
            return Ok(0);
        }
        let bytes = self
            .file
            .read_range(self.offset + self.at, take)
            .map_err(io::Error::other)?;
        out[..take].copy_from_slice(&bytes);
        self.at += take as u64;
        Ok(take)
    }
}

impl Seek for BodyRangeReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let at = match from {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::Current(delta) => self.at.checked_add_signed(delta),
            SeekFrom::End(delta) => self.len.checked_add_signed(delta),
        }
        .filter(|at| *at <= self.len)
        .ok_or(io::ErrorKind::InvalidInput)?;
        self.at = at;
        Ok(at)
    }
}
