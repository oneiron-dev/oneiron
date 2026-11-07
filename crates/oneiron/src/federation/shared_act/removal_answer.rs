//! A removal archive's copy as a door answers it and a receiver takes it in
//! (FIX 21529): the copy's metadata and digest beside the archive as a spool
//! file, so neither side holds an archive whole.
//! [`RemovalExportFile::write_json`] writes the copy's JSON byte for byte as
//! [`RemovalExportCopy`] serialises it, the archive base64-encoded from its
//! file as it is written; a receiver decodes the archive into a spool file
//! of its own and keeps the rest of the copy
//! ([`RemovalExportFile::received`]).

use std::io::{Seek, SeekFrom, Write};

use super::RemovalExportCopy;
use super::removal_archive::KeptRemovalCopy;

/// The bytes that open the archive's value in a copy's JSON: the member
/// follows `format`, and no JSON string holds an unescaped quote, so its
/// first appearance is the member.
const ARCHIVE_OPENING: &[u8] = br#","archive":""#;

/// A removal archive's copy whose archive is a spool file (FIX 21529): what
/// the removal archive doors answer, and what
/// [`crate::Vault::import_removal_archive`] takes in. Its JSON is the copy's
/// ([`Self::write_json`]).
#[derive(Debug)]
pub struct RemovalExportFile {
    pub(super) copy: KeptRemovalCopy,
    /// BLAKE3 of the archive, lowercase hex: of `archive` as a door answers
    /// it, and as its copy names it where a receiver took it in.
    pub(super) digest: String,
    pub(super) archive: std::fs::File,
}

/// BLAKE3 of what the spool file `file` holds, lowercase hex, read a piece
/// at a time from its start; the file is left rewound.
pub(super) fn spool_digest(file: &mut std::fs::File) -> std::io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(file, &mut hasher)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(hasher.finalize().to_hex().to_string())
}

impl RemovalExportFile {
    pub(super) const fn new(copy: KeptRemovalCopy, digest: String, archive: std::fs::File) -> Self {
        Self {
            copy,
            digest,
            archive,
        }
    }

    /// A copy as its receiver read it: `copy`'s metadata and digest, its
    /// archive the spool file `archive`, decoded from the copy's base64.
    /// `copy.export.archive` is not read; a receiver leaves it empty. The
    /// digest is the one the copy names, which
    /// [`crate::Vault::import_removal_archive`] checks the file against.
    #[must_use]
    pub fn received(copy: RemovalExportCopy, archive: std::fs::File) -> Self {
        let RemovalExportCopy {
            receipt_id,
            vault_id,
            member,
            delivered_at,
            expires_at,
            export,
        } = copy;
        Self {
            copy: KeptRemovalCopy {
                receipt_id,
                vault_id,
                member,
                delivered_at,
                expires_at,
                format: export.format,
                holder_requests: export.holder_requests,
            },
            digest: export.digest,
            archive,
        }
    }

    /// The removal's receipt id, which keys the archive.
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.copy.receipt_id
    }

    /// The removed Owner, PERSON hex: the archive's one recipient.
    #[must_use]
    pub fn member(&self) -> &str {
        &self.copy.member
    }

    /// When it was last delivered: its delivery version.
    #[must_use]
    pub const fn delivered_at(&self) -> u64 {
        self.copy.delivered_at
    }

    /// BLAKE3 of the archive, lowercase hex, as the copy names it.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Writes the copy's compact JSON to `out`: the bytes
    /// `serde_json::to_vec` gives for the [`RemovalExportCopy`] holding this
    /// archive, its archive standard base64 read from the file a piece at a
    /// time. It may be written again: the file is read from its start.
    ///
    /// # Errors
    ///
    /// The spool file's and `out`'s I/O errors; a copy whose metadata does
    /// not encode.
    pub fn write_json(&mut self, out: &mut impl Write) -> std::io::Result<()> {
        let (head, tail) = self.json_around_archive()?;
        out.write_all(&head)?;
        self.archive.seek(SeekFrom::Start(0))?;
        {
            // The encoder borrows `out` until it drops: the tail follows it.
            let mut encoder = base64::write::EncoderWriter::new(
                &mut *out,
                &base64::engine::general_purpose::STANDARD,
            );
            std::io::copy(&mut self.archive, &mut encoder)?;
            encoder.finish()?;
        }
        out.write_all(&tail)
    }

    /// The copy's JSON before and after its archive's base64: the copy
    /// serialised with an empty archive, cut inside the archive's quotes.
    fn json_around_archive(&self) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
        let empty: RemovalExportCopy = self
            .copy
            .clone()
            .with_archive(Vec::new(), self.digest.clone());
        let mut json = serde_json::to_vec(&empty)?;
        let at = json
            .windows(ARCHIVE_OPENING.len())
            .position(|window| window == ARCHIVE_OPENING)
            .ok_or_else(|| std::io::Error::other("a removal export copy's JSON has no archive"))?;
        let tail = json.split_off(at + ARCHIVE_OPENING.len());
        Ok((json, tail))
    }
}
