//! A released offer's files, as the self-host shipper reads them (TL-6):
//! the manifest a piece's facts come from, and the bytes of its sealed
//! stream, its chunk files concatenated in part order.
//!
//! The facts are the manifest's: its body less the signature, the lists
//! and the chunk file names (the head); its persons and worlds; and its
//! chunk table. The stream's length is the table's sum, its digest the
//! manifest's `ciphertext_digest`, and the facts digest the contract's one
//! fn over the whole lists. C is never read here: it is the custody row's.
//!
//! A head whose compact JSON is over the intake's cap carries its filter's
//! model as a digest and a short preview instead ([`model_digest_form`],
//! FIX 7415), and the facts digest is over the head as it is sent. A head
//! within the cap is sent as the manifest gives it. The piece is never
//! refused or dropped for its head.
//!
//! A window reads its own range only. Each chunk file the range touches is
//! read through once, its length and BLAKE3 checked against the manifest,
//! and only the range's share of it kept. A file that is not what the
//! manifest says, or is not there, ships nothing for its piece
//! ([`Unreadable`]), and the piece is read again next pass; which of the two
//! rides its row for the owner (FIX 6916). Released files are never written
//! again, and the outbox's purge only removes them, so no lock is taken: a
//! file purged mid-read reads as missing, and its piece leaves the next
//! page.

use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::Path;

use oneiron::feedback::{PieceFilesProblem, TrainingSubmissionId};
use oneiron_vault_contract::conversation_training::{
    PieceChunkV1, PieceFactsHeadV1, PieceFinalV1, decode_training_offer, is_lower_hex,
    offer_manifest_file_name, piece_facts_digest,
};

/// Lower-case hex characters of a BLAKE3 digest.
const DIGEST_HEX: usize = 64;
/// The buffer a chunk file is read through.
const READ_BUFFER: usize = 64 * 1024;
/// CALLS TL6_HEAD_MODEL_DIGEST: the intake's cap on a head's compact JSON
/// (LC's `HEAD_JSON_MAX`, 8 KiB, which it counts in UTF-16 units), counted
/// here in its UTF-8 bytes, which are never fewer.
const HEAD_JSON_MAX: usize = 8 * 1024;
/// CALLS TL6_HEAD_MODEL_DIGEST: the most characters of the filter's model
/// a head over the cap keeps beside the model's digest.
const MODEL_PREVIEW_CHARS: usize = 64;

/// Why a piece's files ship nothing this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unreadable {
    /// A file is not there, or does not read.
    Missing,
    /// The manifest does not decode or names another submission, or a
    /// chunk file is not the length or the BLAKE3 the manifest gives.
    Mismatch,
}

impl Unreadable {
    /// The problem the piece's row records for the owner (FIX 6916).
    pub(super) const fn problem(self) -> PieceFilesProblem {
        match self {
            Self::Missing => PieceFilesProblem::Missing,
            Self::Mismatch => PieceFilesProblem::Mismatched,
        }
    }
}

/// One released piece's facts, from its manifest.
pub(super) struct Piece {
    /// The scalar facts: the manifest's body less its signature, its lists
    /// and its chunk file names, within the intake's cap ([`within_cap`]).
    pub(super) head: PieceFactsHeadV1,
    /// The person codes.
    pub(super) persons: Vec<String>,
    /// The world codes.
    pub(super) worlds: Vec<String>,
    /// The chunk table, in part order.
    pub(super) chunks: Vec<PieceChunkV1>,
    /// Each chunk's file in `offers/`, as the manifest names it.
    files: Vec<String>,
    /// The sealed stream's length: the chunk table's sum.
    pub(super) total_bytes: u64,
    /// The sealed stream's BLAKE3, 64 hex: the manifest's
    /// `ciphertext_digest`.
    total_digest: String,
    /// The facts digest over the whole lists, 64 hex.
    facts_digest: String,
}

impl Piece {
    /// The facts of `id`'s released offer, from its manifest in `offers`.
    ///
    /// # Errors
    /// [`Unreadable`]: no manifest, or one that is not this submission's.
    pub(super) fn read(offers: &Path, id: TrainingSubmissionId) -> Result<Self, Unreadable> {
        let submission = id.to_hex();
        let name = offer_manifest_file_name(&submission).ok_or(Unreadable::Mismatch)?;
        let mut manifest = Vec::new();
        open_regular(&offers.join(name))?
            .read_to_end(&mut manifest)
            .map_err(|_| Unreadable::Missing)?;
        let body = decode_training_offer(&manifest)
            .map_err(|_| Unreadable::Mismatch)?
            .body;
        if body.submission_id != submission
            || !is_lower_hex(&body.payload.ciphertext_digest, DIGEST_HEX)
        {
            return Err(Unreadable::Mismatch);
        }
        let mut chunks = Vec::with_capacity(body.payload.chunks.len());
        let mut files = Vec::with_capacity(body.payload.chunks.len());
        let mut total_bytes = 0_u64;
        for chunk in body.payload.chunks {
            total_bytes = total_bytes
                .checked_add(chunk.bytes)
                .ok_or(Unreadable::Mismatch)?;
            chunks.push(PieceChunkV1 {
                bytes: chunk.bytes,
                digest: chunk.digest,
            });
            files.push(chunk.file);
        }
        let head = within_cap(PieceFactsHeadV1 {
            submission_id: body.submission_id,
            scope: body.scope,
            event_seq: body.event_seq,
            source: body.source,
            training: body.training,
            privacy: body.privacy,
            filter: body.filter,
            encoding: body.payload.encoding,
            key_id: body.payload.key_id,
            text_bytes: body.payload.text_bytes,
            prepared_at: body.prepared_at,
        })?;
        let facts_digest = piece_facts_digest(&head, &body.persons, &body.worlds, &chunks)
            .map_err(|_| Unreadable::Mismatch)?;
        Ok(Self {
            head,
            persons: body.persons,
            worlds: body.worlds,
            chunks,
            files,
            total_bytes,
            total_digest: body.payload.ciphertext_digest,
            facts_digest: oneiron_vault_contract::hex(&facts_digest),
        })
    }

    /// The piece's final: its totals and both digests.
    pub(super) fn finish(&self) -> PieceFinalV1 {
        PieceFinalV1 {
            persons_total: len_u64(self.persons.len()),
            worlds_total: len_u64(self.worlds.len()),
            chunks_total: len_u64(self.chunks.len()),
            total_bytes: self.total_bytes,
            total_digest: self.total_digest.clone(),
            facts_digest: self.facts_digest.clone(),
        }
    }

    /// The sealed stream's bytes from `start` to `end`, from the chunk
    /// files in `offers` the range touches. Each is read through once and
    /// checked whole against the manifest before any of it is kept.
    ///
    /// # Errors
    /// [`Unreadable`]: a chunk file missing, or not the manifest's.
    pub(super) fn read_range(
        &self,
        offers: &Path,
        start: u64,
        end: u64,
    ) -> Result<Vec<u8>, Unreadable> {
        let len = usize::try_from(end.saturating_sub(start)).map_err(|_| Unreadable::Mismatch)?;
        let mut range = Vec::with_capacity(len);
        let mut chunk_start = 0_u64;
        for (chunk, file) in self.chunks.iter().zip(&self.files) {
            let chunk_end = chunk_start
                .checked_add(chunk.bytes)
                .ok_or(Unreadable::Mismatch)?;
            if chunk_end > start && chunk_start < end {
                read_chunk(
                    &offers.join(file),
                    chunk,
                    chunk_start,
                    (start, end),
                    &mut range,
                )?;
            }
            if chunk_end >= end {
                break;
            }
            chunk_start = chunk_end;
        }
        if range.len() != len {
            return Err(Unreadable::Mismatch);
        }
        Ok(range)
    }
}

/// Reads the chunk file at `path`, which starts at stream offset
/// `chunk_start`, through once: checks its length and BLAKE3 against
/// `chunk`, and appends its share of the stream range from `start` to `end`
/// to `range`. Bytes appended before a failed check go with the caller's
/// range.
fn read_chunk(
    path: &Path,
    chunk: &PieceChunkV1,
    chunk_start: u64,
    (start, end): (u64, u64),
    range: &mut Vec<u8>,
) -> Result<(), Unreadable> {
    let mut file = open_regular(path)?;
    let held = file.metadata().map_err(|_| Unreadable::Missing)?.len();
    if held != chunk.bytes {
        return Err(Unreadable::Mismatch);
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; READ_BUFFER];
    let mut at = chunk_start;
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Unreadable::Missing),
        };
        let bytes = buffer.get(..read).ok_or(Unreadable::Mismatch)?;
        hasher.update(bytes);
        let read_end = at.checked_add(len_u64(read)).ok_or(Unreadable::Mismatch)?;
        let (from, to) = (start.max(at), end.min(read_end));
        if from < to {
            let lo = usize::try_from(from - at).map_err(|_| Unreadable::Mismatch)?;
            let hi = usize::try_from(to - at).map_err(|_| Unreadable::Mismatch)?;
            range.extend_from_slice(bytes.get(lo..hi).ok_or(Unreadable::Mismatch)?);
        }
        at = read_end;
        if at - chunk_start > chunk.bytes {
            return Err(Unreadable::Mismatch);
        }
    }
    let whole = at - chunk_start == chunk.bytes;
    if !whole || oneiron_vault_contract::hex(hasher.finalize().as_bytes()) != chunk.digest {
        return Err(Unreadable::Mismatch);
    }
    Ok(())
}

/// Opens the regular file at `path`, never a link the directory's other
/// writers could aim elsewhere.
fn open_regular(path: &Path) -> Result<File, Unreadable> {
    let meta = fs::symlink_metadata(path).map_err(|_| Unreadable::Missing)?;
    if !meta.file_type().is_file() {
        return Err(Unreadable::Mismatch);
    }
    File::open(path).map_err(|_| Unreadable::Missing)
}

/// `head` within the intake's cap (FIX 7415): as it is when its compact
/// JSON fits [`HEAD_JSON_MAX`]; else with its filter's model in
/// [`model_digest_form`], the preview cut a character shorter until the
/// head fits. A head that fits not even with no preview goes in that
/// smallest form: the piece is never refused or dropped here.
///
/// # Errors
/// [`Unreadable::Mismatch`]: a head that does not encode.
fn within_cap(mut head: PieceFactsHeadV1) -> Result<PieceFactsHeadV1, Unreadable> {
    if head_json_len(&head)? <= HEAD_JSON_MAX {
        return Ok(head);
    }
    let model = std::mem::take(&mut head.filter.model);
    let mut preview = MODEL_PREVIEW_CHARS;
    loop {
        head.filter.model = model_digest_form(&model, preview);
        if preview == 0 || head_json_len(&head)? <= HEAD_JSON_MAX {
            return Ok(head);
        }
        preview -= 1;
    }
}

/// CALLS TL6_HEAD_MODEL_DIGEST (FIX 7415): the filter's `model` as a head
/// over the intake's cap carries it, in the contract's own `model` field:
/// `blake3:`, the BLAKE3 of the model's UTF-8 bytes as 64 lower-case hex,
/// `:`, then the model's first `preview` characters, cut on a character
/// boundary. No contract type changes; LC's intake reads this form.
fn model_digest_form(model: &str, preview: usize) -> String {
    let digest = oneiron_vault_contract::hex(blake3::hash(model.as_bytes()).as_bytes());
    let end = model
        .char_indices()
        .nth(preview)
        .map_or(model.len(), |(at, _)| at);
    let kept = model.get(..end).unwrap_or_default();
    format!("blake3:{digest}:{kept}")
}

/// The length of `head`'s compact JSON, as serde_json writes it.
///
/// # Errors
/// [`Unreadable::Mismatch`]: a head that does not encode.
fn head_json_len(head: &PieceFactsHeadV1) -> Result<usize, Unreadable> {
    serde_json::to_vec(head)
        .map(|json| json.len())
        .map_err(|_| Unreadable::Mismatch)
}

/// A length as a `u64`.
fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}
