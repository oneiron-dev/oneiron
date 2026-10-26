//! The copy a repo-derived index or embedding input is made from (FIX 7608
//! slice 3, ASK 1: search and embeddings read the MASKED copy, and a FILE
//! reveal grants neither plaintext search nor embedding inputs).
//!
//! Every text index, symbol graph, phonetic code and vector built from a
//! repo blob a receive mark covers is derived from its projection, never
//! the stored bytes: the masked copy, or the sealed-file placeholder
//! [`REPO_OPAQUE_FILE_BYTES`] for residue no span isolates. A copy only
//! replaces bytes: a document, chunk or item that indexes today still
//! indexes, as its safe copy. The stored blob, its ASSET, its snapshot
//! entry and its history stay exactly as received.
//!
//! An input is joined to a marked blob only by a proved link: the whole
//! BLAKE3 of its bytes (a snapshot ASSET's body, a media envelope's inner
//! bytes, a file's full source), or a record whose id is the snapshot ASSET
//! id that BLAKE3 derives. No path, chunk text or recorded hash string is a
//! link. The marks are read once per pass (CALL 8033 option d); a lookup's
//! store error propagates, never an exact fallback (Engine 10-22 05:5x).
//! Every unmarked input reads as it always has.
//!
//! A copy's stamp names its source, the marks and copy it was made under,
//! and [`RepoIndexProjectionVersion`]. It stays internal: a writer that
//! publishes a copy compares it with the copy the same transaction makes
//! now, and a mask change requeues the copies its blobs derive
//! ([`refresh_repo_index_projection_in_txn`]).

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use super::types::REPO_OPAQUE_FILE_BYTES;
use super::{RepoBodyProjection, project_repo_bytes_in_txn};
use crate::Vault;
use crate::codebase::snapshot_asset_entity_id;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::secret_marks::{RepoMarkFacts, RepoSecretMarkLookup};

mod invalidate;
pub(crate) use invalidate::refresh_repo_index_projection_in_txn;

/// The domain of a copy stamp's fingerprint.
const REPO_INDEX_STAMP_CONTEXT: &str = "oneiron.repo-index-projection.stamp.v1";

/// The rules an index copy is made by (CALL 3-I, ruling (d), Engine 10-22
/// 07:20): part of every copy's stamp, so a change to them rebuilds only the
/// copies it changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RepoIndexProjectionVersion(u16);

impl RepoIndexProjectionVersion {
    /// Copies are the masked projection or the sealed-file placeholder.
    pub(crate) const CURRENT: Self = Self(1);

    pub(crate) const fn get(self) -> u16 {
        self.0
    }
}

/// How an index copy stands in for its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepoIndexCopyKind {
    /// Each marked span overwritten in place.
    Masked,
    /// [`REPO_OPAQUE_FILE_BYTES`].
    Opaque,
}

/// What one index copy was made from: value-free (no secret, no per-key
/// fingerprint), and equal for two copies only when their source, marks,
/// returned bytes and rules all are.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the copy identity a CALL 3-I version change rebuilds by; writers read copy_blake3 and kind"
)]
pub(crate) struct RepoIndexProjectionStamp {
    /// The whole BLAKE3 of the stored blob the copy stands in for.
    pub(crate) source_blake3: [u8; 32],
    /// Every readable mark of that blob, sorted.
    pub(crate) mark_ids: Vec<EntityId>,
    /// The BLAKE3 of exactly the copy's bytes: a later mask on the same mark
    /// ids changes it.
    pub(crate) copy_blake3: [u8; 32],
    pub(crate) kind: RepoIndexCopyKind,
    pub(crate) version: RepoIndexProjectionVersion,
}

impl RepoIndexProjectionStamp {
    /// One digest of every field: the identity a derived work item commits
    /// to.
    #[allow(
        dead_code,
        reason = "the copy identity a CALL 3-I version change rebuilds by"
    )]
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(REPO_INDEX_STAMP_CONTEXT);
        hasher.update(&self.version.get().to_be_bytes());
        hasher.update(&[match self.kind {
            RepoIndexCopyKind::Masked => 0,
            RepoIndexCopyKind::Opaque => 1,
        }]);
        hasher.update(&self.source_blake3);
        hasher.update(&self.copy_blake3);
        hasher.update(&(self.mark_ids.len() as u64).to_be_bytes());
        for id in &self.mark_ids {
            hasher.update(id.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }
}

/// The bytes one index input is derived from: the stored bytes when no mark
/// covers them, else their copy and its stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoIndexInput {
    bytes: Vec<u8>,
    stamp: Option<RepoIndexProjectionStamp>,
}

impl RepoIndexInput {
    fn stored(bytes: Vec<u8>) -> Self {
        Self { bytes, stamp: None }
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The copy's stamp; `None` for stored bytes.
    pub(crate) fn stamp(&self) -> Option<&RepoIndexProjectionStamp> {
        self.stamp.as_ref()
    }

    /// Whether the input is the sealed-file placeholder.
    pub(crate) fn opaque(&self) -> bool {
        self.stamp
            .as_ref()
            .is_some_and(|stamp| stamp.kind == RepoIndexCopyKind::Opaque)
    }

    /// The input as text: a copy that no longer decodes keeps every other
    /// character.
    pub(crate) fn into_text(self) -> String {
        text_of(self.bytes)
    }
}

/// `bytes` as text, each undecodable sequence replaced.
fn text_of(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
}

/// The sealed-file placeholder as text.
pub(crate) fn opaque_index_text() -> String {
    text_of(REPO_OPAQUE_FILE_BYTES.to_vec())
}

/// Every readable repo mark, read once for one index pass, and the two
/// joins an input is proved by: the marked blobs' whole BLAKE3, and the
/// snapshot ASSET ids they derive.
pub(crate) struct RepoIndexMarks {
    facts: RepoMarkFacts,
    hashes: BTreeSet<[u8; 32]>,
    sources: BTreeMap<EntityId, [u8; 32]>,
    /// Marked blobs a mark of which does not decode: their copy is unknown,
    /// so every projection of them fails (FIX 10793). Empty for
    /// [`Self::read_in_txn`].
    unreadable: BTreeSet<[u8; 32]>,
}

impl RepoIndexMarks {
    /// The marks `txn` reads.
    ///
    /// # Errors
    /// A store failure, or a mark that does not decode.
    pub(crate) fn read_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<Self> {
        let facts = RepoMarkFacts::read_in_txn(vault, txn, RepoSecretMarkLookup::ReadableClaims)?;
        Self::of(facts, BTreeSet::new())
    }

    /// The marks `txn` reads, scoped per blob for a sync release (FIX 7608
    /// slice 4, FIX 10793): a mark that does not decode fails only the
    /// projections of the blob it names, which stays marked (its source and
    /// copy ids derive as any other's). Every other blob reads as before.
    ///
    /// # Errors
    /// A store failure, or a mark that does not decode and names no blob.
    pub(crate) fn read_scoped_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<Self> {
        let (facts, unreadable) = RepoMarkFacts::read_scoped_in_txn(vault, txn)?;
        Self::of(facts, unreadable)
    }

    fn of(facts: RepoMarkFacts, unreadable: BTreeSet<[u8; 32]>) -> Result<Self> {
        let mut hashes = facts.raw_hashes();
        hashes.extend(unreadable.iter().copied());
        let sources = hashes
            .iter()
            .map(|hash| Ok((snapshot_asset_entity_id(hash)?, *hash)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(Self {
            facts,
            hashes,
            sources,
            unreadable,
        })
    }

    /// The failure every projection of a blob [`Self::read_scoped_in_txn`]
    /// found an undecodable mark of answers.
    fn readable(&self, source: &[u8; 32]) -> Result<()> {
        if self.unreadable.contains(source) {
            return Err(crate::error::Error::CorruptedIndex(
                "a repo secret mark does not decode",
            ));
        }
        Ok(())
    }

    /// No mark anywhere: every input is its stored bytes.
    pub(crate) fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Whether a mark covers the blob whose whole bytes hash to `raw_blake3`.
    pub(crate) fn is_marked(&self, raw_blake3: &[u8; 32]) -> bool {
        self.hashes.contains(raw_blake3)
    }

    /// The marked blob record `entity` is the snapshot ASSET of, if any.
    pub(crate) fn source_of(&self, entity: &EntityId) -> Option<[u8; 32]> {
        self.sources.get(entity).copied()
    }

    /// Every marked blob's snapshot ASSET id with its whole BLAKE3 (FIX
    /// 7608 slice 4: the sync copy is made once per marked blob per pass).
    pub(crate) fn marked_sources(&self) -> Vec<(EntityId, [u8; 32])> {
        self.sources.iter().map(|(id, hash)| (*id, *hash)).collect()
    }

    /// The spans the masked copy of the marked blob `source` overwrites,
    /// unioned as the whole-byte projector unions them; `None` when its copy
    /// is the placeholder. An incoming edit of the copy is translated over
    /// exactly these.
    ///
    /// # Errors
    /// A store failure reading the blob's mask row.
    pub(crate) fn copy_places_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        source: &[u8; 32],
    ) -> Result<Option<crate::secret_custody::KeyPlaces>> {
        self.readable(source)?;
        let marks = self.facts.for_hash(source);
        if marks.is_empty() || marks.opaque() {
            return Ok(None);
        }
        let mut places = marks.places();
        if let Some(row) = crate::secret_custody::masked_file_in_txn(&vault.store, txn, source)? {
            for (member, spans) in row.places() {
                for span in spans {
                    crate::origin::secret_marks::add_place(&mut places, &member, span);
                }
            }
        }
        Ok(Some(places))
    }

    /// Whether any of record `entity`'s index inputs is a copy: it is a
    /// marked blob's snapshot ASSET, or its body or a field is a marked
    /// blob's whole bytes.
    pub(crate) fn touches(
        &self,
        entity: &EntityId,
        body: &[u8],
        fields: &[(String, String)],
    ) -> bool {
        !self.is_empty()
            && (self.sources.contains_key(entity)
                || self.is_marked(blake3::hash(body).as_bytes())
                || fields
                    .iter()
                    .any(|(_, value)| self.is_marked(blake3::hash(value.as_bytes()).as_bytes())))
    }

    /// `bytes` as an index reads them, joined by their own whole BLAKE3.
    ///
    /// # Errors
    /// A store failure reading the blob's mask row.
    pub(crate) fn input_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        bytes: Vec<u8>,
    ) -> Result<RepoIndexInput> {
        if self.is_empty() {
            return Ok(RepoIndexInput::stored(bytes));
        }
        let hash = *blake3::hash(&bytes).as_bytes();
        if !self.is_marked(&hash) {
            return Ok(RepoIndexInput::stored(bytes));
        }
        self.project_in_txn(vault, txn, &hash, bytes)
    }

    /// `bytes`, which a proved link says stand for the marked blob `source`:
    /// its masked copy when they are its exact bytes, the placeholder when
    /// they are anything else.
    ///
    /// # Errors
    /// As [`Self::input_in_txn`].
    pub(crate) fn source_input_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        source: &[u8; 32],
        bytes: Vec<u8>,
    ) -> Result<RepoIndexInput> {
        self.project_in_txn(vault, txn, source, bytes)
    }

    fn project_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        source: &[u8; 32],
        bytes: Vec<u8>,
    ) -> Result<RepoIndexInput> {
        self.readable(source)?;
        let marks = self.facts.for_hash(source);
        if marks.is_empty() {
            return Ok(RepoIndexInput::stored(bytes));
        }
        let mark_ids = marks.ids()?;
        let (kind, bytes) = match project_repo_bytes_in_txn(vault, txn, &marks, bytes)? {
            RepoBodyProjection::Exact(bytes) => return Ok(RepoIndexInput::stored(bytes)),
            RepoBodyProjection::Masked { bytes, .. } => (RepoIndexCopyKind::Masked, bytes),
            RepoBodyProjection::Opaque(_) => {
                (RepoIndexCopyKind::Opaque, REPO_OPAQUE_FILE_BYTES.to_vec())
            }
        };
        let stamp = RepoIndexProjectionStamp {
            source_blake3: *source,
            mark_ids,
            copy_blake3: *blake3::hash(&bytes).as_bytes(),
            kind,
            version: RepoIndexProjectionVersion::CURRENT,
        };
        Ok(RepoIndexInput {
            bytes,
            stamp: Some(stamp),
        })
    }

    /// `text` as an index reads it, joined by its own whole BLAKE3.
    ///
    /// # Errors
    /// As [`Self::input_in_txn`].
    pub(crate) fn text_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        text: String,
    ) -> Result<String> {
        if self.is_empty() {
            return Ok(text);
        }
        Ok(self
            .input_in_txn(vault, txn, text.into_bytes())?
            .into_text())
    }

    /// The body record `entity` indexes from: a marked blob's snapshot ASSET
    /// reads its copy, any other body by its own whole BLAKE3.
    ///
    /// # Errors
    /// As [`Self::input_in_txn`].
    pub(crate) fn body_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        body: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if self.is_empty() {
            return Ok(body);
        }
        Ok(match self.source_of(entity) {
            Some(source) => self.source_input_in_txn(vault, txn, &source, body)?,
            None => self.input_in_txn(vault, txn, body)?,
        }
        .into_bytes())
    }

    /// The text fields record `entity` indexes, each as its copy. A marked
    /// blob's snapshot ASSET (or the document it owns) reads its first field,
    /// its body text, as the blob's copy: masked when it is the blob's exact
    /// bytes, else the placeholder. Its other fields keep their text unless
    /// they are a marked blob's bytes, and an opaque blob's record reads the
    /// placeholder in every field, never its old title or tags. Any other
    /// record's field is a copy only when it is a marked blob's whole bytes.
    /// Every field stays, so the record stays searchable.
    ///
    /// # Errors
    /// As [`Self::input_in_txn`].
    pub(crate) fn fields_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        fields: Vec<(String, String)>,
    ) -> Result<Vec<(String, String)>> {
        if self.is_empty() {
            return Ok(fields);
        }
        let Some(source) = self.source_of(entity) else {
            return fields
                .into_iter()
                .map(|(name, value)| Ok((name, self.text_in_txn(vault, txn, value)?)))
                .collect();
        };
        let opaque = self.facts.for_hash(&source).opaque();
        let mut out = Vec::with_capacity(fields.len());
        for (index, (name, value)) in fields.into_iter().enumerate() {
            let value = if opaque {
                opaque_index_text()
            } else if index == 0 {
                self.source_input_in_txn(vault, txn, &source, value.into_bytes())?
                    .into_text()
            } else {
                self.text_in_txn(vault, txn, value)?
            };
            out.push((name, value));
        }
        Ok(out)
    }
}

/// [`RepoIndexMarks::fields_in_txn`] under the marks `txn` reads now: the
/// one call a text index makes between extracting a record's fields and
/// indexing them.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(crate) fn masked_repo_index_fields_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    fields: Vec<(String, String)>,
) -> Result<Vec<(String, String)>> {
    RepoIndexMarks::read_in_txn(vault, txn)?.fields_in_txn(vault, txn, entity, fields)
}

/// [`RepoIndexMarks::input_in_txn`] under the marks `txn` reads now, for a
/// door that derives one input.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(crate) fn masked_repo_index_input_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    bytes: Vec<u8>,
) -> Result<RepoIndexInput> {
    RepoIndexMarks::read_in_txn(vault, txn)?.input_in_txn(vault, txn, bytes)
}
