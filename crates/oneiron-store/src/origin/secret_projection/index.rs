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
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use heed::RoTxn;

use crate::code_snapshot::ids::codebase_asset_entity_id as snapshot_asset_entity_id;
use crate::origin::secret_projection::types::REPO_OPAQUE_FILE_BYTES;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The domain of a copy stamp's fingerprint.
const REPO_INDEX_STAMP_CONTEXT: &str = "oneiron.repo-index-projection.stamp.v1";

/// The domain of a mark generation's digest.
pub const REPO_MARK_GENERATION_CONTEXT: &str = "oneiron.repo-index-projection.mark-generation.v1";

/// What a sync release does with a mark failure no blob is tied to (a mark
/// claim that does not decode and names no blob, or a store failure in the
/// mark walk), when no item is then provably unmarked (CALL
/// S4FIX-UNKNOWN-MARK; review F4 rule, ruling A3): `true` fails that pass
/// closed with the error, never raw; `false` would go on without the mark
/// and report it. A mark tied to its blob fails only that blob's items.
pub const UNATTRIBUTABLE_MARK_FAILS_CLOSED: bool = true;

/// The rules an index copy is made by (CALL 3-I, ruling (d), Engine 10-22
/// 07:20): part of every copy's stamp, so a change to them rebuilds only the
/// copies it changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RepoIndexProjectionVersion(pub u16);

impl RepoIndexProjectionVersion {
    /// Copies are the masked projection or the sealed-file placeholder.
    pub const CURRENT: Self = Self(1);

    pub const fn get(self) -> u16 {
        self.0
    }
}

/// How an index copy stands in for its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoIndexCopyKind {
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
pub struct RepoIndexProjectionStamp {
    /// The whole BLAKE3 of the stored blob the copy stands in for.
    pub source_blake3: [u8; 32],
    /// Every readable mark of that blob, sorted.
    pub mark_ids: Vec<EntityId>,
    /// The BLAKE3 of exactly the copy's bytes: a later mask on the same mark
    /// ids changes it.
    pub copy_blake3: [u8; 32],
    pub kind: RepoIndexCopyKind,
    pub version: RepoIndexProjectionVersion,
}

impl RepoIndexProjectionStamp {
    /// One digest of every field: the identity a derived work item commits
    /// to.
    #[allow(
        dead_code,
        reason = "the copy identity a CALL 3-I version change rebuilds by"
    )]
    pub fn fingerprint(&self) -> [u8; 32] {
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
pub struct RepoIndexInput {
    pub bytes: Vec<u8>,
    pub stamp: Option<RepoIndexProjectionStamp>,
}

impl RepoIndexInput {
    pub fn stored(bytes: Vec<u8>) -> Self {
        Self { bytes, stamp: None }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The copy's stamp; `None` for stored bytes.
    pub fn stamp(&self) -> Option<&RepoIndexProjectionStamp> {
        self.stamp.as_ref()
    }

    /// Whether the input is the sealed-file placeholder.
    pub fn opaque(&self) -> bool {
        self.stamp
            .as_ref()
            .is_some_and(|stamp| stamp.kind == RepoIndexCopyKind::Opaque)
    }

    /// The input as text: a copy that no longer decodes keeps every other
    /// character.
    pub fn into_text(self) -> String {
        text_of(self.bytes)
    }
}

/// `bytes` as text, each undecodable sequence replaced.
fn text_of(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
}

/// The sealed-file placeholder as text.
pub fn opaque_index_text() -> String {
    text_of(REPO_OPAQUE_FILE_BYTES.to_vec())
}
