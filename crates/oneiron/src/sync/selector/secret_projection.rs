//! The masked copy every sync peer gets of a marked repo item (FIX 7608
//! slice 4; ruling A3: sync always carries the masked copy, owner-linked
//! devices included, while the human owner door stays exact on every
//! device).
//!
//! A copy only replaces bytes. The canonical rows, windows, documents and
//! queues on this device stay exactly as stored; what leaves it is derived
//! from them at release, and what arrives on a copy is translated back to
//! its source before anything canonical changes. The two roles never meet
//! in one store:
//!
//! - **Source and copy are bound, never conflated.** A marked snapshot
//!   ASSET's copy has its own id ([`RepoSyncProjectionId`]), derived from
//!   the source id alone: the alias is injective and outlives a re-mask, so
//!   an edit a peer made on an older copy still resolves to its source and
//!   is diffed against the current copy (never imported as a new row). The
//!   copy's bytes are named by its stamp, not its id. Any other row whose
//!   body is a marked blob's whole bytes keeps its id and carries the copy's
//!   bytes in place. Edges, tombstones and side-map keys follow the alias.
//! - **One read per pass.** The marks, each copy, its spans and its stamp
//!   are read once ([`SyncSecretProjection::read_in_txn`]) through slice 3's
//!   [`RepoIndexMarks`]; nothing here detects, masks or diffs on its own.
//! - **A copy's generation is its stamp, not a version vector.** The
//!   generation a release carries ([`SyncSecretProjection::generation`])
//!   commits to every copy it projects; a peer, cache or queue item bound to
//!   another generation gets a replacement, even when its version vector is
//!   equal (GAP 2 of the s4 soundness read).
//! - **Structure is kept only where it provably holds.** A map register's
//!   value may change length inside its one operation unit, so a window's
//!   map history keeps its operation ids with each value and key aliased
//!   ([`history`]). A text or list payload whose unit count a mask may change
//!   never takes that path: it ships as its separate copy lineage.
//! - **Incoming copy edits are translated, never imported raw.** A copy key
//!   resolves to its source, a copy row to the stored bytes, and a changed
//!   body goes through the shipped visible diff; only its ruled
//!   `projection_edit_conflict` / `sealed_file_edited` results hold.
//!
//! The source -> copy map is derived, never stored: its rules are
//! [`SyncSecretProjection::SCHEMA`] (CALL 4-I, ruling (e)), its lifetime is
//! its source's, with no TTL or cap, and no peer learns a source id from
//! it. A masked lookup's store error propagates; nothing falls back to the
//! stored bytes (Engine 10-22 05:5x).
#![allow(
    dead_code,
    reason = "FIX 7608 slice 4, part 1: the release and inbound adapters call these when they activate together"
)]

mod documents;
mod frames;
mod history;
mod release;
mod rows;

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::secret_projection::index::{RepoIndexCopyKind, RepoIndexMarks};
use crate::ports::EntityStoreRead;
use crate::secret_custody::KeyPlaces;

pub(crate) use documents::{
    DocumentCopy, alias_index_entries, document_copy_in_txn, import_document_copy,
    stored_item_in_txn, with_copy_generation_in_txn,
};
pub use documents::{RepoCopyAliases, repo_document_copy_vector, repo_document_source};
pub(crate) use history::ProjectedHistory;
pub use release::{
    RepoSyncAdmission, admit_repo_sync_frame, prepare_repo_sync_frame, repo_copy_generation,
};
pub(crate) use release::{released_item_blob, released_update};
pub(crate) use rows::{CopyRow, InboundRow};

/// The domain a copy id is derived in.
const COPY_ID_CONTEXT: &str = "oneiron.repo-sync-projection.copy-id.v1";
/// The domain a release's copy generation is fingerprinted in.
const GENERATION_CONTEXT: &str = "oneiron.repo-sync-projection.generation.v1";

/// Which source one copy stands for, and the copy's own id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RepoSyncProjectionId {
    /// The marked snapshot ASSET.
    pub(crate) source: EntityId,
    /// Its copy: derived from `source` under [`SyncSecretProjection::SCHEMA`].
    pub(crate) copy: EntityId,
}

/// One marked blob's copy for this pass.
struct BlobCopy {
    id: RepoSyncProjectionId,
    /// The stored bytes, when this vault still holds them: what an incoming
    /// edit of the copy is translated against. Never released.
    stored: Option<Vec<u8>>,
    /// Exactly the bytes a peer gets.
    copy: Vec<u8>,
    /// The spans `copy` overwrites; `None` for the sealed-file placeholder.
    places: Option<KeyPlaces>,
    /// The slice-3 stamp fingerprint: source, marks, actual copy bytes,
    /// kind and rules.
    stamp: [u8; 32],
}

/// Every marked repo copy one sync pass releases or admits.
pub(crate) struct SyncSecretProjection {
    /// Each marked blob's copy, by the blob's whole BLAKE3.
    blobs: BTreeMap<[u8; 32], BlobCopy>,
    /// Marked snapshot ASSET id -> its blob's whole BLAKE3.
    sources: BTreeMap<EntityId, [u8; 32]>,
    /// Copy id -> the snapshot ASSET it stands for (injective).
    copies: BTreeMap<EntityId, EntityId>,
    /// Each copy's bytes -> the blob it was made from, for a row kept under
    /// its own id.
    copy_bodies: BTreeMap<[u8; 32], [u8; 32]>,
}

impl SyncSecretProjection {
    /// The rules a sync copy and its id are made by (CALL 4-I, ruling (e),
    /// Engine 10-22 07:20). Part of every copy id and generation, so a change
    /// to them is a new copy everywhere.
    pub(crate) const SCHEMA: u16 = 1;

    /// The copies this vault releases now, read in a fresh read transaction.
    /// Never call it while this thread holds another read transaction.
    ///
    /// # Errors
    /// A store failure, or a mark that does not decode.
    pub(crate) fn read(vault: &Vault) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        Self::read_in_txn(vault, &txn)
    }

    /// The copies `txn` reads: one mark walk, one projection per marked
    /// blob.
    ///
    /// # Errors
    /// A store failure, or a mark that does not decode. A masked lookup's
    /// store error propagates; nothing falls back to the stored bytes.
    pub(crate) fn read_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<Self> {
        let marks = RepoIndexMarks::read_in_txn(vault, txn)?;
        let mut projection = Self {
            blobs: BTreeMap::new(),
            sources: BTreeMap::new(),
            copies: BTreeMap::new(),
            copy_bodies: BTreeMap::new(),
        };
        for (source, hash) in marks.marked_sources() {
            let stored = vault
                .store
                .port_entity_raw(txn, &source)?
                .and_then(|raw| raw.get(ENTITY_METADATA_HEADER_LEN..).map(<[u8]>::to_vec))
                .filter(|body| blake3::hash(body).as_bytes() == &hash);
            // Without its stored bytes the projector answers the sealed-file
            // placeholder: never an exact fallback.
            let input =
                marks.source_input_in_txn(vault, txn, &hash, stored.clone().unwrap_or_default())?;
            let Some(stamp) = input.stamp().cloned() else {
                continue;
            };
            let places = match (&stored, stamp.kind) {
                (Some(_), RepoIndexCopyKind::Masked) => {
                    marks.copy_places_in_txn(vault, txn, &hash)?
                }
                _ => None,
            };
            let copy = input.into_bytes();
            let id = RepoSyncProjectionId {
                source,
                copy: copy_id(&source)?,
            };
            projection.sources.insert(source, hash);
            projection.copies.insert(id.copy, source);
            projection.copy_bodies.insert(stamp.copy_blake3, hash);
            projection.blobs.insert(
                hash,
                BlobCopy {
                    id,
                    stored,
                    copy,
                    places,
                    stamp: stamp.fingerprint(),
                },
            );
        }
        Ok(projection)
    }

    /// No marked repo item: every release is today's bytes.
    pub(crate) fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// The copy id a peer knows the marked snapshot ASSET `source` by.
    pub(crate) fn copy_of(&self, source: &EntityId) -> Option<EntityId> {
        let hash = self.sources.get(source)?;
        self.blobs.get(hash).map(|blob| blob.id.copy)
    }

    /// The marked snapshot ASSET the copy id `copy` stands for.
    pub(crate) fn source_of_copy(&self, copy: &EntityId) -> Option<EntityId> {
        self.copies.get(copy).copied()
    }

    /// Whether `id` is a marked source or one of its copies: an item whose
    /// release or admission goes through this projection.
    pub(crate) fn binds(&self, id: &EntityId) -> bool {
        self.sources.contains_key(id) || self.copies.contains_key(id)
    }

    /// `key` with every marked source id segment (`:`-separated) replaced by
    /// its copy id; `None` when no segment is a marked source.
    pub(crate) fn rekey(&self, key: &str) -> Option<String> {
        alias_segments(key, |id| self.copy_of(id))
    }

    /// `key` with every copy id segment replaced by its source id: the key
    /// an incoming copy operation targets canonically.
    pub(crate) fn source_key(&self, key: &str) -> Option<String> {
        alias_segments(key, |id| self.source_of_copy(id))
    }

    /// The copy generation a release carrying the marked sources `sources`
    /// is made under: one fingerprint over each copy's stamp. Equal for two
    /// releases only when every copy they carry is byte-identical under the
    /// same rules; a mask that changes spans under the same mark ids changes
    /// it.
    pub(crate) fn generation<I: IntoIterator<Item = EntityId>>(&self, sources: I) -> [u8; 32] {
        let carried: BTreeSet<EntityId> = sources.into_iter().collect();
        let mut hasher = blake3::Hasher::new_derive_key(GENERATION_CONTEXT);
        hasher.update(&Self::SCHEMA.to_be_bytes());
        for source in carried {
            let Some(blob) = self
                .sources
                .get(&source)
                .and_then(|hash| self.blobs.get(hash))
            else {
                continue;
            };
            hasher.update(source.as_bytes());
            hasher.update(&blob.stamp);
        }
        *hasher.finalize().as_bytes()
    }

    /// The blob copy a marked snapshot ASSET stands for.
    fn blob_of_source(&self, source: &EntityId) -> Option<&BlobCopy> {
        self.sources
            .get(source)
            .and_then(|hash| self.blobs.get(hash))
    }
}

/// The copy id of the marked snapshot ASSET `source`: an ASSET id (the
/// codebase derivation) over a digest of the rules and the source id. One
/// source, one copy id, for every generation of its copy.
fn copy_id(source: &EntityId) -> Result<EntityId> {
    let mut material = Vec::with_capacity(2 + 16);
    material.extend_from_slice(&SyncSecretProjection::SCHEMA.to_be_bytes());
    material.extend_from_slice(source.as_bytes());
    crate::codebase::snapshot_asset_entity_id(&blake3::derive_key(COPY_ID_CONTEXT, &material))
}

/// `key` with each 32-hex segment `alias` names replaced; `None` when none
/// is.
fn alias_segments<F>(key: &str, alias: F) -> Option<String>
where
    F: Fn(&EntityId) -> Option<EntityId>,
{
    let mut changed = false;
    let mut out = Vec::new();
    for part in key.split(':') {
        let aliased = (part.len() == 32)
            .then(|| EntityId::from_hex(part).ok())
            .flatten()
            .and_then(|id| alias(&id));
        match aliased {
            Some(id) => {
                changed = true;
                out.push(id.to_hex());
            }
            None => out.push(part.to_owned()),
        }
    }
    changed.then(|| out.join(":"))
}
