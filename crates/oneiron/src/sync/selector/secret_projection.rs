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
//!   `projection_edit_conflict` / `sealed_file_edited` results hold, each
//!   kept as a held record and never applied (FIX 10598).
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
mod held;
mod history;
mod reauthor;
mod release;
mod rows;

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
// FIX 10798: the derivation is featureless, so a source erase reaches the
// copy's rows in every build; this path keeps it for the copy leaves.
use crate::origin::secret_projection::copy_id::{REPO_SYNC_PROJECTION_SCHEMA, copy_id};
use crate::origin::secret_projection::index::{RepoIndexCopyKind, RepoIndexMarks};
use crate::origin::secret_projection::types::REPO_OPAQUE_FILE_BYTES;
use crate::ports::EntityStoreRead;
use crate::secret_custody::KeyPlaces;

pub(crate) use documents::{
    IndexCopies, document_copy_in_txn, import_document_copy, stored_item_in_txn,
    with_copy_generation_in_txn,
};
pub use documents::{
    RepoCopyAliases, repo_document_copy_id, repo_document_copy_vector, repo_document_lineage_edit,
    repo_document_source,
};
pub(crate) use history::ProjectedHistory;
pub use release::{
    RepoSyncAdmission, admit_repo_sync_frame, prepare_repo_sync_frame,
    prepare_repo_sync_frame_for_home, repo_copy_generation,
};
pub(crate) use release::{released_item_blob, released_update};
pub(crate) use rows::{CopyRow, InboundRow};

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
    /// Each marked blob whose copy this pass could not make (a mark that
    /// does not decode, a stored-bytes, mask or projection failure), by its
    /// whole BLAKE3: only the items it could mark take the marked path's
    /// fail-safe, never its stored bytes (FIX 10793).
    unread: BTreeMap<[u8; 32], RepoSyncProjectionId>,
    /// Marked snapshot ASSET id -> its blob's whole BLAKE3.
    sources: BTreeMap<EntityId, [u8; 32]>,
    /// Copy id -> the snapshot ASSET it stands for (injective).
    copies: BTreeMap<EntityId, EntityId>,
    /// Each copy's bytes -> the blob it was made from, for a row kept under
    /// its own id.
    copy_bodies: BTreeMap<[u8; 32], [u8; 32]>,
}

/// What one item is this pass: the per-item answer every release reads.
pub(crate) enum ItemCopy<'p> {
    /// Provably no marked item: its stored bytes, as today.
    Unmarked,
    /// A marked item: `bytes` under `key` (the copy id for a marked
    /// snapshot ASSET, the item's own id otherwise).
    Copy { key: EntityId, bytes: &'p [u8] },
    /// An item a marked blob whose copy is unread names: the sealed-file
    /// placeholder for an export, withheld for a window frame.
    Unread { key: EntityId },
}

/// The stamp an unread copy is fingerprinted by: no real stamp is all
/// zero, so a copy read again later is a new generation.
const UNREAD_STAMP: [u8; 32] = [0; 32];

impl SyncSecretProjection {
    /// The rules a sync copy and its id are made by (CALL 4-I, ruling (e),
    /// Engine 10-22 07:20). Part of every copy id and generation, so a change
    /// to them is a new copy everywhere.
    pub(crate) const SCHEMA: u16 = REPO_SYNC_PROJECTION_SCHEMA;

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
    /// blob. A blob whose copy fails is unread for this pass: only the
    /// items it could mark fail safe (FIX 10793).
    ///
    /// # Errors
    /// A store failure in the walk, or a mark that does not decode and
    /// names no blob: no item is then provably unmarked. Nothing falls back
    /// to the stored bytes.
    pub(crate) fn read_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<Self> {
        let marks = RepoIndexMarks::read_scoped_in_txn(vault, txn)?;
        let mut projection = Self {
            blobs: BTreeMap::new(),
            unread: BTreeMap::new(),
            sources: BTreeMap::new(),
            copies: BTreeMap::new(),
            copy_bodies: BTreeMap::new(),
        };
        for (source, hash) in marks.marked_sources() {
            let id = RepoSyncProjectionId {
                source,
                copy: copy_id(&source)?,
            };
            match blob_copy_in_txn(vault, txn, &marks, id, hash) {
                Ok(None) => continue,
                Ok(Some(blob)) => {
                    projection
                        .copy_bodies
                        .insert(*blake3::hash(&blob.copy).as_bytes(), hash);
                    projection.blobs.insert(hash, blob);
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "sync: a marked repo copy is unreadable; only the items it marks fail safe"
                    );
                    projection.unread.insert(hash, id);
                }
            }
            projection.sources.insert(source, hash);
            projection.copies.insert(id.copy, source);
        }
        Ok(projection)
    }

    /// No marked repo item: every release is today's bytes.
    pub(crate) fn is_empty(&self) -> bool {
        self.blobs.is_empty() && self.unread.is_empty()
    }

    /// The copy id a peer knows the marked snapshot ASSET `source` by.
    pub(crate) fn copy_of(&self, source: &EntityId) -> Option<EntityId> {
        self.sources
            .get(source)
            .and_then(|hash| self.id_of(hash))
            .map(|id| id.copy)
    }

    /// The source and copy ids of the marked blob `hash`, read or not.
    fn id_of(&self, hash: &[u8; 32]) -> Option<RepoSyncProjectionId> {
        self.blobs
            .get(hash)
            .map(|blob| blob.id)
            .or_else(|| self.unread.get(hash).copied())
    }

    /// What item `id`, whose body is `body`, is this pass. A marked snapshot
    /// ASSET moves to its copy id (its own exact bytes masked, any other body
    /// the placeholder); a known copy id keeps its id and carries its
    /// source's current copy, unless it already holds it (FIX 10795); any
    /// other item whose body is a marked blob's whole bytes keeps its id.
    pub(crate) fn item(&self, id: &EntityId, body: &[u8]) -> ItemCopy<'_> {
        if self.is_empty() {
            return ItemCopy::Unmarked;
        }
        let hash = *blake3::hash(body).as_bytes();
        // The marked blob `id` is bound to by id, and the copy id it keeps
        // when it is a copy id itself.
        let bound = match (self.sources.get(id), self.copies.get(id)) {
            (Some(marked), _) => Some((*marked, None)),
            (None, Some(source)) => self.sources.get(source).map(|marked| (*marked, Some(*id))),
            (None, None) => None,
        };
        if let Some((marked, copy_key)) = bound {
            let Some(blob) = self.blobs.get(&marked) else {
                return match (copy_key, self.unread.get(&marked)) {
                    (Some(key), _) => ItemCopy::Unread { key },
                    (None, Some(unread)) => ItemCopy::Unread { key: unread.copy },
                    (None, None) => ItemCopy::Unmarked,
                };
            };
            return match copy_key {
                Some(_) if self.copy_bodies.get(&hash) == Some(&marked) => ItemCopy::Unmarked,
                Some(key) => ItemCopy::Copy {
                    key,
                    bytes: blob.copy.as_slice(),
                },
                None => ItemCopy::Copy {
                    key: blob.id.copy,
                    bytes: if hash == marked {
                        blob.copy.as_slice()
                    } else {
                        REPO_OPAQUE_FILE_BYTES
                    },
                },
            };
        }
        match (self.blobs.get(&hash), self.unread.contains_key(&hash)) {
            (Some(blob), _) => ItemCopy::Copy {
                key: *id,
                bytes: blob.copy.as_slice(),
            },
            (None, true) => ItemCopy::Unread { key: *id },
            (None, false) => ItemCopy::Unmarked,
        }
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
            let Some(stamp) = self
                .sources
                .get(&source)
                .and_then(|hash| self.stamp_of(hash))
            else {
                continue;
            };
            hasher.update(source.as_bytes());
            hasher.update(&stamp);
        }
        *hasher.finalize().as_bytes()
    }

    /// The stamp of the marked blob `hash`'s copy; [`UNREAD_STAMP`] for an
    /// unread one.
    fn stamp_of(&self, hash: &[u8; 32]) -> Option<[u8; 32]> {
        match self.blobs.get(hash) {
            Some(blob) => Some(blob.stamp),
            None => self.unread.contains_key(hash).then_some(UNREAD_STAMP),
        }
    }

    /// The blob copy a marked snapshot ASSET stands for.
    fn blob_of_source(&self, source: &EntityId) -> Option<&BlobCopy> {
        self.sources
            .get(source)
            .and_then(|hash| self.blobs.get(hash))
    }
}

/// The copy of the marked blob `hash`, whose snapshot ASSET is `id.source`;
/// `None` when its marks leave it exact.
///
/// # Errors
/// A store failure, or this blob's own marks or mask row not reading.
fn blob_copy_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    id: RepoSyncProjectionId,
    hash: [u8; 32],
) -> Result<Option<BlobCopy>> {
    let stored = vault
        .store
        .port_entity_raw(txn, &id.source)?
        .and_then(|raw| raw.get(ENTITY_METADATA_HEADER_LEN..).map(<[u8]>::to_vec))
        .filter(|body| blake3::hash(body).as_bytes() == &hash);
    // Without its stored bytes the projector answers the sealed-file
    // placeholder: never an exact fallback.
    let input = marks.source_input_in_txn(vault, txn, &hash, stored.clone().unwrap_or_default())?;
    let Some(stamp) = input.stamp().cloned() else {
        return Ok(None);
    };
    let places = match (&stored, stamp.kind) {
        (Some(_), RepoIndexCopyKind::Masked) => marks.copy_places_in_txn(vault, txn, &hash)?,
        _ => None,
    };
    Ok(Some(BlobCopy {
        id,
        stored,
        copy: input.into_bytes(),
        places,
        stamp: stamp.fingerprint(),
    }))
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
