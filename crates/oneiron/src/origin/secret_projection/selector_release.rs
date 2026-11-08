//! The marked repo copies shared by scoped exports and sync adapters.
//!
//! One projection and one per-pass copy cache retain the existing masking,
//! copy identity, unread placeholders and generation fingerprints.
#![allow(
    dead_code,
    reason = "FIX 7608 slice 4, part 1: the release and inbound adapters call these when they activate together"
)]

mod cache;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use heed::RoTxn;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
// FIX 10798: the derivation is featureless, so a source erase reaches the
// copy's rows in every build; this path keeps it for the copy leaves.
use crate::origin::secret_projection::copy_id::{REPO_SYNC_PROJECTION_SCHEMA, copy_id};
use crate::origin::secret_projection::index::{RepoIndexCopyKind, RepoIndexMarks};
use crate::origin::secret_projection::types::REPO_OPAQUE_FILE_BYTES;
use crate::ports::EntityStoreRead;
use crate::secret_custody::KeyPlaces;

/// The domain a release's copy generation is fingerprinted in.
pub(crate) const GENERATION_CONTEXT: &str = "oneiron.repo-sync-projection.generation.v1";

/// Which source one copy stands for, and the copy's own id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RepoSyncProjectionId {
    /// The marked snapshot ASSET.
    pub(crate) source: EntityId,
    /// Its copy: derived from `source` under [`SyncSecretProjection::SCHEMA`].
    pub(crate) copy: EntityId,
}

/// One marked blob's copy for this pass.
pub(crate) struct BlobCopy {
    id: RepoSyncProjectionId,
    /// The stored bytes, when this vault still holds them: what an incoming
    /// edit of the copy is translated against. Never released, never kept
    /// past the pass.
    stored: Option<Vec<u8>>,
    /// Exactly the bytes a peer gets.
    copy: Arc<[u8]>,
    /// The BLAKE3 of `copy`.
    copy_hash: [u8; 32],
    /// The spans `copy` overwrites; `None` for the sealed-file placeholder.
    places: Option<Arc<KeyPlaces>>,
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
    /// items it could mark fail safe (FIX 10793). A marked snapshot ASSET
    /// whose stored bytes are now another marked blob (a landed copy edit's
    /// carried mark, FIX 10732) stands for that blob under its own copy id;
    /// its old blob keeps its placeholder copy.
    ///
    /// # Errors
    /// A store failure in the walk, or a mark that does not decode and
    /// names no blob: no item is then provably unmarked. Nothing falls back
    /// to the stored bytes.
    pub(crate) fn read_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<Self> {
        let marks = RepoIndexMarks::read_scoped_in_txn(vault, txn)?;
        let mut kept = cache::PassCopies::open(vault);
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
            let body = match vault.store.port_entity_raw(txn, &source) {
                Ok(raw) => {
                    raw.and_then(|raw| raw.get(ENTITY_METADATA_HEADER_LEN..).map(<[u8]>::to_vec))
                }
                Err(error) => {
                    projection.unreadable(id, hash, &error);
                    projection.sources.insert(source, hash);
                    projection.copies.insert(id.copy, source);
                    continue;
                }
            };
            let (stored, carried) = match body {
                Some(body) => {
                    let own = *blake3::hash(&body).as_bytes();
                    if own == hash {
                        (Some(body), None)
                    } else if marks.is_marked(&own) {
                        (None, Some((own, body)))
                    } else {
                        (None, None)
                    }
                }
                None => (None, None),
            };
            if !projection.take_blob(vault, txn, &marks, &mut kept, id, hash, stored) {
                continue;
            }
            let mut bound = hash;
            if let Some((own, body)) = carried
                && projection.take_blob(vault, txn, &marks, &mut kept, id, own, Some(body))
            {
                bound = own;
            }
            projection.sources.insert(source, bound);
            projection.copies.insert(id.copy, source);
        }
        kept.close();
        Ok(projection)
    }

    /// Makes the copy of the marked blob `hash` for `id` over `stored` and
    /// keeps it, or keeps the blob unread when its copy fails; `false` when
    /// its marks leave it exact. A copy over stored bytes is never replaced
    /// by one without.
    #[expect(
        clippy::too_many_arguments,
        reason = "the pass, its transaction and marks, and the one blob it makes"
    )]
    fn take_blob(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        marks: &RepoIndexMarks,
        kept: &mut cache::PassCopies,
        id: RepoSyncProjectionId,
        hash: [u8; 32],
        stored: Option<Vec<u8>>,
    ) -> bool {
        match blob_copy_in_txn(vault, txn, marks, kept, id, hash, stored) {
            Ok(None) => false,
            Ok(Some(blob)) => {
                let held = self
                    .blobs
                    .get(&hash)
                    .is_some_and(|held| held.stored.is_some());
                if blob.stored.is_some() || !held {
                    self.copy_bodies.insert(blob.copy_hash, hash);
                    self.blobs.insert(hash, blob);
                }
                true
            }
            Err(error) => {
                self.unreadable(id, hash, &error);
                true
            }
        }
    }

    /// Keeps the marked blob `hash` for `id` unread this pass: its copy
    /// failed with `error`.
    fn unreadable(&mut self, id: RepoSyncProjectionId, hash: [u8; 32], error: &Error) {
        tracing::warn!(
            %error,
            "sync: a marked repo copy is unreadable; only the items it marks fail safe"
        );
        self.unread.insert(hash, id);
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
                    bytes: &blob.copy[..],
                },
                None => ItemCopy::Copy {
                    key: blob.id.copy,
                    bytes: if hash == marked {
                        &blob.copy[..]
                    } else {
                        REPO_OPAQUE_FILE_BYTES
                    },
                },
            };
        }
        match (self.blobs.get(&hash), self.unread.contains_key(&hash)) {
            (Some(blob), _) => ItemCopy::Copy {
                key: *id,
                bytes: &blob.copy[..],
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
    pub(crate) fn stamp_of(&self, hash: &[u8; 32]) -> Option<[u8; 32]> {
        match self.blobs.get(hash) {
            Some(blob) => Some(blob.stamp),
            None => self.unread.contains_key(hash).then_some(UNREAD_STAMP),
        }
    }

    /// The blob copy a marked snapshot ASSET stands for.
    pub(crate) fn blob_of_source(&self, source: &EntityId) -> Option<&BlobCopy> {
        self.sources
            .get(source)
            .and_then(|hash| self.blobs.get(hash))
    }
}

/// The copy of the marked blob `hash` for the snapshot ASSET `id.source`,
/// over `stored`, its bytes when it holds exactly that blob's; `None` when
/// its marks leave it exact. A copy `kept` holds under the same stored
/// bytes, holding and spans is taken again (FIX 10599); any other is made
/// and kept.
///
/// # Errors
/// A store failure, or this blob's own marks or mask row not reading.
fn blob_copy_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    kept: &mut cache::PassCopies,
    id: RepoSyncProjectionId,
    hash: [u8; 32],
    stored: Option<Vec<u8>>,
) -> Result<Option<BlobCopy>> {
    // What the copy is made over: the spans the marks and mask row place now.
    // Read for every blob, so one whose mark does not decode fails here, kept
    // copy or not (FIX 10793).
    let placed = marks.copy_places_in_txn(vault, txn, &hash)?;
    let present = stored.is_some();
    let copy = match kept.take(&hash, present, placed.as_ref()) {
        Some(copy) => copy,
        None => {
            // Without its stored bytes the projector answers the sealed-file
            // placeholder: never an exact fallback.
            let input =
                marks.source_input_in_txn(vault, txn, &hash, stored.clone().unwrap_or_default())?;
            let Some(stamp) = input.stamp().cloned() else {
                return Ok(None);
            };
            let places = match (present, stamp.kind) {
                (true, RepoIndexCopyKind::Masked) => placed.clone(),
                _ => None,
            };
            kept.keep(
                hash,
                present,
                placed,
                input.into_bytes(),
                places,
                stamp.fingerprint(),
            )
        }
    };
    Ok(Some(BlobCopy {
        id,
        stored,
        copy: Arc::clone(&copy.copy),
        copy_hash: copy.copy_hash,
        places: copy.places.clone(),
        stamp: copy.stamp,
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

/// What a stored row becomes on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CopyRow {
    /// Not a marked item: its stored bytes, as today.
    Keep,
    /// The copy: under `key` (the copy id for a marked snapshot ASSET, else
    /// the row's own id), with the copy's bytes behind the stored header.
    Copy { key: EntityId, row: Vec<u8> },
    /// A row a marked blob whose copy is unread this pass could mark: the
    /// sealed-file placeholder behind the stored header, under `key`. An
    /// export carries it; a window frame carrying it is withheld and owed.
    Sealed { key: EntityId, row: Vec<u8> },
}

impl CopyRow {
    /// The bytes and id the row leaves under: `raw` under `id` when it is no
    /// marked item.
    pub(crate) fn released(self, id: EntityId, raw: Vec<u8>) -> (EntityId, Vec<u8>) {
        match self {
            Self::Keep => (id, raw),
            Self::Copy { key, row } | Self::Sealed { key, row } => (key, row),
        }
    }
}

impl SyncSecretProjection {
    /// Row `raw`, stored under `id`, as a peer gets it ([`Self::item`]): a
    /// marked snapshot ASSET moves to its copy id, a mismatched body under
    /// that id reads as the sealed-file placeholder, a known copy id carries
    /// its source's current copy, and any other row whose body is a marked
    /// blob's whole bytes keeps its id. A row an unread copy could mark is
    /// [`CopyRow::Sealed`].
    pub(crate) fn project_row(&self, id: &EntityId, raw: &[u8]) -> CopyRow {
        if self.is_empty() || raw.len() < ENTITY_METADATA_HEADER_LEN {
            return CopyRow::Keep;
        }
        let (header, body) = raw.split_at(ENTITY_METADATA_HEADER_LEN);
        match self.item(id, body) {
            ItemCopy::Unmarked => CopyRow::Keep,
            ItemCopy::Copy { key, bytes } => CopyRow::Copy {
                key,
                row: [header, bytes].concat(),
            },
            ItemCopy::Unread { key } => CopyRow::Sealed {
                key,
                row: [header, REPO_OPAQUE_FILE_BYTES].concat(),
            },
        }
    }
}

impl BlobCopy {
    pub(crate) fn copy(&self) -> &[u8] {
        &self.copy
    }

    pub(crate) fn stored(&self) -> Option<&[u8]> {
        self.stored.as_deref()
    }

    pub(crate) fn places(&self) -> Option<&KeyPlaces> {
        self.places.as_deref()
    }

    pub(crate) fn stamp(&self) -> [u8; 32] {
        self.stamp
    }
}

impl SyncSecretProjection {
    pub(crate) fn blob(&self, hash: &[u8; 32]) -> Option<&BlobCopy> {
        self.blobs.get(hash)
    }

    pub(crate) fn source_hash(&self, source: &EntityId) -> Option<&[u8; 32]> {
        self.sources.get(source)
    }

    pub(crate) fn source_ids(&self) -> impl Iterator<Item = &EntityId> {
        self.sources.keys()
    }

    pub(crate) fn source_hashes(&self) -> impl Iterator<Item = (&EntityId, &[u8; 32])> {
        self.sources.iter()
    }

    pub(crate) fn has_source(&self, source: &EntityId) -> bool {
        self.sources.contains_key(source)
    }

    pub(crate) fn unread_is_empty(&self) -> bool {
        self.unread.is_empty()
    }

    pub(crate) fn is_unread(&self, hash: &[u8; 32]) -> bool {
        self.unread.contains_key(hash)
    }

    pub(crate) fn copy_body_source_hash(&self, hash: &[u8; 32]) -> Option<&[u8; 32]> {
        self.copy_bodies.get(hash)
    }

    pub(crate) fn unread_stamp() -> [u8; 32] {
        UNREAD_STAMP
    }

    pub(crate) fn stamp_is_unread(stamp: &[u8; 32]) -> bool {
        *stamp == UNREAD_STAMP
    }
}
