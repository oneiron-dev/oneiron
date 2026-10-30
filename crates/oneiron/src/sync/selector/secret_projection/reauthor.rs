//! A marked snapshot ASSET's current copy, written again for a home that may
//! hold an older one (FIX 10729, option (b), lead ruling 10-26 13:3x).
//!
//! Loro keeps the first operation it knew under an id, and a home never
//! installs a device's window (it refuses a device REPLACEMENT), so an
//! operation released once with an older copy is never corrected by sending
//! it again. A device's send to its home therefore also carries, for each
//! marked snapshot ASSET its window holds, one fresh register operation
//! writing the current copy under the copy id, and for each row kept under
//! its own id whose body is a marked blob's whole bytes, one writing its copy
//! under that id (FIX 10874). Its peer is derived from the source (the row's
//! own id for the latter), this device and the copy's stamp: a new stamp (a
//! later mark, a re-mask) is a fresh id, never a raw operation's, and the
//! operation's later Lamport wins over the older copy wherever it lands. Its
//! value is the copy itself, so the release passes it as it is, and nothing
//! raw is in it.
//!
//! A home sends the operation back like any other. Its peer names its
//! source, so a holder of the stored bytes lands it as the stored row and
//! never diffs an older copy as an edit, whatever generation of the copy it
//! carries. A device whose window already holds the operation for the
//! current stamp writes none.

use loro::{ExportMode, IdSpan, LoroDoc, LoroValue, PeerID, ValueOrContainer};

use super::frames::isolated;
use super::{CopyRow, InboundRow, SyncSecretProjection};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncEngineContext};
use crate::store::Store;

/// The domain a re-authoring peer is derived in.
const REAUTHOR_CONTEXT: &str = "oneiron.repo-sync-projection.reauthor.v1";

/// The root map whose values are rows.
const ROWS: &str = "entities";

/// How far a re-authoring peer's source bits sit: the low 31 bits name the
/// device and stamp, the next 32 the source.
const SOURCE_SHIFT: u32 = 31;

/// One register a release writes again.
struct Reauthor {
    peer: PeerID,
    key: EntityId,
    row: Vec<u8>,
}

impl SyncSecretProjection {
    /// `encoded`, an update `local`'s window `context` sends its home and
    /// that otherwise goes as it is (its `spans`), with each marked snapshot
    /// ASSET's current copy written again under a fresh id. `made` is the
    /// isolated window copy already holding the update, when the release
    /// made one (FIX 10599); otherwise one is made here. `None` when the
    /// window holds every such operation already, or when the update does
    /// not import whole on a copy of the window: the blob goes as it came.
    ///
    /// # Errors
    /// A failure writing or exporting the operations.
    pub(super) fn reauthored(
        &self,
        store: &Store,
        context: &LoroDoc,
        local: PeerID,
        encoded: &[u8],
        mut spans: Vec<IdSpan>,
        made: Option<LoroDoc>,
    ) -> Result<Option<Vec<u8>>> {
        let wanted = self.reauthors(store, context, local);
        if wanted.is_empty() {
            return Ok(None);
        }
        let target = match made {
            Some(target) => target,
            None => {
                let Some(target) = isolated(Some(context)) else {
                    return Ok(None);
                };
                if target
                    .import(encoded)
                    .ok()
                    .is_none_or(|status| status.pending.is_some())
                {
                    return Ok(None);
                }
                target
            }
        };
        let rows = target.get_map(ROWS);
        let mut written = false;
        for Reauthor { peer, key, row } in wanted {
            target.commit();
            target
                .set_peer_id(peer)
                .map_err(|_| Error::InvariantViolation("re-authored copy peer"))?;
            rows.insert(&key.to_hex(), LoroValue::Binary(row.into()))
                .map_err(|_| Error::InvariantViolation("re-authored copy register"))?;
            target.commit();
            if let Some(end) = target.oplog_vv().get(&peer).copied().filter(|end| *end > 0) {
                spans.push(IdSpan::new(peer, 0, end));
                written = true;
            }
        }
        if !written {
            return Ok(None);
        }
        spans.sort_by_key(|span| span.peer);
        target
            .export(ExportMode::updates_in_range(spans))
            .map(Some)
            .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))
    }

    /// The registers `context`, `local`'s window, needs written again: each
    /// marked snapshot ASSET row it holds whose copy this pass made, and each
    /// row under its own id whose body is a marked blob's whole bytes (FIX
    /// 10874), unless the window already holds its operation for that copy's
    /// stamp.
    fn reauthors(&self, store: &Store, context: &LoroDoc, local: PeerID) -> Vec<Reauthor> {
        let rows = context.get_map(ROWS);
        let held = context.oplog_vv();
        let mut wanted = Vec::new();
        for (source, hash) in &self.sources {
            let Some(blob) = self.blobs.get(hash) else {
                continue;
            };
            let peer = reauthor_peer(local, source, &blob.stamp);
            if held.get(&peer).is_some() {
                continue;
            }
            let Some(loro::ValueOrContainer::Value(LoroValue::Binary(value))) =
                rows.get(&source.to_hex())
            else {
                continue;
            };
            let raw: &[u8] = &value;
            let carrier = crate::world_keys::image_pad_row(store, raw);
            if let CopyRow::Copy { key, row } =
                self.project_row(source, carrier.as_deref().unwrap_or(raw))
            {
                wanted.push(Reauthor { peer, key, row });
            }
        }
        rows.for_each(|key, value| {
            let (Ok(id), ValueOrContainer::Value(LoroValue::Binary(value))) =
                (EntityId::from_hex(key), value)
            else {
                return;
            };
            // A marked source and a copy id take the arm above.
            if self.binds(&id) {
                return;
            }
            let raw: &[u8] = &value;
            let carrier = crate::world_keys::image_pad_row(store, raw);
            let row = carrier.as_deref().unwrap_or(raw);
            let Some(blob) = row
                .get(ENTITY_METADATA_HEADER_LEN..)
                .and_then(|body| self.blobs.get(blake3::hash(body).as_bytes()))
            else {
                return;
            };
            let peer = reauthor_peer(local, &id, &blob.stamp);
            if held.get(&peer).is_some() {
                return;
            }
            if let CopyRow::Copy { key, row } = self.project_row(&id, row) {
                wanted.push(Reauthor { peer, key, row });
            }
        });
        wanted
    }

    /// `submitted`, a row `peer` wrote under the copy id `key`, when `peer`
    /// re-authored that copy (any device's, any stamp): it carries no edit,
    /// so it lands as the stored row. `None` for any other row, and when
    /// this pass holds no stored bytes for its source.
    pub(super) fn reauthored_row(
        &self,
        peer: PeerID,
        key: &EntityId,
        submitted: &[u8],
    ) -> Option<InboundRow> {
        let source = self.source_of_copy(key)?;
        if peer >> SOURCE_SHIFT != u64::from(source_bits(&source)) {
            return None;
        }
        let stored = self.blob_of_source(&source)?.stored.as_ref()?;
        let header = submitted.get(..ENTITY_METADATA_HEADER_LEN)?;
        Some(InboundRow::Source {
            id: source,
            row: [header, stored.as_slice()].concat(),
        })
    }

    /// `submitted`, a row `peer` wrote under its own id `key`, when `peer`
    /// re-authored that row's copy (FIX 10874, any device's, any stamp) and
    /// this window (`context`) holds the row as a marked blob's whole bytes:
    /// it carries no edit, so it lands as the stored row, never as an older
    /// copy's masked bytes. `None` for any other row.
    pub(super) fn reauthored_own_row(
        &self,
        store: &Store,
        context: Option<&LoroDoc>,
        peer: PeerID,
        key: &EntityId,
        submitted: &[u8],
    ) -> Option<InboundRow> {
        if self.binds(key) || peer >> SOURCE_SHIFT != u64::from(source_bits(key)) {
            return None;
        }
        let Some(ValueOrContainer::Value(LoroValue::Binary(value))) =
            context?.get_map(ROWS).get(&key.to_hex())
        else {
            return None;
        };
        let raw: &[u8] = &value;
        let carrier = crate::world_keys::image_pad_row(store, raw);
        let body = carrier.as_deref().unwrap_or(raw).get(ENTITY_METADATA_HEADER_LEN..)?;
        let hash = blake3::hash(body);
        if !self.blobs.contains_key(hash.as_bytes()) && !self.unread.contains_key(hash.as_bytes()) {
            return None;
        }
        let header = submitted.get(..ENTITY_METADATA_HEADER_LEN)?;
        Some(InboundRow::Source {
            id: *key,
            row: [header, body].concat(),
        })
    }
}

/// The peer `local` re-authors `source`'s copy stamped `stamp` by (`source`
/// a marked snapshot ASSET, or a row kept under its own id): the source's
/// bits above, the device's and stamp's below. 63 bits.
fn reauthor_peer(local: PeerID, source: &EntityId, stamp: &[u8; 32]) -> PeerID {
    let mut material = Vec::with_capacity(2 + 16 + 8 + 32);
    material.extend_from_slice(&SyncSecretProjection::SCHEMA.to_be_bytes());
    material.extend_from_slice(source.as_bytes());
    material.extend_from_slice(&local.to_be_bytes());
    material.extend_from_slice(stamp);
    let key = blake3::derive_key(REAUTHOR_CONTEXT, &material);
    let low = u32::from_be_bytes([key[0], key[1], key[2], key[3]]) >> 1;
    (u64::from(source_bits(source)) << SOURCE_SHIFT) | u64::from(low)
}

/// The 32 bits every re-authoring peer of `source` carries.
fn source_bits(source: &EntityId) -> u32 {
    let mut material = Vec::with_capacity(2 + 16);
    material.extend_from_slice(&SyncSecretProjection::SCHEMA.to_be_bytes());
    material.extend_from_slice(source.as_bytes());
    let key = blake3::derive_key(REAUTHOR_CONTEXT, &material);
    u32::from_be_bytes([key[0], key[1], key[2], key[3]])
}
