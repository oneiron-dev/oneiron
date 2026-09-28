//! Grant-checked, per-item residence projections over a window document.
//! Window keys stay opaque here so a world-plus-month key has the same shape.

#[cfg(test)]
mod tests;

mod discover;
pub use discover::discover_local_window_keys;

#[cfg(test)]
use loro::ExportMode;
use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroValue};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::federation::FederationGrantScope;

#[cfg(test)]
use super::loro_support::map_insert_bytes;
use super::loro_support::{map_for_each_value_bytes, map_get_bytes};
#[cfg(test)]
use super::schema::create_window_doc;
use super::selector::{SyncSelector, filtered_window_doc};
use super::types::WindowKey;

/// Collect the actor-readable lexical candidate set before applying a
/// residence grant. The underlying scoped search already scores the full
/// indexed corpus; requesting the same candidate count prevents a narrowed
/// residence grant from exhausting a smaller top-k before intersection.
pub fn home_search_candidates(
    vault: &Vault,
    proof: &crate::authority::VerifiedSlip,
    query: &str,
    limit: usize,
) -> Result<Vec<(EntityId, f32, WindowKey)>> {
    let actor = crate::claim::ScopedReadActorKey::from_verified_slip(proof).ok_or(
        Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied),
    )?;
    let candidates = vault.scoped_read_search_candidate_limit(limit, true, false)?;
    let mut results = Vec::new();
    for hit in vault
        .scoped_read(actor)
        .search_text(query, candidates, None)?
        .value
    {
        let Some(raw) = vault.get_raw(&hit.id)? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("home search entity header"))?;
        results.push((
            hit.id,
            hit.score,
            WindowKey::from_timestamp(header.learned_at),
        ));
    }
    Ok(results)
}

/// The maximum number of metadata rows returned in one index page.
pub const INDEX_PAGE_MAX: usize = 256;
/// A bounded promotion snapshot fits inside the app RPC result after base64
/// expansion. Above this, do not perform a partial promotion.
pub const MAX_PROMOTION_SNAPSHOT_BYTES: usize = 22 * 1024 * 1024;

/// One metadata-only entry: the body and CRDT history are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowIndexEntry {
    pub entity_id: String,
    pub title: Option<String>,
    pub learned_at: u64,
}

/// Pagination over an already selected metadata projection. No Loro history
/// is exported when moving from one page to the next.
#[derive(Debug, Clone, Copy)]
pub struct IndexPage {
    /// Exclusive entity ID cursor, never an offset into an unfiltered window.
    pub after: Option<EntityId>,
    pub limit: usize,
}

/// Lightweight cross-page revision of read policy and the materialized
/// graph. Neither ordinary clock reads nor app RPC bookkeeping move these.
/// A change to a facet edge or retrieval floor invalidates cached selection.
pub fn index_selection_revision(vault: &Vault) -> Result<([u8; 32], u64, u64)> {
    let txn = vault.store.env.read_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    Ok((
        policy.read_frontier_hash()?,
        crate::ppr::read_graph_version(&vault.store, &txn)?,
        crate::federation::record_scope::read_scope_revision(&vault.store, &txn)?,
    ))
}

/// Authorize one window and build a metadata-only, sorted projection ONCE.
/// The server retains it for a bounded socket session; every later page
/// rechecks the grant, snapshot revision and live actor read floor.
pub fn window_index_projection(
    vault: &Vault,
    source: &LoroDoc,
    window: &WindowKey,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    title_max_chars: usize,
    mut readable: impl FnMut(EntityId) -> Result<bool>,
) -> Result<Vec<WindowIndexEntry>> {
    let selected = filtered_window_doc(vault, source, window, scope, selector)?;
    let mut entries = Vec::new();
    let mut result = Ok(());
    map_for_each_value_bytes(&selected.get_map("entities"), |key, blob| {
        if result.is_err() {
            return;
        }
        let (Ok(id), Some(blob)) = (EntityId::from_hex(key), blob) else {
            return;
        };
        if id.to_hex() != key {
            return;
        }
        let Some(header) = EntityMetadataHeader::parse(blob) else {
            return;
        };
        match readable(id) {
            Ok(true) => entries.push(WindowIndexEntry {
                entity_id: key.to_owned(),
                title: title_from_body(&blob[ENTITY_METADATA_HEADER_LEN..], title_max_chars),
                learned_at: header.learned_at,
            }),
            Ok(false) => {}
            Err(error) => result = Err(error),
        }
    });
    result?;
    entries.sort_unstable_by(|a, b| a.entity_id.cmp(&b.entity_id));
    Ok(entries)
}

/// Slice a previously authorized projection in O(log N + page size), with no
/// full-window Loro export or selector rebuild.
pub fn window_index_page(
    entries: &[WindowIndexEntry],
    page: IndexPage,
) -> Result<Vec<WindowIndexEntry>> {
    if page.limit == 0 || page.limit > INDEX_PAGE_MAX {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::DocumentAdmissionDenied,
        ));
    }
    let start = page.after.map_or(0, |cursor| {
        let after = cursor.to_hex();
        entries.partition_point(|entry| entry.entity_id <= after)
    });
    Ok(entries
        .iter()
        .skip(start)
        .take(page.limit)
        .cloned()
        .collect())
}

/// Read one grant-selected body without creating any Loro operations on the
/// device. The returned value is a read-only cache entry until its whole
/// canonical window is promoted for an edit.
pub fn selected_item_blob(
    vault: &Vault,
    source: &LoroDoc,
    window: &WindowKey,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    item: EntityId,
) -> Result<Option<Vec<u8>>> {
    let selected = filtered_window_doc(vault, source, window, scope, selector)?;
    Ok(map_get_bytes(&selected.get_map("entities"), &item.to_hex()))
}

/// Refuse a local put at an item held only as a thin read cache. The check
/// runs in the applying transaction; rematerialized replicated rows bypass it
/// through their separately admitted sync origin, never a caller-supplied flag.
pub(crate) fn require_promoted_for_cached_id(
    store: &crate::store::Store,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(window) = store
        .sync_state
        .get(txn, &format!("ro:e:{}", id.to_hex()))?
    else {
        return Ok(());
    };
    let window = std::str::from_utf8(&window).map_err(|_| Error::InvalidKey)?;
    if WindowKey::try_new(window).is_none()
        || store
            .sync_state
            .get(txn, &format!("rp:w:{window}"))?
            .is_none()
    {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::ThinItemRequiresPromotion,
        ));
    }
    Ok(())
}

/// Inspect every incoming operation before an opened-item update reaches
/// the observed home document. Only writes to EXISTING selected items with
/// a stable birth scope can run on the thin residence lane. Other operation
/// families use their own admitted doors; they are not smuggled as item edits.
pub fn admit_promoted_window_update(
    vault: &Vault,
    source: &LoroDoc,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    proof: &crate::authority::VerifiedSlip,
    update: &[u8],
) -> Result<()> {
    let malformed = || Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied);
    let metadata = LoroDoc::decode_import_blob_meta(update, true).map_err(|_| malformed())?;
    if metadata.mode.is_snapshot() {
        return Err(malformed());
    }
    let candidate = source.fork();
    let status = candidate.import(update).map_err(|_| malformed())?;
    if status.pending.is_some() {
        return Err(malformed());
    }
    let operations =
        candidate.export_json_updates(&metadata.partial_start_vv, &metadata.partial_end_vv);
    let expected = metadata
        .partial_end_vv
        .iter()
        .try_fold(0_usize, |sum, (peer, end)| {
            let start = metadata.partial_start_vv.get(peer).copied().unwrap_or(0);
            sum.checked_add(usize::try_from(end.checked_sub(start)?).ok()?)
        });
    let inspected = operations
        .changes
        .iter()
        .flat_map(|change| &change.ops)
        .try_fold(0_usize, |sum, op| sum.checked_add(op.content.op_len()));
    if expected.is_none() || expected != inspected {
        return Err(malformed());
    }
    let entities = ContainerID::new_root("entities", ContainerType::Map);
    let txn = vault.store.env.read_txn()?;
    for op in operations.changes.into_iter().flat_map(|change| change.ops) {
        let JsonOpContent::Map(MapOp::Insert {
            key,
            value: LoroValue::Binary(blob),
        }) = op.content
        else {
            return Err(malformed());
        };
        if op.container != entities {
            return Err(malformed());
        }
        let id = EntityId::from_hex(&key).map_err(|_| malformed())?;
        if key != id.to_hex() {
            return Err(malformed());
        }
        super::selector::admit_promoted_entity_write_in_txn(
            vault, &txn, id, &blob, scope, selector, proof,
        )?;
    }
    Ok(())
}

/// Export the canonical window, not the selector's synthetic document.
/// The selector and actor read floor must cover EVERY currently carried row;
/// otherwise full-window promotion would disclose another principal's data.
/// A shallow snapshot carries the home frontier but not pre-promotion history.
pub fn promotion_snapshot(
    vault: &Vault,
    source: &LoroDoc,
    window: &WindowKey,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    readable: impl FnMut(EntityId) -> Result<bool>,
) -> Result<Option<Vec<u8>>> {
    if !promotion_covers_full_window(vault, source, window, scope, selector, readable)? {
        return Ok(None);
    }
    let bytes = super::window::export_history_free_window_snapshot(source)?;
    if bytes.len() > MAX_PROMOTION_SNAPSHOT_BYTES {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::PromotionTooLarge,
        ));
    }
    Ok(Some(bytes))
}

/// Re-check the grant and actor floor before a promoted window receives new
/// bytes. The caller must NEVER broadcast raw full-window updates on a stale
/// grant: a newly withheld row may have landed since promotion.
pub fn promotion_covers_full_window(
    vault: &Vault,
    source: &LoroDoc,
    window: &WindowKey,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    mut readable: impl FnMut(EntityId) -> Result<bool>,
) -> Result<bool> {
    // The existing full-window egress scrub is the authority for local-only
    // carriers. Its output may contain old history; discard it and compare
    // only the content-bearing current state against the grant selector.
    let _ = super::window::export_scrubbed_window_snapshot(vault, window, source)?;
    let selected = filtered_window_doc(vault, source, window, scope, selector)?;
    if !same_nonempty_roots(&selected, source) {
        return Ok(false);
    }
    let mut admitted = Ok(());
    map_for_each_value_bytes(&source.get_map("entities"), |raw_key, blob| {
        if admitted.is_err() {
            return;
        }
        admitted = (|| {
            let id = EntityId::from_hex(raw_key)?;
            let readable_now = readable(id)?;
            if id.to_hex() != raw_key || blob.is_none() || !readable_now {
                return Err(Error::sync_protocol(
                    SyncProtocolValidation::DocumentAdmissionDenied,
                ));
            }
            Ok(())
        })();
    });
    Ok(admitted.is_ok())
}

/// Root maps used by other sync planes can be lazily created but empty.
/// Only content-bearing maps constrain full-window coverage; unknown nonempty
/// roots still fail closed unless the selector copied them byte-for-byte.
fn same_nonempty_roots(selected: &LoroDoc, source: &LoroDoc) -> bool {
    fn roots(doc: &LoroDoc) -> Option<std::collections::BTreeMap<String, loro::LoroValue>> {
        let loro::LoroValue::Map(map) = doc.get_deep_value() else {
            return None;
        };
        Some(map.iter().filter(|(_, value)| {
            !matches!(value, loro::LoroValue::Map(nested) if nested.is_empty())
        }).map(|(key, value)| (key.to_string(), value.clone())).collect())
    }
    roots(selected).is_some_and(|selected| roots(source) == Some(selected))
}

fn title_from_body(body: &[u8], max_chars: usize) -> Option<String> {
    // The generic ledger cannot assume each registered kind has a title.
    // Only a literal string `title` in a MessagePack map is index metadata.
    let mut cursor = std::io::Cursor::new(body);
    let rmpv::Value::Map(fields) = rmpv::decode::read_value(&mut cursor).ok()? else {
        return None;
    };
    if cursor.position() != body.len() as u64 {
        return None;
    }
    let titles: Vec<_> = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some("title"))
        .collect();
    if titles.len() != 1 {
        return None;
    }
    let value = titles[0].1.as_str()?.trim();
    (!value.is_empty() && max_chars > 0).then(|| value.chars().take(max_chars).collect())
}
