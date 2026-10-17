//! Grant-checked, per-item residence projections over a window document.
//! Window keys stay opaque here so a world-plus-month key has the same shape.

#[cfg(test)]
mod tests;

mod admission;
mod authority_tail;
mod discover;
mod policy;
mod prune;
mod sealed;
pub use admission::{ResidenceAdmission, rows_may_reach, withheld_from_peer};
pub use authority_tail::{
    AUTHORITY_TAIL_PAGE_MAX, AuthorityPageImport, authority_append_for, authority_range_for,
    authority_tail_for, authority_wanted, held_authority_entries, import_authority_page,
};
pub use discover::discover_local_window_keys;
pub use policy::{
    DeviceSyncPreference, effective_residence_mode, load_device_sync_preference,
    local_is_elected_home, resolve_residence_mode, set_device_sync_preference, synced_as_replica,
};
pub(crate) use prune::demote_resident_window;
pub(crate) use prune::record_item_touch_in_txn;
pub use prune::{WindowDemotion, prune_thin_items, record_item_touch};
pub use sealed::{
    SEALED_PUT_PART_MAX, SEALED_READ_PART_MAX, SEALED_SHELF_PAGE_MAX, SealedShelfEntry,
    sealed_shelf_after, sealed_shelf_packet, sealed_shelf_packet_part, shelve_sealed_window,
    shelve_staged_sealed_window, stage_sealed_part, want_sealed_replacement,
    wanted_sealed_replacements,
};

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
use super::selector::{SyncSelector, filtered_window_doc_for, granted_window_doc};
use super::types::WindowKey;
use super::window::Withhold;

/// Collect the actor-readable lexical candidates before applying a
/// residence grant: the bounded candidate window, so a narrowed residence
/// grant does not exhaust a smaller top-k before intersection. The page is
/// short when the window holds fewer resident rows.
pub fn home_search_candidates(
    vault: &Vault,
    proof: &crate::authority::VerifiedSlip,
    query: &str,
    limit: usize,
) -> Result<Vec<(EntityId, f32, WindowKey)>> {
    let actor = vault
        .credential_read_key(proof)?
        .ok_or(Error::sync_protocol(
            SyncProtocolValidation::DocumentAdmissionDenied,
        ))?;
    let candidates = crate::memory::caps::narrowed_candidate_window(limit);
    let mut results = Vec::new();
    for hit in vault
        .scoped_read(actor)
        .search_text(query, candidates, None)?
        .value
    {
        let Some(raw) = vault.get_raw(&hit.id)? else {
            continue;
        };
        results.push((hit.id, hit.score, residence_window_for_blob(&raw)?));
    }
    Ok(results)
}

/// The canonical window that holds one entity: a CLAIM that names a world
/// lives in that world's month partition, every other row in the base month.
/// A malformed carrier stays in the base partition, as window admission keeps it.
pub fn residence_window_for_blob(raw: &[u8]) -> Result<WindowKey> {
    let header =
        EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("residence entity header"))?;
    Ok(match super::types::entity_world(raw).ok().flatten() {
        Some(world) => WindowKey::for_world(header.learned_at, world),
        None => WindowKey::from_timestamp(header.learned_at),
    })
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
    readable: impl FnMut(EntityId) -> Result<bool>,
) -> Result<Vec<WindowIndexEntry>> {
    window_index_projection_with(
        vault,
        source,
        window,
        scope,
        selector,
        Withhold::Unknown,
        title_max_chars,
        readable,
    )
}

/// [`window_index_projection`] for the machine a residence read serves:
/// `withhold` names the worlds kept off it, at the selector's source.
#[allow(clippy::too_many_arguments)]
pub fn window_index_projection_with(
    vault: &Vault,
    source: &LoroDoc,
    window: &WindowKey,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    withhold: Withhold<'_>,
    title_max_chars: usize,
    mut readable: impl FnMut(EntityId) -> Result<bool>,
) -> Result<Vec<WindowIndexEntry>> {
    let selected = filtered_window_doc_for(vault, source, window, scope, selector, withhold)?;
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
    selected_item_blob_with(
        vault,
        source,
        window,
        scope,
        selector,
        Withhold::Unknown,
        item,
    )
}

/// [`selected_item_blob`] for the machine a residence read serves.
pub fn selected_item_blob_with(
    vault: &Vault,
    source: &LoroDoc,
    window: &WindowKey,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    withhold: Withhold<'_>,
    item: EntityId,
) -> Result<Option<Vec<u8>>> {
    let selected = filtered_window_doc_for(vault, source, window, scope, selector, withhold)?;
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
    if !super::loro_support::json_covers_blob(&operations, &metadata) {
        return Err(malformed());
    }
    let entities = ContainerID::new_root("entities", ContainerType::Map);
    let births = ContainerID::new_root(super::row_birth::ROW_BIRTHS_MAP, ContainerType::Map);
    let txn = vault.store.env.read_txn()?;
    for op in operations.changes.into_iter().flat_map(|change| change.ops) {
        let JsonOpContent::Map(MapOp::Insert {
            key,
            value: LoroValue::Binary(blob),
        }) = op.content
        else {
            return Err(malformed());
        };
        // A row is born once, never on this lane: a birth write here may
        // only restate the carrier the home window already holds.
        if op.container == births {
            let held = super::loro_support::map_get_bytes(
                &source.get_map(super::row_birth::ROW_BIRTHS_MAP),
                &key,
            );
            if held.as_deref() != Some(&blob[..]) {
                return Err(malformed());
            }
            continue;
        }
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
/// A window this device withholds as device-only is never promoted.
///
/// `readable` names each row the walk admits, and the caller lists those as
/// the rows the snapshot was derived from (DEC-0005). A local write can land
/// on the window between the walk and the export, so the bytes leave only
/// once a walk named every row they carry; a window that keeps changing
/// under its walks is not promoted.
pub fn promotion_snapshot(
    vault: &Vault,
    source: &LoroDoc,
    window: &WindowKey,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    readable: impl FnMut(EntityId) -> Result<bool>,
) -> Result<Option<Vec<u8>>> {
    promotion_snapshot_with(
        vault,
        source,
        window,
        scope,
        selector,
        Withhold::Unknown,
        readable,
    )
}

/// [`promotion_snapshot`] for the machine a residence read serves: a window
/// is withheld only when it carries a world `withhold` names.
pub fn promotion_snapshot_with(
    vault: &Vault,
    source: &LoroDoc,
    window: &WindowKey,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    withhold: Withhold<'_>,
    mut readable: impl FnMut(EntityId) -> Result<bool>,
) -> Result<Option<Vec<u8>>> {
    for _ in 0..PROMOTION_WALKS {
        let mut named = std::collections::BTreeSet::new();
        let walk = |id: EntityId| {
            named.insert(id.to_hex());
            readable(id)
        };
        if !promotion_covers_full_window_for(
            vault, source, window, scope, selector, withhold, walk,
        )? || super::window::window_withheld_for(vault, window, source, withhold)?
        {
            return Ok(None);
        }
        #[cfg(test)]
        promotion_hook::run(source);
        // The checked door, never the persisted root: a pinned window with no clean root is
        // refused, typed.
        let Some(bytes) =
            super::window::export_promotion_snapshot(vault, window, source, withhold)?
        else {
            return Ok(None);
        };
        if bytes.len() > MAX_PROMOTION_SNAPSHOT_BYTES {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::PromotionTooLarge,
            ));
        }
        if carries_only(&bytes, &named) {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

/// Walks a promotion makes before it gives up on a window that keeps
/// changing under them.
const PROMOTION_WALKS: usize = 3;

/// Whether every row `snapshot` carries is one of `named`.
fn carries_only(snapshot: &[u8], named: &std::collections::BTreeSet<String>) -> bool {
    let carried = LoroDoc::new();
    if !carried
        .import(snapshot)
        .is_ok_and(|status| status.pending.is_none())
    {
        return false;
    }
    let mut only = true;
    map_for_each_value_bytes(&carried.get_map("entities"), |key, _| {
        only &= named.contains(key);
    });
    only
}

/// Re-check the grant and actor floor before a promoted window receives new
/// bytes. The caller must NEVER broadcast raw full-window updates on a stale
/// grant: a newly withheld row may have landed since promotion. A device-only
/// flag is policy, not authority: it leaves the promotion standing, and the
/// export doors withhold the window.
pub fn promotion_covers_full_window(
    vault: &Vault,
    source: &LoroDoc,
    window: &WindowKey,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    readable: impl FnMut(EntityId) -> Result<bool>,
) -> Result<bool> {
    promotion_covers_full_window_for(
        vault,
        source,
        window,
        scope,
        selector,
        Withhold::Nothing,
        readable,
    )
}

/// [`promotion_covers_full_window`] for the machine `destination` names. A
/// machine of this vault's that proved itself also covers the window's
/// custody transitions (OF-422), each sealed to the owner's machines, its
/// room turn rows (OF-522) and this vault's embedding setup rows (OF-370);
/// the selector copies none of them. Any other destination does not, so a
/// window that carries one is not promoted to it.
pub fn promotion_covers_full_window_for(
    vault: &Vault,
    source: &LoroDoc,
    window: &WindowKey,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    destination: Withhold<'_>,
    mut readable: impl FnMut(EntityId) -> Result<bool>,
) -> Result<bool> {
    // The existing full-window egress scrub is the authority for local-only
    // carriers. Its output may contain old history; discard it and compare
    // only the content-bearing current state against the grant selector.
    let _ = super::window::export_scrubbed_window_snapshot(vault, window, source)?;
    let selected = granted_window_doc(vault, source, window, scope, selector)?;
    let own_machine = matches!(destination, Withhold::Worlds(_) | Withhold::Peer(_));
    if own_machine {
        for name in [
            super::custody::CUSTODY_MAP,
            super::room_turns::ROOM_TURNS_MAP,
        ] {
            super::loro_support::copy_binary_root_map(source, &selected, name)?;
        }
        copy_embedding_setup_rows(source, &selected)?;
    }
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
            // A setup row is no actor's content: an own machine takes it whatever it reads.
            let readable_now = readable(id)? || (own_machine && blob.is_some_and(is_setup_row));
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

/// Whether `blob` is an EMBEDDING_SETUP row (OF-370).
fn is_setup_row(blob: &[u8]) -> bool {
    EntityMetadataHeader::parse(blob)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_EMBEDDING_SETUP)
}

/// Copies the EMBEDDING_SETUP rows `source` carries, and their births, into
/// `selected`: this vault's setup reaches its own machines whatever they
/// opened, while the selector keeps it off a peer or a guest (OF-370).
fn copy_embedding_setup_rows(source: &LoroDoc, selected: &LoroDoc) -> Result<()> {
    let mut rows = Vec::new();
    map_for_each_value_bytes(&source.get_map("entities"), |key, blob| {
        if let (Ok(id), Some(blob)) = (EntityId::from_hex(key), blob)
            && is_setup_row(blob)
        {
            rows.push((id, key.to_owned(), blob.to_vec()));
        }
    });
    if rows.is_empty() {
        return Ok(());
    }
    let entities = selected.get_map("entities");
    for (_, key, blob) in &rows {
        super::loro_support::map_insert_bytes(&entities, key, blob)?;
    }
    let owners: Vec<EntityId> = rows.into_iter().map(|(id, _, _)| id).collect();
    super::row_birth::copy_births(source, selected, &owners)?;
    selected.commit();
    Ok(())
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

/// A local write landed on a window between a promotion's walk and its
/// export.
#[cfg(test)]
pub(crate) mod promotion_hook {
    use loro::LoroDoc;
    use std::cell::RefCell;

    type Write = Box<dyn FnOnce(&LoroDoc)>;

    thread_local! {
        static WRITE: RefCell<Option<Write>> = const { RefCell::new(None) };
    }

    /// Lands `write` on the window after the next walk on this thread.
    pub(crate) fn arm(write: impl FnOnce(&LoroDoc) + 'static) {
        WRITE.with(|hook| *hook.borrow_mut() = Some(Box::new(write)));
    }

    pub(super) fn run(doc: &LoroDoc) {
        if let Some(write) = WRITE.with(|hook| hook.borrow_mut().take()) {
            write(doc);
        }
    }
}
