//! A window's metadata-only index: the listing a residence read serves one
//! page at a time, each entry with the content-world witness of its row
//! (FIX 14534).

use loro::LoroDoc;
use serde::{Deserialize, Serialize};

use super::content_world::{ContentWorld, content_world_in};
use super::title_from_body;
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::federation::FederationGrantScope;
use crate::sync::loro_support::map_for_each_value_bytes;
use crate::sync::selector::{SyncSelector, filtered_window_doc_for};
use crate::sync::types::WindowKey;
use crate::sync::window::Withhold;

/// One metadata-only entry: the body and CRDT history are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowIndexEntry {
    pub entity_id: String,
    pub title: Option<String>,
    pub learned_at: u64,
    /// Where the listed row sits (FIX 14534); unknown from a home that sent
    /// none.
    #[serde(default)]
    pub content_world: ContentWorld,
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
        // FIX 7608 slice 4: a re-mask of a marked repo copy is a new selection.
        crate::sync::selector::secret_projection::with_copy_generation_in_txn(
            vault,
            &txn,
            policy.read_frontier_hash()?,
        )?,
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
    // FIX 7608 slice 4: a marked repo item is listed by its copy id and
    // titled by its copy, never by its raw body.
    let copies = crate::sync::selector::secret_projection::IndexCopies::read(vault)?;
    let mut entries = Vec::new();
    let mut listed = Vec::new();
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
            Ok(true) => {
                listed.push(id);
                entries.push(WindowIndexEntry {
                    entity_id: copies.shown(&id, key),
                    title: copies.title(&id, blob, |body| title_from_body(body, title_max_chars)),
                    learned_at: header.learned_at,
                    content_world: ContentWorld::Unknown,
                });
            }
            Ok(false) => {}
            Err(error) => result = Err(error),
        }
    });
    result?;
    // Each listed row's witness (FIX 14534), read once every check above is
    // done: `readable` opens transactions of its own, and none may nest in
    // one held here.
    let txn = vault.store.env.read_txn()?;
    for (entry, id) in entries.iter_mut().zip(listed) {
        entry.content_world = content_world_in(&vault.store, &txn, id)?.shown_to(&withhold);
    }
    drop(txn);
    entries.sort_unstable_by(|a, b| a.entity_id.cmp(&b.entity_id));
    Ok(entries)
}

/// Slice a previously authorized projection in O(log N + page size), with no
/// full-window Loro export or selector rebuild.
pub fn window_index_page(
    entries: &[WindowIndexEntry],
    page: IndexPage,
) -> Result<Vec<WindowIndexEntry>> {
    if page.limit == 0 {
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
