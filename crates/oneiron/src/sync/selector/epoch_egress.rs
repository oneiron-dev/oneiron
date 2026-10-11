//! The epoch fence at sync egress: an epoch summary leaves through a
//! selector export only beside every record it was written from, judged by
//! what the exporter itself ships (agent-runtime-v1 §d7).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use loro::LoroDoc;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::federation::Position;
use crate::sync::loro_support::map_for_each_value_bytes;
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;
use crate::sync::window::{
    apply_pending_window_updates, load_window_from_state, reverse_rematerialize,
};

use super::codec::SyncSelector;

/// Window `key` as this vault holds it (its stored state, else its pending
/// updates), with every local row it lacks packed in: the document a fetch
/// of `key` would be filtered from.
pub(super) fn rematerialized_window(
    vault: &Vault,
    peer: &str,
    key: &WindowKey,
) -> Result<LoroDoc> {
    let doc = match load_window_from_state(vault, peer, key) {
        Ok(doc) => doc,
        Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
            let doc = create_window_doc(peer, key);
            apply_pending_window_updates(vault, &doc, key)?;
            doc
        }
        Err(error) => return Err(error),
    };
    reverse_rematerialize(vault, &doc, key)?;
    Ok(doc)
}

/// The window that packs a stored row: its learned-at month, in the
/// partition of its world (only a CLAIM names one). `None` when the row
/// names no world it can be placed by.
fn carrier_window(raw: &[u8]) -> Option<WindowKey> {
    let header = EntityMetadataHeader::parse(raw)?;
    let month = WindowKey::from_timestamp(header.learned_at);
    Some(match crate::sync::types::entity_world(raw).ok()? {
        None => month,
        Some(world) => WindowKey::for_month_world(&month, world),
    })
}

/// The epoch summaries among `shipped` (what this export of window `key`
/// ships after every other withholding) that must stay home: an epoch
/// summary leaves only beside every record it was written from
/// (agent-runtime-v1 §d7). Each source must be erased or withdrawn by
/// nothing, and either ship here (a nested epoch only if it leaves too) or
/// ship from the export of the window that packs it, under this same
/// selector. A source neither export carries cannot be proven carried, so
/// its summary stays home; the sources are never sent along. Without
/// `elsewhere`, only this export counts.
pub(super) fn unbacked_epochs(
    vault: &Vault,
    (source_doc, key): (&LoroDoc, &WindowKey),
    shipped: &BTreeSet<EntityId>,
    selector: &SyncSelector,
    position: &Position,
    elsewhere: bool,
) -> Result<BTreeSet<EntityId>> {
    let entities = source_doc.get_map("entities");
    // Each epoch's sources, or `None` when the epoch itself is withdrawn;
    // and each source's window, `None` when it is withdrawn or unplaced.
    let mut epochs = BTreeMap::<EntityId, Option<Vec<EntityId>>>::new();
    let mut placed = BTreeMap::<EntityId, Option<WindowKey>>::new();
    // A NOTE this export would drop with its sidecar is not shipped here.
    let mut here = shipped.clone();
    {
        let rtxn = vault.store.env.read_txn()?;
        let withdrawn = |id: &EntityId| -> Result<bool> {
            let state =
                crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &rtxn, id)?;
            Ok(state.deleted || state.stale)
        };
        let is_epoch = |raw: &[u8]| {
            raw.first() == Some(&crate::registry::ENTITY_TYPE_SUMMARY)
                && raw.len() >= ENTITY_METADATA_HEADER_LEN
                && crate::compaction::decode_epoch_summary_body(&raw[ENTITY_METADATA_HEADER_LEN..])
                    .is_ok()
        };
        for id in shipped {
            // The bytes this export ships, or the stored row behind them.
            let Some(carried) = crate::sync::loro_support::map_get_bytes(&entities, &id.to_hex())
            else {
                continue;
            };
            if carried.first() != Some(&crate::registry::ENTITY_TYPE_SUMMARY)
                || !(is_epoch(&carried)
                    || vault.get_raw_in(&rtxn, id)?.as_deref().is_some_and(is_epoch))
            {
                continue;
            }
            if withdrawn(id)? {
                epochs.insert(*id, None);
                continue;
            }
            let mut sources = Vec::new();
            for edge in crate::ports::EdgeStoreRead::port_edges(
                &vault.store,
                &rtxn,
                id,
                crate::ports::EdgeDirection::Out,
                Some(EdgeKind::DerivedFrom),
                None,
            )? {
                let source = edge?.target;
                sources.push(source);
                if !placed.contains_key(&source) {
                    let raw = vault.get_raw_in(&rtxn, &source)?;
                    let kind = raw.as_deref().and_then(|raw| raw.first().copied());
                    if kind == Some(crate::registry::ENTITY_TYPE_NOTE)
                        && crate::sync::note::blocked(vault, &rtxn, source_doc, &source)?
                    {
                        here.remove(&source);
                    }
                    // A guest share strips grant and authority rows after this
                    // pass, so neither backs a summary.
                    let window = match raw {
                        Some(raw)
                            if !withdrawn(&source)?
                                && !matches!(
                                    kind,
                                    Some(
                                        crate::registry::ENTITY_TYPE_FEDERATION_GRANT
                                            | crate::registry::ENTITY_TYPE_AUTHORITY_LOG
                                    )
                                ) =>
                        {
                            carrier_window(&raw)
                        }
                        _ => None,
                    };
                    placed.insert(source, window);
                }
            }
            epochs.insert(*id, Some(sources));
        }
    }
    // What each other window's export ships, read with no transaction open.
    let mut carried = HashMap::<String, BTreeSet<EntityId>>::new();
    if elsewhere {
        for (source, window) in &placed {
            let Some(window) = window else { continue };
            if here.contains(source)
                || window.as_str() == key.as_str()
                || carried.contains_key(window.as_str())
            {
                continue;
            }
            // A window whose export fails proves nothing: its sources'
            // summaries stay home, and this export goes on.
            let mut ids = BTreeSet::new();
            if let Ok(selected) = rematerialized_window(vault, "selector-epoch-source", window)
                .and_then(|doc| {
                    super::authorize::filter_window_doc_in(
                        vault, &doc, window, selector, position, false,
                    )
                })
            {
                map_for_each_value_bytes(&selected.get_map("entities"), |raw_key, blob| {
                    if blob.is_some()
                        && let Ok(id) = EntityId::from_hex(raw_key)
                    {
                        ids.insert(id);
                    }
                });
            }
            carried.insert(window.as_str().to_owned(), ids);
        }
    }
    let mut withheld = BTreeSet::new();
    loop {
        let before = withheld.len();
        for (epoch, sources) in &epochs {
            if withheld.contains(epoch) {
                continue;
            }
            let backed = sources.as_ref().is_some_and(|sources| {
                sources.iter().all(|source| match placed.get(source) {
                    Some(Some(window)) => {
                        (here.contains(source) && !withheld.contains(source))
                            || carried
                                .get(window.as_str())
                                .is_some_and(|ids| ids.contains(source))
                    }
                    _ => false,
                })
            });
            if !backed {
                withheld.insert(*epoch);
            }
        }
        if withheld.len() == before {
            return Ok(withheld);
        }
    }
}
