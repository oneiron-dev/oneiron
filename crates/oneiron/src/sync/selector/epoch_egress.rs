//! The epoch fence at sync egress: an epoch summary leaves through a
//! selector export only beside every record it was written from, judged by
//! what the exporter itself ships (agent-runtime-v1 §d7).

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use loro::LoroDoc;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::sync::loro_support::TombstoneIndex;

/// The epoch summaries among `shipped` (what this export of `source` ships
/// after every other withholding, read in its snapshot `rtxn`) that must
/// stay home. An epoch summary leaves only beside every record it was
/// written from, and only this export, in this snapshot, can prove that:
/// each source must be erased or withdrawn by nothing and ship here too (a
/// nested epoch only if it leaves as well). A source another window carries,
/// or none does, cannot be proven from here, so its summary stays home; the
/// sources are never sent along. A row is an epoch summary when its stored
/// row or the bytes this export would ship say so, since a carrier the vault
/// refused at a stored epoch's id may hold its words in any form. A source
/// ships only as the record stored at its id: such a carrier is not what the
/// summary was written from.
pub(super) fn unbacked_epochs(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    source: &LoroDoc,
    shipped: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let entities = source.get_map("entities");
    let tombstones = TombstoneIndex::build(&source.get_map("tombstones"));
    let withdrawn = |id: &EntityId| -> Result<bool> {
        let state = crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, rtxn, id)?;
        Ok(state.deleted || state.stale)
    };
    // In any form: a pointer is resolved by the head stored at its id, and
    // one no head stands for is held as an epoch (Astra 1384e).
    let is_epoch = |id: &EntityId, raw: Option<Vec<u8>>| -> Result<bool> {
        let Some(raw) = raw.filter(|raw| {
            raw.first() == Some(&crate::registry::ENTITY_TYPE_SUMMARY)
                && raw.len() >= ENTITY_METADATA_HEADER_LEN
        }) else {
            return Ok(false);
        };
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        Ok(crate::compaction::stored_epoch_in(&vault.store, rtxn, id, body)?.may_be())
    };
    // Each epoch's sources, or `None` when the epoch itself is withdrawn;
    // and whether each source ships here, withdrawn by nothing.
    let mut epochs = BTreeMap::<EntityId, Option<Vec<EntityId>>>::new();
    let mut backs = BTreeMap::<EntityId, bool>::new();
    for id in shipped {
        let carried = crate::sync::loro_support::map_get_bytes(&entities, &id.to_hex());
        if !is_epoch(id, carried)? && !is_epoch(id, vault.get_raw_in(rtxn, id)?)? {
            continue;
        }
        if withdrawn(id)? {
            epochs.insert(*id, None);
            continue;
        }
        let mut sources = Vec::new();
        for edge in crate::ports::EdgeStoreRead::port_edges(
            &vault.store,
            rtxn,
            id,
            crate::ports::EdgeDirection::Out,
            Some(EdgeKind::DerivedFrom),
            None,
        )? {
            let from = edge?.target;
            sources.push(from);
            if let Entry::Vacant(slot) = backs.entry(from) {
                slot.insert(
                    shipped.contains(&from)
                        && !withdrawn(&from)?
                        && ships_whole(vault, rtxn, source, &tombstones, &from)?,
                );
            }
        }
        epochs.insert(*id, Some(sources));
    }
    let mut withheld = BTreeSet::new();
    loop {
        let before = withheld.len();
        for (epoch, sources) in &epochs {
            if withheld.contains(epoch) {
                continue;
            }
            let backed = sources.as_ref().is_some_and(|sources| {
                sources.iter().all(|source| {
                    backs.get(source).copied().unwrap_or(false) && !withheld.contains(source)
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

/// Whether a row this export selected leaves whole, as the record stored at
/// its id. Its carrier must be the stored row by sync ingest's own echo test
/// (the same bytes, or the same pack row in its wire form): a peer's write
/// the vault refused there (a retype, a move to another world, a new body) is
/// not that record. A NOTE the export drops with its sidecar does not leave
/// whole, and neither does a grant or authority row, which a guest share
/// strips after this pass.
fn ships_whole(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    source: &LoroDoc,
    tombstones: &TombstoneIndex,
    id: &EntityId,
) -> Result<bool> {
    let carried =
        crate::sync::loro_support::map_get_bytes(&source.get_map("entities"), &id.to_hex());
    let (Some(stored), Some(carried)) = (vault.get_raw_in(rtxn, id)?, carried) else {
        return Ok(false);
    };
    // A file-plane ASSET's carrier holds its body inline (FIX 5393), or binds
    // it by reference (FIX 5489).
    if stored != carried
        && !crate::sync::pack_sync::pack_echo_equal(&stored, &carried)
        && !crate::sync::asset_body::doc_echo_equal(
            &vault.store,
            rtxn,
            source,
            id,
            &stored,
            &carried,
        )?
    {
        return Ok(false);
    }
    Ok(match stored.first().copied() {
        None
        | Some(
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT
            | crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
        ) => false,
        Some(crate::registry::ENTITY_TYPE_NOTE) => {
            !crate::sync::note::blocked(vault, rtxn, tombstones, id)?
        }
        Some(_) => true,
    })
}
