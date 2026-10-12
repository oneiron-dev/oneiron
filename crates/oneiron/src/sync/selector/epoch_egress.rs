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

/// The epoch summaries among `shipped` (what this export of `source` ships
/// after every other withholding, read in its snapshot `rtxn`) that must
/// stay home. An epoch summary leaves only beside every record it was
/// written from, and only this export, in this snapshot, can prove that:
/// each source must be erased or withdrawn by nothing and ship here too (a
/// nested epoch only if it leaves as well). A source another window carries,
/// or none does, cannot be proven from here, so its summary stays home; the
/// sources are never sent along. A source ships only as the record stored at
/// its id: a peer's carrier the vault refused there is not what the summary
/// was written from.
pub(super) fn unbacked_epochs(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    source: &LoroDoc,
    shipped: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let entities = source.get_map("entities");
    let withdrawn = |id: &EntityId| -> Result<bool> {
        let state = crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, rtxn, id)?;
        Ok(state.deleted || state.stale)
    };
    let is_epoch = |raw: &[u8]| {
        raw.first() == Some(&crate::registry::ENTITY_TYPE_SUMMARY)
            && raw.len() >= ENTITY_METADATA_HEADER_LEN
            && crate::compaction::decode_epoch_summary_body(&raw[ENTITY_METADATA_HEADER_LEN..])
                .is_ok()
    };
    // Each epoch's sources, or `None` when the epoch itself is withdrawn;
    // and whether each source ships here, withdrawn by nothing.
    let mut epochs = BTreeMap::<EntityId, Option<Vec<EntityId>>>::new();
    let mut backs = BTreeMap::<EntityId, bool>::new();
    for id in shipped {
        let carried = crate::sync::loro_support::map_get_bytes(&entities, &id.to_hex());
        if !carried.as_deref().is_some_and(is_epoch) {
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
                        && ships_whole(vault, rtxn, source, &from)?,
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
    id: &EntityId,
) -> Result<bool> {
    let carried =
        crate::sync::loro_support::map_get_bytes(&source.get_map("entities"), &id.to_hex());
    let (Some(stored), Some(carried)) = (vault.get_raw_in(rtxn, id)?, carried) else {
        return Ok(false);
    };
    if stored != carried && !crate::sync::pack_sync::pack_echo_equal(&stored, &carried) {
        return Ok(false);
    }
    Ok(match stored.first().copied() {
        None
        | Some(
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT
            | crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
        ) => false,
        Some(crate::registry::ENTITY_TYPE_NOTE) => {
            !crate::sync::note::blocked(vault, rtxn, source, id)?
        }
        Some(_) => true,
    })
}
