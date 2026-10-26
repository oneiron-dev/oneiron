//! The erase of a fitted install's `skill.section_fit` receipt (FIX 9752).
//! A receipt is a separate claim on the skill that names the install claim,
//! its hub source and the actor that offered it, so neither an erase of the
//! install claim nor one of the skill reaches it by itself. This eraser runs
//! in the erase's own transaction at both delete doors and takes the receipt
//! whole: a receipt that only stopped authorizing would keep those names.
use super::super::claim::{PREDICATE_PLUGIN_SECTION_INSTALL, PluginInstallClaimPayload};
use super::{PREDICATE_SKILL_SECTION_FIT, map_entry};
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// Erases every `skill.section_fit` receipt an erase of `id` covers: each
/// receipt on `id` when it is a skill, and each receipt naming `id` when it
/// is a section install claim. Any other entity holds none. Registered in
/// `deletion/derived_rows.rs`, so it runs before the record's body and
/// edges go.
pub(crate) fn erase_section_fit_receipts_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(entity_type) = entity_type_in_txn(store, wtxn, id)? else {
        return Ok(());
    };
    let receipts = if entity_type == crate::registry::ENTITY_TYPE_SKILL {
        section_fit_receipts_in_txn(store, wtxn, id, None)?
    } else if entity_type == crate::registry::ENTITY_TYPE_CLAIM
        && let Some(skill) = installed_skill_in_txn(store, wtxn, id)?
    {
        section_fit_receipts_in_txn(store, wtxn, &skill, Some(&id.to_hex()))?
    } else {
        Vec::new()
    };
    for receipt in receipts {
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, wtxn, &receipt)?;
        crate::ppr::invalidate_ppr_for_delete(store, wtxn, &receipt, &neighbors)?;
        if graph {
            crate::ppr::increment_graph_version(store, wtxn)?;
        }
        if vector {
            crate::hnsw::increment_vector_version(store, wtxn)?;
        }
    }
    Ok(())
}

/// The stored entity type of `id`, while its record is still here.
fn entity_type_in_txn(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    Ok(
        crate::ports::EntityStoreRead::port_entity_record(store, txn, id)?
            .map(|raw| raw.entity_type),
    )
}

/// The claim body stored at `id`; none for a non-claim or one that does not
/// decode, which this eraser leaves as it is.
fn stored_claim_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_record(store, txn, id)? else {
        return Ok(None);
    };
    if raw.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    Ok(crate::claim::decode_claim_body(&raw.body, true).ok())
}

/// The skill a section install claim targets; none for any other claim.
fn installed_skill_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(body) = stored_claim_in_txn(store, txn, id)? else {
        return Ok(None);
    };
    if body.predicate != PREDICATE_PLUGIN_SECTION_INSTALL {
        return Ok(None);
    }
    Ok(PluginInstallClaimPayload::from_value(&body.value)
        .ok()
        .map(|payload| payload.target.target_skill_ref()))
}

/// The `skill.section_fit` receipts on `skill`, whatever their lifecycle:
/// every one, or only those naming `install_claim`.
fn section_fit_receipts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    install_claim: Option<&str>,
) -> Result<Vec<EntityId>> {
    let mut receipts = Vec::new();
    for entry in crate::ports::EdgeStoreRead::port_edges(
        store,
        txn,
        skill,
        crate::ports::EdgeDirection::In,
        Some(crate::edge::EdgeKind::ClaimOf),
        None,
    )? {
        let claim_id = entry?.target;
        let Some(body) = stored_claim_in_txn(store, txn, &claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_SKILL_SECTION_FIT {
            continue;
        }
        let rmpv::Value::Map(entries) = &body.value else {
            continue;
        };
        let named = map_entry(entries, "install_claim").and_then(rmpv::Value::as_str);
        if install_claim.is_none_or(|wanted| named == Some(wanted)) {
            receipts.push(claim_id);
        }
    }
    Ok(receipts)
}
