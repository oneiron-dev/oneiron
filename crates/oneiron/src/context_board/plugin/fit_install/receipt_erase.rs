//! The erase of a fitted install's `skill.section_fit` receipt (FIX 9752).
//! A receipt is a separate claim on the skill that names the install claim,
//! its hub source and the actor that offered it, so neither an erase of the
//! install claim nor one of the skill reaches it by itself. This eraser runs
//! in the erase's own transaction at both delete doors and takes the receipt
//! whole: a receipt that only stopped authorizing would keep those names.
//! A hub erase takes whole every receipt from that hub, and an actor erase
//! scrubs only the receipt's actor leaf (FIX 11060).
use super::super::claim::{PREDICATE_PLUGIN_SECTION_INSTALL, PluginInstallClaimPayload};
use super::{PREDICATE_SKILL_SECTION_FIT, map_entry};
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// Erases every `skill.section_fit` receipt an erase of `id` covers: each
/// receipt on `id` when it is a skill, each receipt naming `id` when it is a
/// section install claim, and each receipt from `id` when it is a skill hub
/// (FIX 11060; whole rows, so the install stops authorizing). A receipt whose
/// actor leaf is `id` keeps its row and names no one there. Any other entity
/// holds none. Registered in `deletion/derived_rows.rs`, so it runs before
/// the record's body and edges go.
pub(crate) fn erase_section_fit_receipts_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(entity_type) = entity_type_in_txn(store, wtxn, id)? else {
        return Ok(());
    };
    let mut receipts = if entity_type == crate::registry::ENTITY_TYPE_SKILL {
        section_fit_receipts_in_txn(store, wtxn, id, None)?
    } else if entity_type == crate::registry::ENTITY_TYPE_CLAIM
        && let Some(skill) = installed_skill_in_txn(store, wtxn, id)?
    {
        section_fit_receipts_in_txn(store, wtxn, &skill, Some(&id.to_hex()))?
    } else {
        Vec::new()
    };
    if entity_type == crate::registry::ENTITY_TYPE_SKILL_HUB {
        receipts.extend(hub_receipts_in_txn(store, wtxn, id)?);
    }
    let scrubbed: Vec<EntityId> = actor_receipts_in_txn(store, wtxn, id)?
        .into_iter()
        .filter(|receipt| !receipts.contains(receipt))
        .collect();
    for receipt in receipts {
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, wtxn, &receipt)?;
        crate::batch::stage_cascade_tombstone_in_txn(store, wtxn, &receipt)?;
        crate::ppr::invalidate_ppr_for_delete(store, wtxn, &receipt, &neighbors)?;
        if graph {
            crate::ppr::increment_graph_version(store, wtxn)?;
        }
        if vector {
            crate::hnsw::increment_vector_version(store, wtxn)?;
        }
    }
    for receipt in scrubbed {
        scrub_receipt_actor_in_txn(store, wtxn, &receipt)?;
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

/// The `skill.section_fit` receipts from `hub`, whatever their lifecycle, by
/// the posting list. An `ExistingSkill` receipt carries empty hub leaves and
/// never matches (FIX 11060).
fn hub_receipts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    hub: &EntityId,
) -> Result<Vec<EntityId>> {
    let wanted = hub.to_hex();
    let mut receipts = Vec::new();
    for claim_id in
        crate::claim::claim_ids_for_predicate_in_txn(store, txn, PREDICATE_SKILL_SECTION_FIT)?
    {
        let Some(body) = stored_claim_in_txn(store, txn, &claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_SKILL_SECTION_FIT {
            continue;
        }
        let rmpv::Value::Map(entries) = &body.value else {
            continue;
        };
        if map_entry(entries, "hub_id")
            .and_then(rmpv::Value::as_str)
            .is_some_and(|leaf| !leaf.is_empty() && leaf == wanted)
        {
            receipts.push(claim_id);
        }
    }
    Ok(receipts)
}

/// The `skill.section_fit` receipts whose actor leaf is `actor`, by the
/// posting list, whatever erased-id type names it (FIX 11060).
fn actor_receipts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<EntityId>> {
    let wanted = actor.to_hex();
    let mut receipts = Vec::new();
    for claim_id in
        crate::claim::claim_ids_for_predicate_in_txn(store, txn, PREDICATE_SKILL_SECTION_FIT)?
    {
        let Some(body) = stored_claim_in_txn(store, txn, &claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_SKILL_SECTION_FIT {
            continue;
        }
        let rmpv::Value::Map(entries) = &body.value else {
            continue;
        };
        if map_entry(entries, "actor").and_then(rmpv::Value::as_str) == Some(wanted.as_str()) {
            receipts.push(claim_id);
        }
    }
    Ok(receipts)
}

/// Rewrites `receipt` with only its actor leaf scrubbed to `""`, keeping its
/// id, header, status and scope stamp (FIX 11060). The leaf sits outside
/// `fields()`, so the install still authorizes. A receipt that does not
/// decode, names no actor, or is no receipt stays as it is.
fn scrub_receipt_actor_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &EntityId,
) -> Result<()> {
    let Some(stored) = crate::ports::EntityStoreRead::port_entity_record(store, wtxn, receipt)?
    else {
        return Ok(());
    };
    if stored.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(());
    }
    let Ok(mut body) = crate::claim::decode_claim_body(&stored.body, true) else {
        return Ok(());
    };
    if body.predicate != PREDICATE_SKILL_SECTION_FIT {
        return Ok(());
    }
    let rmpv::Value::Map(entries) = &mut body.value else {
        return Ok(());
    };
    let mut scrubbed = false;
    for (key, value) in entries.iter_mut() {
        if key.as_str() == Some("actor") {
            *value = rmpv::Value::from("");
            scrubbed = true;
        }
    }
    if !scrubbed {
        return Ok(());
    }
    let data = crate::claim::encode_claim_body(&body)?;
    crate::claim::validate_claim_body_and_decode_in_txn(store, wtxn, &data, true)?;
    let next = crate::ports::EntityRecord {
        entity_type: stored.entity_type,
        occurred: stored.occurred,
        learned_at: stored.learned_at,
        body: data,
    };
    let encoded = next.encode();
    crate::ports::EntityStoreStaging::port_stage_entity_row(store, wtxn, receipt, &encoded)?;
    crate::vault::entity_revision::remove_entity_revisions(store, wtxn, receipt)?;
    crate::vault::entity_revision::capture_entity_revision(store, wtxn, receipt, &encoded)?;
    Ok(())
}
