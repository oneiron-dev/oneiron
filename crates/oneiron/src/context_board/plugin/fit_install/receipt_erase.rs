//! The erase of a fitted install's `skill.section_fit` receipt (FIX 9752).
//! A receipt is a separate claim on the skill that names the install claim,
//! its hub source and the actor that offered it, so neither an erase of the
//! install claim nor one of the skill reaches it by itself. This eraser runs
//! in the erase's own transaction at both delete doors and takes the receipt
//! whole: a receipt that only stopped authorizing would keep those names.
//! A hub erase takes whole every receipt from that hub (FIX 11060). An actor
//! erase scrubs only the receipt's actor leaf from the erase-only actor sweep
//! (`deletion::actor_fields`), never from this hook, which also runs on soft
//! deletes that keep attribution (FIX 812, FIX 6640).
use super::super::claim::{PREDICATE_PLUGIN_SECTION_INSTALL, PluginInstallClaimPayload};
use super::{PREDICATE_SKILL_SECTION_FIT, map_entry};
use crate::claim::ClaimBody;
use crate::deletion::ActorErasureWriter;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// Erases every `skill.section_fit` receipt an erase of `id` covers: each
/// receipt on `id` when it is a skill, each receipt naming `id` when it is a
/// section install claim, and each receipt from `id` when it is a skill hub
/// (FIX 11060; whole rows, so the install stops authorizing). Any other
/// entity holds none. Registered in `deletion/derived_rows.rs`, so it runs
/// before the record's body and edges go, on soft deletes too.
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
    Ok(())
}

/// Scrubs the actor leaf of every `skill.section_fit` receipt naming `actor`
/// (FIX 11060). Runs only from the erase-only actor sweep
/// (`deletion::actor_fields::scrub_actor_fields_in_txn`, which the live erase,
/// marker-only replay and checkpoint-restore sweeps all reach), so a soft
/// delete keeps receipts' attribution while every hard path scrubs. Safe in
/// either order with the hook's whole-delete above: a receipt gone already
/// reads back absent and is left alone.
pub(crate) fn scrub_section_fit_receipt_actors_in_txn(
    erase: &mut ActorErasureWriter<'_, '_>,
) -> Result<()> {
    let receipts = {
        let (vault, wtxn, actor) = erase.parts();
        actor_receipts_in_txn(&vault.store, wtxn, &actor)?
    };
    for receipt in receipts {
        scrub_receipt_actor_in_txn(erase, &receipt)?;
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

/// The complete stored receipt with only this erased actor's leaf cleared.
/// The receipt's binding fields and permissions do not include `actor`.
/// Unsupported receipts and leaves naming anyone else are not projections.
pub(crate) fn stored_section_fit_actor_erasure_body(
    body: &ClaimBody,
    actor: &EntityId,
) -> Option<ClaimBody> {
    if body.predicate != PREDICATE_SKILL_SECTION_FIT
        || super::SectionFitReceipt::from_value(&body.value).is_none()
    {
        return None;
    }
    let wanted = actor.to_hex();
    let mut next = body.clone();
    let rmpv::Value::Map(entries) = &mut next.value else {
        return None;
    };
    let mut changed = false;
    for (key, value) in entries {
        if key.as_str() == Some("actor") && value.as_str() == Some(wanted.as_str()) {
            *value = rmpv::Value::from("");
            changed = true;
        }
    }
    changed.then_some(next)
}

/// Applies the actor-only projection in its authorized erase writer, through
/// the normal indexed claim path. The revision tail removes the old actor
/// bytes and captures the row that materialization actually stored.
fn scrub_receipt_actor_in_txn(
    erase: &mut ActorErasureWriter<'_, '_>,
    receipt: &EntityId,
) -> Result<()> {
    if !crate::batch::materialize_stored_section_fit_actor_erasure_in_txn(erase, receipt)? {
        return Ok(());
    }
    let (vault, wtxn, _) = erase.parts();
    crate::vault::entity_revision::remove_entity_revisions(&vault.store, wtxn, receipt)?;
    let staged = crate::ports::EntityStoreRead::port_entity_record(&vault.store, wtxn, receipt)?
        .ok_or(crate::error::Error::EntityNotFound)?;
    let encoded = staged.encode();
    crate::vault::entity_revision::capture_entity_revision(&vault.store, wtxn, receipt, &encoded)?;
    Ok(())
}
