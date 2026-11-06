//! Reconcile compatible raw passport heads after a public claim write.
//!
//! Only the public `Vault::put_claim` door calls this after normal admission.
//! Typed import/invite and batch writes retain their existing paths. Unsupported
//! rows remain admitted as before; no replacement actor or head is manufactured.

use super::claims::{PREDICATE_CALENDAR_PASSPORT, decode_passport_value};
use crate::claim::{
    ClaimLifecycleStatus, ClaimSubject, base_world_id, claim_sensitivity_band, claim_surfaceable,
};
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::vault::Vault;

/// Reconcile a raw, admitted passport against its sole active same-key peer.
/// Both rows must be un-attributed and share scope. Native supersession retains
/// the losing assertion as history in the caller's transaction. A presence
/// transition updates the head; otherwise the feed's sequence/hash rules decide.
pub(crate) fn settle_generic_calendar_claim_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    now: u64,
) -> crate::Result<()> {
    let Some(new_body) = vault.get_claim_in_txn(txn, id)? else {
        return Ok(());
    };
    if new_body.predicate != PREDICATE_CALENDAR_PASSPORT
        || new_body.source.is_some()
        || new_body.evidence.is_some()
        || !claim_surfaceable(&new_body)
        || !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, id)?
    {
        return Ok(());
    }
    let ClaimSubject::Entity(event) = new_body.subject else {
        return Ok(());
    };
    if vault.get_entity_type_in_txn(txn, &event)? != Some(ENTITY_TYPE_EVENT) {
        return Ok(());
    }
    let new_value = decode_passport_value(&new_body.value)?;

    let mut peer = None;
    for peer_id in vault.claims_for_subject_in_txn(txn, &event)? {
        if peer_id == *id {
            continue;
        }
        let Some(peer_body) = vault.get_claim_in_txn(txn, &peer_id)? else {
            continue;
        };
        if peer_body.predicate != PREDICATE_CALENDAR_PASSPORT
            || peer_body.subject != ClaimSubject::Entity(event)
            || peer_body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let peer_value = decode_passport_value(&peer_body.value)?;
        if peer_value.system != new_value.system || peer_value.uid != new_value.uid {
            continue;
        }
        if peer.is_some() {
            return Ok(());
        }
        peer = Some((peer_id, peer_body, peer_value));
    }
    let Some((peer_id, peer_body, peer_value)) = peer else {
        return Ok(());
    };
    if peer_body.source.is_some()
        || peer_body.evidence.is_some()
        || !claim_surfaceable(&peer_body)
        || !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, &peer_id)?
        || peer_body.world.unwrap_or_else(base_world_id)
            != new_body.world.unwrap_or_else(base_world_id)
        || peer_body.rel != new_body.rel
        || peer_body.scope_facet != new_body.scope_facet
        || peer_body.scope_project != new_body.scope_project
        || peer_body.scope != new_body.scope
        || peer_body.session_tag != new_body.session_tag
        || claim_sensitivity_band(&peer_body) != claim_sensitivity_band(&new_body)
    {
        return Ok(());
    }

    let new_wins = new_value.presence != peer_value.presence
        || new_value.last_sequence > peer_value.last_sequence
        || (new_value.last_sequence == peer_value.last_sequence
            && new_value.content_hash != peer_value.content_hash);
    if new_wins {
        vault.supersede_claim_in_txn(txn, id, &peer_id, now)?;
    } else {
        vault.supersede_claim_in_txn(txn, &peer_id, id, now)?;
    }
    Ok(())
}
