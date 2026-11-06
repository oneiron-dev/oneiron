//! The observed-preference bar for an extracted want (FIX 21842).
//!
//! ARCH-0003 (#observed-vs-stated, owner 2026-07-29) mints a want derived
//! from behaviour as an `observed` `preference.*` claim beside the
//! `user_stated` one, and the `signal_extraction` job writes it, on "three
//! observations across two or more sessions". An extracted preference is
//! stamped Observed only when the evidence that survived admission joins to
//! that much of the user's own behaviour, counted here off the stored rows,
//! never off the model's word. One observation is one live TURN the user
//! spoke; its session is the live SESSION that TURN was witnessed into, read
//! off the recorded membership. An assistant, system or tool turn, an
//! imported turn, a cited CLAIM, a row that does not resolve and a
//! membership never recorded count for nothing. Below the bar the candidate
//! keeps its computed meet.

use std::collections::BTreeSet;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    OBSERVED_PREFERENCE_MIN_OBSERVATIONS, OBSERVED_PREFERENCE_MIN_SESSIONS,
    preference_answers_agree,
};
use crate::compaction::turn_session_membership_in_txn;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Whether `evidence` holds at least [`OBSERVED_PREFERENCE_MIN_OBSERVATIONS`]
/// distinct live TURNs the user spoke, across at least
/// [`OBSERVED_PREFERENCE_MIN_SESSIONS`] distinct live SESSIONs, read on the
/// writer's snapshot.
pub(crate) fn observed_preference_support_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    evidence: &[EntityId],
) -> Result<bool> {
    let mut observations = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    for turn in evidence {
        if !user_turn_in_txn(vault, txn, turn)? {
            continue;
        }
        let Some(session) = turn_session_membership_in_txn(&vault.store, txn, turn)? else {
            continue;
        };
        if !is_live(vault, txn, &session, ENTITY_TYPE_SESSION)? {
            continue;
        }
        observations.insert(*turn);
        sessions.insert(session);
    }
    Ok(observations.len() >= OBSERVED_PREFERENCE_MIN_OBSERVATIONS
        && sessions.len() >= OBSERVED_PREFERENCE_MIN_SESSIONS)
}

/// Whether `id` is a live TURN the user spoke, not imported: its GATE-10
/// role read by the one turn-body decoder.
fn user_turn_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    if !is_live(vault, txn, id, ENTITY_TYPE_TURN)? {
        return Ok(false);
    }
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)? else {
        return Ok(false);
    };
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(false);
    };
    let facts = crate::dreamer_consolidation::decode_turn_body(body);
    Ok(!facts.imported
        && matches!(
            crate::dreamer_runner::dreamer_turn_role(
                facts.speaker.as_deref(),
                &vault.config.assistant_display_names,
            ),
            crate::dreamer_runner::DreamerTurnRole::User
        ))
}

fn is_live(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId, entity_type: u8) -> Result<bool> {
    Ok(matches!(
        live_entity_row_in_txn(&vault.store, txn, id)?,
        LiveEntityRow::Live { entity_type: found, .. } if found == entity_type
    ))
}

/// The standing `user_stated` claims on the observed `body`'s key whose
/// answer it does not give: the same subject, predicate, world,
/// relationships, facet and project, Active, Auto or Approved, and valid now.
/// Each is the other half of one `conflict.open` pair (OF-023); both claims
/// stay active, and the stated one is never closed.
pub(super) fn stated_preference_peers_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    observed: &EntityId,
    body: &ClaimBody,
) -> Result<Vec<EntityId>> {
    let ClaimSubject::Entity(subject) = &body.subject else {
        return Ok(Vec::new());
    };
    let standing_at = vault.store.clock.now_recorded_at();
    let mut peers = Vec::new();
    for peer in vault.claims_for_subject_in_txn(txn, subject)? {
        if peer == *observed {
            continue;
        }
        let Some(stated) = vault.get_claim_in_txn(txn, &peer)? else {
            continue;
        };
        if stated.source == Some(ClaimSource::UserStated)
            && stated.lifecycle == ClaimLifecycleStatus::Active
            && matches!(
                stated.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
            && stated.predicate == body.predicate
            && stated.world == body.world
            && stated.rel == body.rel
            && stated.scope_facet == body.scope_facet
            && stated.scope_project == body.scope_project
            && !stated.valid_from.is_some_and(|start| start > standing_at)
            && !stated.valid_to.is_some_and(|end| end <= standing_at)
            && !preference_answers_agree(&body.value, &stated.value)
        {
            peers.push(peer);
        }
    }
    Ok(peers)
}
