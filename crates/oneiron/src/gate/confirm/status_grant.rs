//! The settlement status rewrite a critical confirm's timeout or answer
//! grants: the single-use authority and the door that applies it.

use crate::batch::{BatchOp, apply_session_bundle_claim_puts};
use crate::claim::transition::{
    ClaimTransitionKind, TransitionDelta, stage_owner_machine_transition,
    stage_system_machine_transition,
};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, encode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// A private, single-use authority for a settlement status rewrite.
///
/// Its fields are deliberately not caller supplied at the materialization door:
/// only the verified timeout/sweep and authority-fold paths below can construct it.
#[derive(Clone, Copy)]
pub(in crate::gate) enum PreauthorizedClaimStatusGrant {
    TimeoutDemotion,
    FoldDecline,
    FoldClear,
}

#[cfg(test)]
impl PreauthorizedClaimStatusGrant {
    // Test-only access verifies the materialization door's row/header binding.
    pub(in crate::gate) fn test_timeout_demotion() -> Self {
        Self::TimeoutDemotion
    }
}

pub(in crate::gate) fn put_preauthorized_claim_status_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    expected: &ClaimBody,
    grant: PreauthorizedClaimStatusGrant,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let current = vault
        .get_claim_in_txn(&*wtxn, id)?
        .ok_or(Error::EntityNotFound)?;
    let raw = vault
        .store
        .port_entity_record(&*wtxn, id)?
        .ok_or(Error::EntityNotFound)?;
    if raw.entity_type != ENTITY_TYPE_CLAIM
        || raw.occurred.start != occurred.start
        || raw.occurred.end != occurred.end
        || raw.learned_at != learned_at
        || current != *expected
    {
        return Err(Error::InvariantViolation(
            "preauthorized claim status update does not bind current claim row",
        ));
    }
    let mut updated = current.clone();
    match grant {
        PreauthorizedClaimStatusGrant::TimeoutDemotion => {
            updated.approval = ClaimApprovalStatus::Proposed;
        }
        PreauthorizedClaimStatusGrant::FoldClear => {
            updated.approval = ClaimApprovalStatus::Auto;
        }
        PreauthorizedClaimStatusGrant::FoldDecline => {
            updated.lifecycle = ClaimLifecycleStatus::Retracted;
        }
    }
    // A MACHINE-born claim's live row is its signed history's projection: the
    // rewrite stages the transition that projects it in this writer, and the
    // row carries what the history then projects (FIX 12025).
    if updated != current
        && crate::authority::machine_claim_needs_history(&vault.store, &*wtxn, &current)?
    {
        updated = stage_status_transition(vault, wtxn, *id, &current, grant)?;
    }
    let data = encode_claim_body(&updated)?;
    crate::claim::validate_claim_body_bytes(&data, false)?;
    apply_session_bundle_claim_puts(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
    )
}

/// The signed transition that projects `grant` on a MACHINE-born claim. No
/// person answered a lapse, so it is the engine's own principal's, the one
/// its `Demoted` settlement names; a decline is the owner's retraction; a
/// clear is the MACHINE author's own grant, which the fold records as `Auto`.
fn stage_status_transition(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    current: &ClaimBody,
    grant: PreauthorizedClaimStatusGrant,
) -> Result<ClaimBody> {
    let now = vault.store.clock.now_recorded_at();
    match grant {
        PreauthorizedClaimStatusGrant::TimeoutDemotion => stage_system_machine_transition(
            vault,
            wtxn,
            id,
            ClaimTransitionKind::ConfirmLapse,
            TransitionDelta::None,
            crate::ports::storage_service_principal()?,
            now,
        ),
        PreauthorizedClaimStatusGrant::FoldDecline => {
            // The fold never moves a validity end outside the claim's own.
            let end = current.valid_to.map_or(now, |old| old.min(now));
            let end = current.valid_from.map_or(end, |start| start.max(end));
            stage_owner_machine_transition(
                vault,
                wtxn,
                id,
                ClaimTransitionKind::Retract,
                TransitionDelta::ValidTo(end),
                now,
            )
        }
        PreauthorizedClaimStatusGrant::FoldClear => {
            let author = crate::memory::claim_author(current)
                .ok_or(Error::InvalidClaimBody("machine claim names no author"))?;
            stage_system_machine_transition(
                vault,
                wtxn,
                id,
                ClaimTransitionKind::Approve,
                TransitionDelta::None,
                author,
                now,
            )
        }
    }
}
