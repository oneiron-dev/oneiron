//! A read-only lookup of an attempt's verified coarse milestone (FIX 8715).
//! The attempt's milestone claims are found by their attempt index (FIX
//! 10766), every one the attempt's own, bound or not.
//!
//! The durable milestone index admits only a milestone bound to a local
//! queue row, because that index decides this device's resume point; a
//! milestone replicated from the device that ran the attempt has no such row
//! here and never enters it. That milestone is still the attempt's coarse
//! progress. This reader finds it from the milestone claims themselves,
//! verified as a replicated claim read is: readable (no withdrawn words),
//! projected through its retained machine history, and causally admitted (a
//! machine-signed claim's proof checked). It writes nothing, indexes nothing
//! and decides no resume: execution and resume keep the bound index.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::authority::AuthorityFold;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::ports::{BodyStale, EntityStoreRead, body_readable_in_txn};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE};
use crate::store::Store;

use super::super::store::DreamerRunnerStore;
use super::super::types::DreamerDurableMilestone;
use super::{
    dreamer_milestone_from_claim_body, milestone_claim_agent_attribution,
    milestone_claim_envelope_writer_kind,
};

impl DreamerRunnerStore<'_> {
    /// The latest verified active/approved milestone claim naming
    /// `attempt_id`, with or without a local queue row: the coarse progress
    /// of an attempt another device ran. Read-only, on its own read
    /// transaction.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn latest_verified_milestone(
        &self,
        attempt_id: AttemptId,
    ) -> Result<Option<DreamerDurableMilestone>> {
        let vault = self.vault;
        let rtxn = vault.store.env.read_txn()?;
        // The claims naming the attempt, by their index (FIX 10766), each
        // still readable here.
        let mut candidates = Vec::new();
        for id in super::claim_index::milestone_claims_in_txn(&vault.store, &rtxn, attempt_id)? {
            let Some(raw) = vault.store.port_entity_record(&rtxn, &id)? else {
                continue;
            };
            let stale = BodyStale::ClaimStatus;
            if raw.entity_type == ENTITY_TYPE_CLAIM
                && body_readable_in_txn(&vault.store, &rtxn, &id, &raw.body, stale)?
            {
                candidates.push(id);
            }
        }
        if candidates.is_empty() {
            return Ok(None);
        }
        let fold = vault.authority_fold_readonly_in_txn(&rtxn)?;
        let mut latest: Option<DreamerDurableMilestone> = None;
        for id in candidates {
            let Some(milestone) = verified_milestone_in_txn(vault, &rtxn, &fold, &id, attempt_id)?
            else {
                continue;
            };
            if latest.as_ref().is_none_or(|current| {
                (milestone.at, milestone.learned_at, milestone.claim_id)
                    > (current.at, current.learned_at, current.claim_id)
            }) {
                latest = Some(milestone);
            }
        }
        Ok(latest)
    }
}

/// Claim `id` as `attempt_id`'s milestone when its projected body is
/// causally admitted, still active/approved, names the attempt and, for an
/// agent-dispatch milestone, carries that milestone's own binding. A claim
/// whose machine history is incomplete or whose proof fails is not verified,
/// so it is skipped, never an error.
fn verified_milestone_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    id: &EntityId,
    attempt_id: AttemptId,
) -> Result<Option<DreamerDurableMilestone>> {
    let Some(raw) = vault.store.port_entity_record(rtxn, id)? else {
        return Ok(None);
    };
    if raw.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let body = match vault.get_claim_in_txn(rtxn, id) {
        Ok(Some(body)) => body,
        Ok(None)
        | Err(Error::Claim(
            ClaimError::MachineClaimHistoryIncomplete | ClaimError::InvalidMachineClaimProof,
        )) => return Ok(None),
        Err(error) => return Err(error),
    };
    if !crate::authority::claim_causal_admitted(&vault.store, rtxn, fold, id, &body)?
        || !dispatch_stamp_bound(&vault.store, rtxn, attempt_id, &body)?
    {
        return Ok(None);
    }
    Ok(dreamer_milestone_from_claim_body(id, &body, raw.learned_at)
        .filter(|milestone| milestone.attempt_id == attempt_id))
}

/// An agent-dispatch milestone (one stamped with its dispatched agent) is
/// about its attempt and rides a stored MACHINE's bookkeeping envelope, as
/// the index's binding check asks. With no local queue row there is no
/// payload agent to compare, so the stamped agent is not checked here; a
/// milestone with no agent stamp passes, as the index passes a non-dispatch
/// attempt's milestone.
fn dispatch_stamp_bound(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
    body: &ClaimBody,
) -> Result<bool> {
    if milestone_claim_agent_attribution(body).is_none() {
        return Ok(true);
    }
    let Ok(subject) = EntityId::from_bytes(*attempt_id.as_bytes()) else {
        return Ok(false);
    };
    if body.subject != ClaimSubject::Entity(subject) {
        return Ok(false);
    }
    Ok(milestone_claim_envelope_writer_kind(store, rtxn, body)? == Some(ENTITY_TYPE_MACHINE))
}
