//! Explicit authority succession for an already admitted code consent wait.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::store::GateDecisionId;

use super::types::{CodeConsentBinding, CodeConsentSavedCredential, CodeConsentWaitRow};

/// The immutable parked step, with the control revision the request observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentRebindTarget {
    pub(crate) run_id: EntityId,
    pub(crate) wait_id: EntityId,
    pub(crate) generation: u64,
    pub(crate) step_hash: [u8; 32],
    pub(crate) effect_digest: [u8; 32],
    pub(crate) revision: u64,
}

/// A holder's actual successor request. Preparing it grants no authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentRebindProposal {
    pub(crate) id: EntityId,
    pub(crate) target: CodeConsentRebindTarget,
    pub(crate) prepared_revision: u64,
    pub(crate) requester: EntityId,
    pub(crate) actor_class: String,
    pub(crate) predecessor: [u8; 32],
    pub(crate) successor: [u8; 32],
    pub(crate) credential: CodeConsentSavedCredential,
    pub(crate) prior_receipt: Option<GateDecisionId>,
    pub(crate) intent_id: [u8; 32],
    pub(crate) proposed_at_ms: u64,
}

/// The owner's separate, explicit authorization for this admission's continuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentRebind {
    pub(crate) proposal: CodeConsentRebindProposal,
    pub(crate) binding_digest: [u8; 32],
    pub(crate) effect_digest: [u8; 32],
    pub(crate) prior_effect_digest: [u8; 32],
    pub(crate) prior_decision: GateDecisionId,
    pub(crate) original_approval: GateDecisionId,
    pub(crate) owner: EntityId,
    pub(crate) principal_ref: String,
    pub(crate) authentication: GateDecisionId,
    pub(crate) receipt: GateDecisionId,
    pub(crate) marker_decision: GateDecisionId,
    pub(crate) confirmed_at_ms: u64,
}

/// Only the original holder's own proposed succession, not the owner's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeConsentRebindPrepared {
    pub(crate) proposal_id: EntityId,
    pub(crate) revision: u64,
    pub(crate) predecessor: [u8; 32],
    pub(crate) successor: [u8; 32],
}

impl CodeConsentWaitRow {
    /// The original request or its last explicitly confirmed successor, as one pair.
    pub(crate) fn active_credential(&self) -> Option<&CodeConsentSavedCredential> {
        self.rebinds
            .last()
            .map(|rebind| &rebind.proposal.credential)
            .or(self.binding.original.credential.as_ref())
    }

    /// The effective binding for current authority, never a rewrite of the ask.
    pub(crate) fn active_binding(&self) -> CodeConsentBinding {
        let mut binding = self.binding.clone();
        if let Some(rebind) = self.rebinds.last() {
            binding.original.credential = Some(rebind.proposal.credential.clone());
            binding.original.opener_slip = Some(rebind.proposal.successor);
            binding.binding_digest = rebind.binding_digest;
            binding.effect_digest = rebind.effect_digest;
        }
        binding
    }

    /// The consumed authorization of this same admission, not an available tap.
    pub(crate) fn consumed_approval(&self) -> Option<([u8; 32], GateDecisionId)> {
        self.rebinds
            .last()
            .map(|rebind| (rebind.effect_digest, rebind.marker_decision))
            .or_else(|| {
                self.answer
                    .as_ref()
                    .map(|answer| (self.binding.effect_digest, answer.decision))
            })
    }
}
