//! Actual-holder proposal and independent-owner confirmation adapters.

use super::*;
use crate::code_run::{CodeConsentRebind, CodeConsentRebindProposal, CodeConsentRebindTarget};
use crate::entity_id::bytes_to_hex_lower;

impl Memory<'_> {
    /// Proposes only this request's own live successor; no owner proof substitutes for it.
    pub fn code_wait_rebind_prepare(
        &self,
        input: CodeWaitRebindPrepareRequest,
    ) -> MemoryResult<CodeWaitRebindPrepared> {
        let target = rebind_target(&input.target, input.revision)?;
        let prepared = self.vault.prepare_code_consent_rebind(
            &target,
            self.code_consent_principal(),
            self.actor_class().gate_actor_class(),
        )?;
        Ok(CodeWaitRebindPrepared {
            target: input.target,
            proposal_ref: prepared.proposal_id,
            revision: prepared.revision,
            predecessor: bytes_to_hex_lower(&prepared.predecessor),
            successor: bytes_to_hex_lower(&prepared.successor),
        })
    }

    /// The owner's distinct, non-generated act authorizes only this continuation.
    pub fn code_wait_rebind_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeWaitRebindRequest,
    ) -> MemoryResult<CodeWaitRebindReceipt> {
        self.code_wait_person(owner)?;
        if self.writes_generated() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "generated code cannot authorize a code consent rebind in a person's name",
                &["Ask the owner to confirm through their own client."],
            ));
        }
        self.code_wait_receipt_as(
            owner,
            CodeWaitReceiptRequest {
                run_id: input.target.run_id,
                wait_id: input.target.wait_id,
            },
        )?
        .ok_or_else(|| {
            MemoryError::not_found("code consent wait is unknown, unsealed or withheld")
        })?;
        let target = rebind_target(&input.target, input.revision)?;
        let (rebind, already_rebound) =
            self.vault
                .confirm_code_consent_rebind(owner, &target, input.proposal_ref)?;
        Ok(rebind_view(&rebind, already_rebound))
    }
}

fn rebind_target(target: &CodeWaitTarget, revision: u64) -> MemoryResult<CodeConsentRebindTarget> {
    Ok(CodeConsentRebindTarget {
        run_id: target.run_id,
        wait_id: target.wait_id,
        generation: target.generation,
        step_hash: super::operations::target_digest("target.step_hash", &target.step_hash)?,
        effect_digest: super::operations::target_digest(
            "target.effect_digest",
            &target.effect_digest,
        )?,
        revision,
    })
}

fn target_view(target: &CodeConsentRebindTarget) -> CodeWaitTarget {
    CodeWaitTarget {
        run_id: target.run_id,
        wait_id: target.wait_id,
        generation: target.generation,
        step_hash: bytes_to_hex_lower(&target.step_hash),
        effect_digest: bytes_to_hex_lower(&target.effect_digest),
    }
}

pub(super) fn prepared_view(proposal: &CodeConsentRebindProposal) -> CodeWaitRebindPrepared {
    CodeWaitRebindPrepared {
        target: target_view(&proposal.target),
        proposal_ref: proposal.id,
        revision: proposal.prepared_revision,
        predecessor: bytes_to_hex_lower(&proposal.predecessor),
        successor: bytes_to_hex_lower(&proposal.successor),
    }
}

pub(super) fn rebind_view(
    rebind: &CodeConsentRebind,
    already_rebound: bool,
) -> CodeWaitRebindReceipt {
    CodeWaitRebindReceipt {
        target: target_view(&rebind.proposal.target),
        proposal_ref: rebind.proposal.id,
        prepared_revision: rebind.proposal.prepared_revision,
        predecessor: bytes_to_hex_lower(&rebind.proposal.predecessor),
        successor: bytes_to_hex_lower(&rebind.proposal.successor),
        binding_digest: bytes_to_hex_lower(&rebind.binding_digest),
        effect_digest: bytes_to_hex_lower(&rebind.effect_digest),
        previous_effect_digest: bytes_to_hex_lower(&rebind.prior_effect_digest),
        intent_id: bytes_to_hex_lower(&rebind.proposal.intent_id),
        original_approval_ref: format!("gate:{}", rebind.original_approval.to_hex()),
        previous_marker_ref: format!("gate:{}", rebind.prior_decision.to_hex()),
        prior_rebind_ref: rebind
            .proposal
            .prior_receipt
            .map(|receipt| format!("gate:{}", receipt.to_hex())),
        owner_ref: rebind.owner,
        authentication_ref: format!("gate:{}", rebind.authentication.to_hex()),
        receipt_ref: format!("gate:{}", rebind.receipt.to_hex()),
        confirmed_at_ms: rebind.confirmed_at_ms,
        already_rebound,
    }
}
