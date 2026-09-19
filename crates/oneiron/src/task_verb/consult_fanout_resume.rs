//! Authenticated exact-digest resume; ruling, policy and TASKs commit together.

use super::consult_fanout_store::{TxnSurface, load_run, save_run};
use super::create_validation::consult_refusal;
use super::{ConsultFanOutChoice, ConsultFanOutReceipt};
use crate::consent::AuthenticatedOwner;
use crate::edit_distance::escalation::{
    EscalationReceipt, EscalationRuling, EscalationTrigger, record_explicit_ruling_in_txn,
};
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryResult, verify_actor_binding,
};
use crate::outbound_chokepoint::{
    FanoutApprovalChoice, FanoutApprovalError, approve_and_resume_fanout, fanout_plan_digest,
};
use crate::unix_seconds_now;

impl Memory<'_> {
    /// Reads the durable run, including a denial parked across restart.
    pub fn consult_fanout_status(
        &self,
        correlation: EntityId,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        let run = load_run(self.vault(), &txn, correlation)?;
        if run.plan.actor_ref != self.actor().to_hex() {
            return Err(consult_refusal(
                MEMORY_CODE_FORBIDDEN,
                "fan-out belongs to another actor",
                "Read the run through its originating actor.",
            ));
        }
        run.receipt()
    }

    /// Rules on the digest shown to the authenticated human. No replacement
    /// payload is accepted. Retrying an approval returns the same TASK set.
    pub fn resume_fan_out_consults(
        &self,
        correlation: EntityId,
        expected_digest: [u8; 32],
        choice: ConsultFanOutChoice,
        owner: &AuthenticatedOwner,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        self.reauthenticate_fanout_owner(owner)?;
        let now = unix_seconds_now();
        self.vault()
            .memory(owner.actor(), crate::EdgeActorClass::Human)
            .with_verified_actor_write_txn(|txn| {
                self.reauthenticate_fanout_owner(owner)?;
                verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
                let mut run = load_run(self.vault(), txn, correlation)?;
                if run.plan.actor_ref != self.actor().to_hex() {
                    return Err(consult_refusal(
                        MEMORY_CODE_FORBIDDEN,
                        "fan-out belongs to another actor",
                        "Resume through its originating actor.",
                    ));
                }
                if run.estimate.plan_digest != expected_digest {
                    return Err(stale_digest());
                }
                // Confirm stored input still computes the exact plan. Not a
                // comparison of two caller-supplied hashes or a mutable draft.
                let frozen_policy = super::ConsultFanOutPolicy {
                    mode: run.plan.mode,
                    ..super::ConsultFanOutPolicy::default()
                };
                let plan = run.input.plan(self.actor(), correlation, &frozen_policy)?;
                if plan != run.plan || fanout_plan_digest(&plan)? != expected_digest {
                    return Err(stale_digest());
                }
                if run.dispatched_at.is_some() {
                    if choice == ConsultFanOutChoice::Deny {
                        return Err(consult_refusal(
                            MEMORY_CODE_INVALID_STATE,
                            "a dispatched fan-out cannot be denied retroactively",
                            "Use the TASK cancellation door.",
                        ));
                    }
                    return run.receipt();
                }
                let row = run.pause.clone().ok_or_else(|| {
                    consult_refusal(
                        MEMORY_CODE_INVALID_STATE,
                        "fan-out has no surfaced approval",
                        "Submit a new fan-out plan.",
                    )
                })?;
                let core_choice = match choice {
                    ConsultFanOutChoice::ApproveOnce => FanoutApprovalChoice::ApproveOnce,
                    ConsultFanOutChoice::ApproveAndRemember => {
                        FanoutApprovalChoice::ApproveAndRememberBriefVerb
                    }
                    ConsultFanOutChoice::Deny => FanoutApprovalChoice::KeepPaused,
                };
                let action = core_choice.action_id();
                let resumed = approve_and_resume_fanout(
                    &plan,
                    &row,
                    core_choice,
                    action,
                    owner.principal_ref(),
                    &mut TxnSurface {
                        vault: self.vault(),
                        txn,
                        run: &mut run,
                    },
                    now.saturating_mul(1000),
                )
                .map_err(|error| match error {
                    FanoutApprovalError::StalePlanDigest => stale_digest(),
                    FanoutApprovalError::Engine(error) => error.into(),
                })?;
                let approved = resumed.is_some();
                record_explicit_ruling_in_txn(
                    self.vault(),
                    txn,
                    owner,
                    EscalationReceipt {
                        task_ref: correlation,
                        scope: run.scope(),
                        trigger: EscalationTrigger::Budget,
                        question: run.plan.brief_ref.clone(),
                        ruling: if approved {
                            EscalationRuling::Approve
                        } else {
                            EscalationRuling::Deny
                        },
                        rationale: run.choice_receipt_ref.clone().unwrap_or_default(),
                        // Raw consult count is the magnitude. The existing ED-06
                        // ceiling comparison enforces <=, never an unbounded verb grant.
                        budget_band: Some(u64::from(run.estimate.total_count)),
                    },
                    choice == ConsultFanOutChoice::ApproveAndRemember,
                    now,
                )?;
                run.denied = !approved;
                if let Some(resume) = resumed {
                    if resume.plan_digest != expected_digest {
                        return Err(stale_digest());
                    }
                    run.choice_receipt_ref = Some(resume.choice_receipt_ref);
                    // This old primitive also offers an outbound verb intent.
                    // It has no count cap and MUST NOT widen the remembered cap.
                    drop(resume.grant_mint_intent);
                    let input = run.input.thaw(self.vault(), now)?;
                    let entries = self.validate_fanout(&input, correlation, now)?;
                    self.mint_fanout_in(txn, &entries, &input, &mut run, now, now)?;
                }
                save_run(self.vault(), txn, &run)?;
                run.receipt()
            })
    }
}

fn stale_digest() -> crate::memory::MemoryError {
    consult_refusal(
        MEMORY_CODE_INVALID_STATE,
        "fan-out approval digest does not match the frozen plan",
        "Read the surfaced digest and rule on that exact plan.",
    )
}
