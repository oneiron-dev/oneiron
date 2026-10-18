//! One proposed claim decided on its own (DOOR-115): the owner's approval or
//! decline of a claim named by its id, not by the run that proposed it, with
//! the consent mechanics a run bundle uses on each of its members.
//!
//! Approval lands the claim's unamended body as the approver's gated write
//! ([`crate::batch::ClaimMaterialization::apply_approval`]), which keeps its
//! author and signs a MACHINE claim's Approve event. A decline replays the
//! reviewed body through the live gate and closes the claim as a declined
//! bundle member closes: a MACHINE claim through its signed Reject event, any
//! other as Rejected and Retracted. A claim that waits in the pending-consent
//! tray has its row closed with its own resolution receipt. The caller has
//! already checked, in this transaction, the owner's proof, the review the
//! decision names and the opener's lineage.

use super::*;

/// Reason code on the tray row an approval closes.
const CLAIM_SETTLE_REASON_APPROVED: &str = "gate.claim.settle.approved";

/// Reason code on the tray row a decline closes.
const CLAIM_SETTLE_REASON_DECLINED: &str = "gate.claim.settle.declined";

/// `grant_ref` prefix binding a closed tray row to the settlement that closed
/// it.
const CLAIM_SETTLE_REF_PREFIX: &str = "claim_settle:";

/// What one claim's decision did, in the transaction that decided it.
pub(crate) struct SettledProposal {
    /// The body the claim carries now.
    pub(crate) body: ClaimBody,
    /// The tray row's resolution receipt, when the claim waited there.
    pub(crate) tray_receipt: Option<GateDecisionRecord>,
    /// The live gate decisions the decision recorded, for the gate's metrics
    /// once the transaction commits.
    pub(crate) recorded: Vec<RecordedClaimGateDecision>,
    /// Whether the proposal came from a Dreamer run: its approval
    /// consolidates VAD once the transaction commits.
    pub(crate) dreamer_run: bool,
}

impl Vault {
    /// Approves or declines the active proposed claim `id` as `actor`, the
    /// owner, in `wtxn`. `owner_answer` is the owner-tier proof that answers
    /// the claim's owner-answer obligation, when the proof holds one.
    ///
    /// A decline needs the claim's pending-consent row: its rejection is the
    /// consent transition that row binds. A tray row whose binding moved since
    /// it was parked refuses [`GateError::GateConsentStale`], and a gate
    /// denial or hold refuses as the gate answers it, so nothing changes.
    pub(crate) fn settle_proposed_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: EntityId,
        action: GateConsentBundleAction,
        actor: WriteActor,
        owner_answer: Option<&crate::consent::OwnerAuthoredWrite>,
        now: u64,
    ) -> Result<SettledProposal> {
        self.settle_reviewed_claim_in_txn(wtxn, id, action, actor, owner_answer, now, false)
    }

    /// The owner's reviewed generated claim, including an unvetted Auto
    /// head, through the same materialization, Gate and receipt machinery.
    pub(crate) fn vet_generated_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: EntityId,
        action: GateConsentBundleAction,
        actor: WriteActor,
        owner_answer: Option<&crate::consent::OwnerAuthoredWrite>,
        now: u64,
    ) -> Result<SettledProposal> {
        self.verify_owner_write_actor_in_txn(wtxn, &actor)?;
        let body = self
            .get_claim_in_txn(wtxn, &id)?
            .ok_or(Error::EntityNotFound)?;
        if !crate::claim::claim_generated_origin(&body) {
            return Err(Error::InvalidClaimBody(
                "vetting requires a generated-origin claim",
            ));
        }
        self.settle_reviewed_claim_in_txn(wtxn, id, action, actor, owner_answer, now, true)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one reviewed settlement and its vetting mode"
    )]
    fn settle_reviewed_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: EntityId,
        action: GateConsentBundleAction,
        actor: WriteActor,
        owner_answer: Option<&crate::consent::OwnerAuthoredWrite>,
        now: u64,
        vetting: bool,
    ) -> Result<SettledProposal> {
        let (body, header) = live_claim_parts_in_txn(&self.store, &*wtxn, &id)?;
        let vet_auto = vetting
            && body.approval == ClaimApprovalStatus::Auto
            && crate::claim::claim_generated_origin(&body)
            && action == GateConsentBundleAction::Approve;
        if (body.approval != ClaimApprovalStatus::Proposed && !vet_auto)
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            return Err(Error::InvalidClaimBody(
                "claim settlement requires an active proposal",
            ));
        }
        let pending = self.store.pending_gate_consent_in_txn(&*wtxn, &id)?;
        if let Some(row) = &pending {
            let (diff_handle, read_frontier_hash) =
                claim_consent_binding_parts(&self.store, &*wtxn, &body)?;
            if diff_handle != row.diff_handle || read_frontier_hash != row.read_frontier_hash {
                return Err(Error::Gate(GateError::GateConsentStale { claim_id: id }));
            }
        }
        let mut recorded = Vec::new();
        let (resolved, tray_receipt) = match action {
            GateConsentBundleAction::Approve => {
                // Closed before the approval lands, so the row leaves its own
                // resolution receipt; a refused approval rolls it back.
                let tray_receipt =
                    close_settled_tray_row_in_txn(self, wtxn, &id, owner_answer, action, now)?;
                let mut approved = body.clone();
                approved.approval = ClaimApprovalStatus::Approved;
                crate::batch::ClaimMaterialization::apply_approval(
                    self,
                    wtxn,
                    BatchOp::Put {
                        id,
                        entity_type: ENTITY_TYPE_CLAIM,
                        occurred: TimeRange {
                            start: header.occurred_start,
                            end: header.occurred_end,
                        },
                        learned_at: header.learned_at,
                        data: encode_claim_body(&approved)?,
                        allow_maintenance: false,
                        allow_reserved_predicate: false,
                        hub_sync_imported: false,
                    },
                    true,
                    Some(actor),
                )?;
                self.complete_deferred_claim_in_txn(wtxn, &id, false, now)?;
                // An approved task proposal lands its TASK in this txn.
                crate::task_verb::settle_task_proposal_in_txn(self, wtxn, id, Some(actor), now)?;
                let resolved = self
                    .get_claim_in_txn(&*wtxn, &id)?
                    .ok_or(Error::EntityNotFound)?;
                (resolved, tray_receipt)
            }
            GateConsentBundleAction::Decline => {
                // A Proposed claim may have no pending obligation (for
                // example an explicit proposal). The same gate and signed
                // rejection still apply; close_settled_tray_row handles the
                // absent row without inventing consent.
                // A MACHINE claim changes only through its signed history,
                // whose fold rejects without retracting.
                let machine =
                    crate::authority::machine_claim_needs_history(&self.store, &*wtxn, &body)?;
                let mut resolved = body.clone();
                resolved.approval = ClaimApprovalStatus::Rejected;
                let occurred = if machine {
                    TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    }
                } else {
                    resolved.lifecycle = ClaimLifecycleStatus::Retracted;
                    resolved.valid_to = Some(now);
                    TimeRange {
                        start: header.occurred_start,
                        end: now.max(header.occurred_start),
                    }
                };
                // The reviewed body is what the gate answers for: a decline
                // closes the claim, and a closed body has no verdict.
                let policy = resolve_policy_manifest(&self.store, &*wtxn)?;
                replay_gate_consent_bundle_member(
                    self,
                    wtxn,
                    &id,
                    &body,
                    &policy,
                    actor,
                    &mut recorded,
                )?;
                if machine {
                    resolved = crate::claim::transition::stage_consent_transition(
                        self, wtxn, id, false, actor, now,
                    )?;
                }
                let put = BatchOp::Put {
                    id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred,
                    learned_at: header.learned_at,
                    data: encode_claim_body(&resolved)?,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                };
                let transition =
                    crate::batch::VerifiedClaimTransition::after_consent(&self.store, wtxn, &put)?;
                let tray_receipt =
                    close_settled_tray_row_in_txn(self, wtxn, &id, owner_answer, action, now)?;
                crate::batch::apply_session_bundle_claim_puts_with_transitions(
                    &self.store,
                    &self.config,
                    &self.analyzer,
                    wtxn,
                    vec![put],
                    vec![transition],
                    self.text_index_trusted
                        .load(std::sync::atomic::Ordering::Acquire),
                )?;
                self.cancel_deferred_claim_in_txn(wtxn, &id)?;
                (resolved, tray_receipt)
            }
        };
        // The host's timers re-read the claim this decision moved.
        crate::batch::queue_proactivity_change(self, wtxn);
        if let Some(row) = &pending {
            // An answer to a Coach heal counts as its review (OF-418).
            crate::dreamer_runner::maintenance::coach_heal::record_owner_review_in_txn(
                self,
                wtxn,
                id,
                &body,
                row.created_at,
                now,
            )?;
        }
        // The fact hooks' settlement feed hears the claim in the transaction
        // that settles it (OF-579).
        crate::runtime_hooks::record_settlement_in_txn(
            self,
            wtxn,
            crate::runtime_hooks::SettledFact {
                proposal: id,
                outcome: match action {
                    GateConsentBundleAction::Approve => {
                        crate::runtime_hooks::SettledOutcome::Approved
                    }
                    GateConsentBundleAction::Decline => {
                        crate::runtime_hooks::SettledOutcome::Declined
                    }
                },
                settled_by: actor.entity_ref(),
                kind: crate::runtime_hooks::SettlementKind::ClaimSettlement,
            },
        )?;
        Ok(SettledProposal {
            body: resolved,
            tray_receipt,
            recorded,
            dreamer_run: pending.is_some_and(|row| row.dreamer_run_id.is_some()),
        })
    }
}

/// Closes `id`'s tray row, when it has one, with the decision's resolution
/// receipt. An owner-tier proof answers the claim's owner-answer obligation
/// for the revision the row showed; a narrower one answers none.
fn close_settled_tray_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    owner_answer: Option<&crate::consent::OwnerAuthoredWrite>,
    action: GateConsentBundleAction,
    now: u64,
) -> Result<Option<GateDecisionRecord>> {
    let Some(row) = vault.store.pending_gate_consent_in_txn(&*wtxn, id)? else {
        return Ok(None);
    };
    let removal = match owner_answer {
        Some(proof) => crate::gate::close_owner_answer_obligation_in_txn(
            &vault.store,
            wtxn,
            id,
            &row.diff_handle,
            crate::gate::OwnerAnswer::owner(proof),
        )?,
        None => crate::store::TrayRemoval::Unanswered,
    };
    let (outcome, reason) = match action {
        GateConsentBundleAction::Approve => (
            GATE_BUNDLE_MEMBER_OUTCOME_APPROVED,
            CLAIM_SETTLE_REASON_APPROVED,
        ),
        GateConsentBundleAction::Decline => (
            GATE_BUNDLE_MEMBER_OUTCOME_REJECTED,
            CLAIM_SETTLE_REASON_DECLINED,
        ),
    };
    vault.store.close_pending_gate_consent_as_in_txn(
        wtxn,
        id,
        now,
        outcome,
        vec![reason.to_owned()],
        Some(format!("{CLAIM_SETTLE_REF_PREFIX}{}", id.to_hex())),
        removal,
    )
}
