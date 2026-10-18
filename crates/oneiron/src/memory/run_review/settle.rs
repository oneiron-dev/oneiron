use super::*;
use crate::claim::ClaimApprovalStatus;
use crate::identity_topology::{IdentityOpWrite, ProposalRuling, TopologySeal};
use crate::run_tree::GateConsentBundleAction;

impl Memory<'_> {
    /// Both answers use the existing per-kind admission and one atomic
    /// transaction. No stale review can settle a newly changed member.
    pub fn settle_run_as_owner(
        &self, owner: &AuthenticatedOwner, input: &RunSettleRequest,
    ) -> MemoryResult<RunSettlement> {
        let run = run_key(&input.review.run_id)?;
        let approve = input.decision == RunSettleDecision::Approve;
        let now = self.vault().store.clock.now_recorded_at();
        let (settlement, metrics, vad) = self.with_verified_actor_write_txn(|txn| {
            let actor = require_owner(self, txn, owner)?;
            if SETTLEMENTS.get(&self.vault().store, txn, &run)?.is_some() {
                return Err(MemoryError::bad_request("this run review already settled"));
            }
            let review = snapshot::review_in_txn(self, txn, &input.review)?;
            if review.review_id != input.review_id {
                return Err(MemoryError::new(super::super::MEMORY_CODE_INVALID_STATE,
                    "the review changed; review the complete set again", &[]));
            }
            let owner_answer = owner.owner_answer_in_txn(self.vault(), txn)?;
            let mut changes = Vec::new();
            let mut stored = Vec::new();
            let mut metrics = Vec::new();
            let mut vad = Vec::new();
            for (member, reviewed) in input.review.changes.iter().zip(&review.changes) {
                let mut verdict = reviewed.verdict;
                let mut receipt = None;
                let mut inverse = None;
                match member {
                    RunReviewChange::Claim { claim_ref }
                    | RunReviewChange::Edge { provenance_ref: claim_ref } => {
                        let id = EntityId::from_hex(claim_ref)?;
                        if verdict == RunChangeVerdict::Waiting {
                            let settled = self.vault().settle_proposed_claim_in_txn(
                                txn, id, if approve { GateConsentBundleAction::Approve }
                                    else { GateConsentBundleAction::Decline },
                                actor, owner_answer.as_ref(), now,
                            )?;
                            metrics.extend(settled.recorded);
                            receipt = settled.tray_receipt.map(|r| format!("gate:{}", r.decision_id.to_hex()));
                            if approve && settled.dreamer_run { vad.push(id); }
                            verdict = if approve { RunChangeVerdict::Landed } else { RunChangeVerdict::Rejected };
                        }
                        if verdict == RunChangeVerdict::Landed {
                            let body = self.vault().get_claim_in_txn(txn, &id)?
                                .ok_or_else(|| MemoryError::not_found("settled claim is absent"))?;
                            let author = snapshot::claim_author(&body)?;
                            inverse = Some(RunInverse::Authored {
                                author: author.to_hex(),
                                fingerprint: fingerprint(&snapshot::binding(self, txn, member)?.0),
                            });
                        }
                    }
                    RunReviewChange::Note { note_ref, fork_ref } => {
                        let landed = crate::note::settle_run_note_in_txn(self, txn,
                            EntityId::from_hex(note_ref)?, EntityId::from_hex(fork_ref)?, approve)?;
                        if let Some((reference, undo)) = landed {
                            receipt = Some(reference);
                            verdict = if approve { RunChangeVerdict::Landed } else { RunChangeVerdict::Rejected };
                            if approve { inverse = Some(RunInverse::Note(undo)); }
                        }
                    }
                    RunReviewChange::Topology { event_ref } => {
                        let event = EntityId::from_hex(event_ref)?;
                        let applied = if verdict == RunChangeVerdict::Waiting {
                            let seal = TopologySeal::decision(crate::authority::ActAuthority::Owner(
                                owner.clone(), crate::authority::ActSurface::ThisInstall,
                            ));
                            let write = IdentityOpWrite {
                                source: crate::claim::ClaimSource::UserStated,
                                approval: ClaimApprovalStatus::Approved,
                                confidence: 1.0, actor: Some(actor),
                            };
                            let (_, resolution, applied) = self.vault()
                                .resolve_identity_proposal_with_applied_in_txn(txn, &event,
                                    if approve { ProposalRuling::Approve } else { ProposalRuling::Reject },
                                    &write, &seal, now)?;
                            receipt = Some(resolution.to_hex());
                            verdict = if approve { RunChangeVerdict::Landed } else { RunChangeVerdict::Rejected };
                            applied
                        } else { Some(event) };
                        inverse = applied.map(|event| RunInverse::Topology { event: event.to_hex() });
                    }
                    RunReviewChange::ExternalEffect { .. }
                    | RunReviewChange::Delete { .. } | RunReviewChange::Erase { .. } => {}
                }
                changes.push(RunChangeOutcome {
                    change: member.change().to_owned(), verdict, receipt,
                });
                stored.push(StoredChange { member: member.clone(), verdict, inverse, compensation: None, unrestored: Vec::new() });
            }
            let reason = if approve { RunSettlementReason::OwnerApproved } else { RunSettlementReason::OwnerRejected };
            let record = super::super::authorship::decision(actor, "proposal_outcome",
                if approve { "approved" } else { "rejected" },
                if approve { "gate.run.settle.approved" } else { "gate.run.settle.rejected" },
                None, review.review_id.as_bytes().to_vec(), now);
            self.vault().store.append_gate_decision_in_txn(txn, &record)?;
            let reference = format!("gate:{}", record.decision_id.to_hex());
            // The owner act's own durable word, not a caller-supplied person
            // id or an invented rule/grant attribution.
            let settlement = RunSettlement {
                kind: RunSettlementKind::ProposalOutcome, run_id: run.clone(),
                receipt: reference.clone(),
                verdict: if changes.iter().any(|c| c.verdict == RunChangeVerdict::Waiting) {
                    RunChangeVerdict::Waiting
                } else if approve { RunChangeVerdict::Landed } else { RunChangeVerdict::Rejected },
                changes, answered_by: RunAnsweredBy::Word { word_ref: reference }, reason,
                summary: if approve { "The owner accepted the reviewed changes." }
                    else { "The owner rejected the waiting changes; earlier landings stay." }.to_owned(),
                revert_handle: format!("run:{run}"),
            };
            SETTLEMENTS.put(&self.vault().store, txn, &run,
                &StoredRun { settlement: settlement.clone(), changes: stored })?;
            Ok((settlement, metrics, vad))
        })?;
        for decision in metrics {
            decision.record_metrics(&self.vault().store.diagnostics.gate);
        }
        for claim in vad { self.vault().consolidate_claim_vad_now(&claim, now)?; }
        self.produced_from(input.review.changes.iter().map(RunReviewChange::rows)
            .collect::<MemoryResult<Vec<_>>>()?.into_iter().flatten());
        Ok(settlement)
    }
}
