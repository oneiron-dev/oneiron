//! A reviewed run's members, each settled by its kind: a claim or edge, a note, a topology event.

use super::*;

/// The owner's answer every member of the reviewed run settles under.
pub(super) struct RunAnswer<'a> {
    pub(super) owner: &'a AuthenticatedOwner,
    pub(super) owner_answer: Option<&'a crate::consent::OwnerAuthoredWrite>,
    pub(super) actor: WriteActor,
    pub(super) approve: bool,
    pub(super) now: u64,
}

/// One member's verdict, receipt and undo after its settlement.
pub(super) struct SettledMember {
    pub(super) verdict: RunChangeVerdict,
    pub(super) receipt: Option<String>,
    pub(super) inverse: Option<RunInverse>,
}

impl Memory<'_> {
    /// Settles one member from its reviewed verdict; a settled claim adds its
    /// gate metrics and, for an approved Dreamer claim, its VAD consolidation.
    pub(super) fn settle_member_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        answer: &RunAnswer<'_>,
        member: &RunReviewChange,
        verdict: RunChangeVerdict,
        metrics: &mut Vec<crate::gate::RecordedClaimGateDecision>,
        vad: &mut Vec<EntityId>,
    ) -> MemoryResult<SettledMember> {
        let mut outcome = SettledMember {
            verdict,
            receipt: None,
            inverse: None,
        };
        match member {
            RunReviewChange::Claim { claim_ref }
            | RunReviewChange::Edge {
                provenance_ref: claim_ref,
            } => {
                self.settle_claim_member_in_txn(
                    txn,
                    answer,
                    member,
                    claim_ref,
                    &mut outcome,
                    metrics,
                    vad,
                )?;
            }
            RunReviewChange::Note { note_ref, fork_ref } => {
                self.settle_note_member_in_txn(
                    txn,
                    answer.approve,
                    note_ref,
                    fork_ref,
                    &mut outcome,
                )?;
            }
            RunReviewChange::Topology { event_ref } => {
                self.settle_topology_member_in_txn(txn, answer, event_ref, &mut outcome)?;
            }
            RunReviewChange::ExternalEffect { .. }
            | RunReviewChange::Delete { .. }
            | RunReviewChange::Erase { .. } => {}
        }
        Ok(outcome)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "a claim member settles under the answer and feeds the commit's metrics and VAD"
    )]
    fn settle_claim_member_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        answer: &RunAnswer<'_>,
        member: &RunReviewChange,
        claim_ref: &str,
        outcome: &mut SettledMember,
        metrics: &mut Vec<crate::gate::RecordedClaimGateDecision>,
        vad: &mut Vec<EntityId>,
    ) -> MemoryResult<()> {
        let id = EntityId::from_hex(claim_ref)?;
        if outcome.verdict == RunChangeVerdict::Waiting {
            let settled = self.vault().settle_proposed_claim_in_txn(
                txn,
                id,
                if answer.approve {
                    GateConsentBundleAction::Approve
                } else {
                    GateConsentBundleAction::Decline
                },
                answer.actor,
                answer.owner_answer,
                answer.now,
            )?;
            metrics.extend(settled.recorded);
            outcome.receipt = settled
                .tray_receipt
                .map(|r| format!("gate:{}", r.decision_id.to_hex()));
            if answer.approve && settled.dreamer_run {
                vad.push(id);
            }
            outcome.verdict = if answer.approve {
                RunChangeVerdict::Landed
            } else {
                RunChangeVerdict::Rejected
            };
        }
        if outcome.verdict == RunChangeVerdict::Landed {
            let body = self
                .vault()
                .get_claim_in_txn(txn, &id)?
                .ok_or_else(|| MemoryError::not_found("settled claim is absent"))?;
            let author = snapshot::claim_author(&body)?;
            outcome.inverse = Some(RunInverse::Authored {
                author: author.to_hex(),
                fingerprint: fingerprint(&snapshot::binding(self, txn, member)?.0),
            });
        }
        Ok(())
    }

    fn settle_note_member_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        approve: bool,
        note_ref: &str,
        fork_ref: &str,
        outcome: &mut SettledMember,
    ) -> MemoryResult<()> {
        let landed = crate::note::settle_run_note_in_txn(
            self,
            txn,
            EntityId::from_hex(note_ref)?,
            EntityId::from_hex(fork_ref)?,
            approve,
        )?;
        if let Some((reference, undo)) = landed {
            outcome.receipt = Some(reference);
            outcome.verdict = if approve {
                RunChangeVerdict::Landed
            } else {
                RunChangeVerdict::Rejected
            };
            if approve {
                outcome.inverse = Some(RunInverse::Note(undo));
            }
        }
        Ok(())
    }

    fn settle_topology_member_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        answer: &RunAnswer<'_>,
        event_ref: &str,
        outcome: &mut SettledMember,
    ) -> MemoryResult<()> {
        let event = EntityId::from_hex(event_ref)?;
        let applied = if outcome.verdict == RunChangeVerdict::Waiting {
            // Where his request reached this install, as
            // the host bound it (FIX 4650): audit only.
            let seal = TopologySeal::decision(crate::authority::ActAuthority::Owner(
                answer.owner.clone(),
                self.owner_surface(),
            ));
            let write = IdentityOpWrite {
                source: crate::claim::ClaimSource::UserStated,
                approval: ClaimApprovalStatus::Approved,
                confidence: 1.0,
                actor: Some(answer.actor),
            };
            let (_, resolution, applied) =
                self.vault().resolve_identity_proposal_with_applied_in_txn(
                    txn,
                    &event,
                    if answer.approve {
                        ProposalRuling::Approve
                    } else {
                        ProposalRuling::Reject
                    },
                    &write,
                    &seal,
                    answer.now,
                )?;
            outcome.receipt = Some(resolution.to_hex());
            outcome.verdict = if answer.approve {
                RunChangeVerdict::Landed
            } else {
                RunChangeVerdict::Rejected
            };
            applied
        } else {
            // FIX 9966: an already-ruled proposal's undo names
            // the op its ruling applied, never the proposal.
            let stored = self
                .vault()
                .identity_topology_event_in_txn(txn, &event)?
                .ok_or_else(|| MemoryError::not_found("topology event is absent"))?;
            crate::memory::run_review::topology::topology_outcome_in_txn(
                self.vault(),
                txn,
                event,
                &stored,
            )?
            .applied
        };
        outcome.inverse = applied.map(|event| RunInverse::Topology {
            event: event.to_hex(),
        });
        Ok(())
    }
}
