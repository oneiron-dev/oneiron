//! The claim put: code mode asks Proposed; a caller's live run asks Auto
//! first, and the checker its door lent reviews that ask in the landing's
//! transaction (FIX LIVE-RUN-CHECKER-INJECT).

use crate::ClaimSubject;
use crate::claim::ScopedReadActorKey;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    SelfDispatchOutcome, SelfEffect, SelfMemoryPutClaimCall, SelfMemoryWriteResult,
};
use crate::error::{Error, Result};

use super::super::HostSelfDispatcher;

impl HostSelfDispatcher<'_> {
    pub(in crate::code_run::dispatcher) fn dispatch_memory_put_claim(
        &self,
        call: SelfMemoryPutClaimCall,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<SelfDispatchOutcome> {
        self.dispatch_memory_put_claim_requesting(
            call,
            read_as,
            crate::claim::ClaimApprovalStatus::Proposed,
            false,
        )
    }

    /// The claim put asking `approval` of the gates: code mode asks
    /// Proposed; a caller's live run asks Auto first (FIX 3983).
    /// `checker_review`: the put is a caller's live-run put, which names
    /// itself to the gate whatever it asks, so the host's auto checker
    /// reviews its Auto request and its Proposed resubmission keeps that
    /// review's hold as a pending review (review 6908 P1).
    pub(crate) fn dispatch_memory_put_claim_requesting(
        &self,
        call: SelfMemoryPutClaimCall,
        read_as: Option<ScopedReadActorKey>,
        approval: crate::claim::ClaimApprovalStatus,
        checker_review: bool,
    ) -> Result<SelfDispatchOutcome> {
        // A position-narrowed slip places no row in core (FIX 10666).
        self.refuse_narrowed_program_write()?;
        let admission = self.code_emission_admission()?;
        let candidate = match admission
            .as_ref()
            .and_then(|admission| admission.candidate_evidence.clone())
        {
            Some(evidence) => (*call.candidate).clone().with_evidence(evidence),
            None => *call.candidate,
        };
        // A live run's put names itself to the gate, whose auto checker reviews it as it reviews a Dreamer
        // write (FIX 3983, review 6881 P1). Its Proposed resubmission carries the same marker, so a checker
        // hold parks it with a pending review instead of landing it unreviewed (review 6908 P1). Code mode
        // carries no marker.
        let producer = if checker_review {
            vec![(
                rmpv::Value::from(crate::gate::CHECKED_PRODUCER_PROVENANCE_KEY),
                rmpv::Value::from(crate::gate::LIVE_RUN_CLAIM_PUT_PRODUCER),
            )]
        } else {
            Vec::new()
        };
        let envelope = self
            .write_envelope_with(SelfEffect::MemoryPutClaim, admission.as_ref(), producer)?
            .with_approval(approval);
        // A live run's put to canonical storage is reviewed by the checker
        // its door lent (FIX LIVE-RUN-CHECKER-INJECT).
        let lent_checker = match (&self.storage, self.auto_checker) {
            (ExecutorStorage::Canonical(vault), Some(checker)) if checker_review => {
                Some((*vault, checker))
            }
            _ => None,
        };
        // The write gate reads no facet; the stored body takes the vault
        // default when the write applies. A put a lent checker reviews is
        // judged again in its landing's transaction, at the facet the landing
        // stamps (below).
        let gate_body = candidate.clone().into_claim_body(
            &envelope,
            crate::claim::substrate_facet_id(envelope.actor().entity_ref())?,
        )?;
        let authored_rules = crate::dreamer_consolidation::prepare_authored_claim(
            &gate_body.predicate,
            &gate_body.value,
        )?;
        if authored_rules.is_some()
            && (gate_body.subject != ClaimSubject::Entity(self.actor.entity_ref())
                || self.actor.actor_class() != crate::EdgeActorClass::Agent)
        {
            return Err(Error::InvalidConfig(
                "Dreamer rule author is not the bound resident".into(),
            ));
        }
        // The subject it names resolves for its writer (OF-063, FIX 1214).
        let subject = match gate_body.subject {
            ClaimSubject::Entity(id) => vec![("/subject", id)],
            ClaimSubject::Edge { source, target, .. } => {
                vec![("/subject", source), ("/subject", target)]
            }
        };
        if let Some(refused) = self.refused_write_reference(
            SelfEffect::MemoryPutClaim,
            "vault.claims.put",
            read_as.as_ref(),
            &subject,
        )? {
            return Ok(refused);
        }
        // The lent checker reviews this ask once, in the transaction that
        // lands it: its gate consults it and records the decision, which the
        // landing reuses (FIX 8752), so no write (a policy that now names a
        // checker, a changed row) comes between the verdict and the landing it
        // answers for. Its turn is taken before the write transaction opens,
        // as the Dreamer's writer takes it (FIX 8751), so the gate never waits
        // for capacity.
        let actual_id = match lent_checker {
            Some((vault, checker)) => {
                let checker = checker.admit_for_writes(&vault.store, self.actor.entity_ref())?;
                // A hold of the Auto request lands it Proposed in this same
                // transaction, the hold replayed onto its pending review: a
                // resubmission would ask the checker again, and the hold this
                // ask recorded would change that answer (review 9216 round 2
                // P1).
                let held_envelope =
                    (approval == crate::claim::ClaimApprovalStatus::Auto).then(|| {
                        envelope
                            .clone()
                            .with_approval(crate::claim::ClaimApprovalStatus::Proposed)
                    });
                let gate_candidate = candidate.clone();
                vault.put_claim_candidate_with_gate_returning_actual(
                    &call.id,
                    candidate,
                    &envelope,
                    call.occurred,
                    call.learned_at,
                    |_| Ok(()),
                    |txn| {
                        // The gate judges the body the landing stores, at the
                        // facet the landing stamps, read in this transaction,
                        // so the decision it records names that body (its
                        // diff handle) and the landing can reuse it (review
                        // 9216 round 2 P1).
                        let facet =
                            crate::batch::claim_candidate_apply::claim_candidate_birth_facet(
                                &vault.store,
                                &*txn,
                                &call.id,
                            )?;
                        let gate_body = gate_candidate.into_claim_body(&envelope, facet)?;
                        let (verdict, recorded) = super::super::envelope::check_write_gate_in_txn(
                            vault,
                            txn,
                            call.id,
                            &gate_body,
                            &envelope,
                            true,
                            Some(&checker),
                        )?;
                        Ok(landing_gate_answer(verdict, recorded, held_envelope))
                    },
                )?
            }
            None => {
                self.check_write_gate(call.id, &gate_body, &envelope, true)?;
                match &self.storage {
                    ExecutorStorage::Canonical(vault) => vault
                        .put_claim_candidate_with_landing_returning_actual(
                            &call.id,
                            candidate,
                            &envelope,
                            call.occurred,
                            call.learned_at,
                            |_| Ok(()),
                        )?,
                    ExecutorStorage::Session(binding) => {
                        binding.session.executor_put_claim_candidate(
                            &binding.route,
                            &call.id,
                            candidate,
                            &envelope,
                            call.occurred,
                            call.learned_at,
                        )?
                    }
                }
            }
        };

        if let Some(json) = authored_rules {
            let admitted = match &self.storage {
                ExecutorStorage::Canonical(vault) => {
                    crate::dreamer_consolidation::admitted_authored_claim(
                        vault, &actual_id, self.actor,
                    )?
                }
                ExecutorStorage::Session(binding) => binding.session.admitted_executor_claim(
                    &binding.route,
                    &actual_id,
                    self.actor,
                )?,
            };
            if !admitted {
                return Err(Error::InvalidConfig(
                    "Dreamer rules require an admitted resident claim".into(),
                ));
            }
            let record =
                crate::dreamer_consolidation::resident_record(self.actor, &json, Some(&actual_id))?;
            match &self.storage {
                ExecutorStorage::Canonical(vault) => {
                    vault.set_claimed_dreamer_failure_rules(self.actor, &json, &actual_id)?;
                }
                ExecutorStorage::Session(binding) => {
                    binding.session.side_table_put_routed(
                        &binding.route,
                        &crate::dreamer_consolidation::DREAMER_FAILURE_RULES,
                        &(),
                        &record,
                    )?;
                }
            }
        }
        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: actual_id,
        }))
    }
}

/// The landing's answer to the gate a lent checker reviewed in its
/// transaction (FIX LIVE-RUN-CHECKER-INJECT): an admission's recorded
/// decision is reused by the landing (FIX 8752); the checker's hold of an
/// Auto request, alone, lands the candidate under `held_envelope`, which asks
/// Proposed, with that hold replayed onto its pending review (review 9216
/// round 2 P1); any other refusal commits only the decision it recorded.
fn landing_gate_answer(
    verdict: Result<()>,
    recorded: Option<crate::gate::RecordedClaimGateDecision>,
    held_envelope: Option<crate::write_envelope::WriteEnvelope>,
) -> crate::claim::LandingGateAnswer {
    use crate::claim::LandingGateAnswer;
    match (verdict, recorded, held_envelope) {
        (Ok(()), recorded, _) => LandingGateAnswer::Admitted(
            recorded
                .as_ref()
                .map(crate::gate::RecordedClaimGateDecision::decision_id),
        ),
        (Err(refusal), Some(recorded), Some(envelope))
            if recorded.checker_hold() && crate::gate::gate_rejection_pends(&refusal) =>
        {
            LandingGateAnswer::CheckerHold {
                decision: recorded.decision_id(),
                envelope,
            }
        }
        (Err(refusal), _, _) => LandingGateAnswer::Refused(refusal),
    }
}
