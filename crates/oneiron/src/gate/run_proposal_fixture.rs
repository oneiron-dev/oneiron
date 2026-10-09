//! Test-support seam: park one Dreamer-authored proposal on a run's consent
//! lane, as a dream pass does, so a host can drive whole-run consent end to
//! end without a model. Compiled only with `test-support`.
use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::edge::EdgeActorClass;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, Error, Result, Vault};

use super::constants::{DREAMER_PROVENANCE_RUN_ID_KEY, DREAMER_PROVENANCE_RUNNER_KEY};

impl Vault {
    /// Writes one Generated `profile.name` proposal of `value` from `agent`
    /// about `subject` under `run_id` and requires the Gate to park it for
    /// consent.
    ///
    /// # Errors
    /// Any write failure, or the live policy not parking the proposal.
    pub fn park_run_proposal_for_test(
        &self,
        run_id: &str,
        agent: EntityId,
        subject: EntityId,
        value: impl Into<Value>,
    ) -> Result<EntityId> {
        self.park_run_proposal_with_predicate_for_test(
            run_id,
            agent,
            subject,
            "profile.name",
            value,
        )
    }

    /// [`Vault::park_run_proposal_for_test`] with the proposal's `predicate`.
    ///
    /// # Errors
    /// Any write failure, or the live policy not parking the proposal.
    pub fn park_run_proposal_with_predicate_for_test(
        &self,
        run_id: &str,
        agent: EntityId,
        subject: EntityId,
        predicate: &str,
        value: impl Into<Value>,
    ) -> Result<EntityId> {
        let at = TimeRange { start: 1, end: 1 };
        for (id, body) in [(agent, b"run agent".as_slice()), (subject, b"run subject")] {
            if self.get(&id)?.is_none() {
                self.put_entity(&id, ENTITY_TYPE_PERSON, at, 1, body)?;
            }
        }
        let evidence = encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
            refs: vec![subject],
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        });
        let candidate =
            ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value.into(), 1.0)
                .with_evidence(evidence);
        let envelope = WriteEnvelope::new(
            WriteActor::new(agent, EdgeActorClass::Agent),
            ClaimSource::Generated,
            WriteProvenance::new(Value::Map(vec![
                (
                    Value::from(DREAMER_PROVENANCE_RUNNER_KEY),
                    Value::from(crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND),
                ),
                (
                    Value::from(DREAMER_PROVENANCE_RUN_ID_KEY),
                    Value::from(run_id),
                ),
            ]))?,
            ClaimApprovalStatus::Proposed,
        );
        let claim_id = EntityId::now();
        self.batch()
            .claim_candidate(&claim_id, candidate, &envelope, at, 3)
            .commit()?;
        let parked = self
            .pending_gate_consents(10_000)?
            .iter()
            .any(|pending| pending.claim_id == *claim_id.as_bytes());
        if parked {
            Ok(claim_id)
        } else {
            Err(Error::InvalidConfig(
                "the live policy did not park this run proposal for consent".into(),
            ))
        }
    }
}
