//! Typed coping observations and per-person aggregates over the engine's coping ledger.
use serde::{Deserialize, Serialize};

use super::{ClaimScope, Memory, MemoryError, MemoryResult, ScopedClaimInput};
use crate::affect::coping::{
    COPING_OUTCOME_PREDICATE, CopingOutcomeValue, CopingStrategy, coping_outcome_value,
    decode_coping_outcome_claim,
};
use crate::claim::{ClaimBody, ClaimReadStatus, ClaimSubject, claim_consolidatable};
use crate::consent::AuthenticatedOwner;
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::{EntityId, Error, WriteActor};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CopingOutcomeRecordRequest {
    pub affected_person_ref: String,
    /// The turn in which the strategy was offered: the canonical strategyRef.
    pub baseline_turn_ref: String,
    pub later_turn_ref: String,
    pub strategy: CopingStrategy,
    pub confidence: f32,
    pub scope: ClaimScope,
    pub sensitivity: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CopingOutcomeUpdateRequest {
    pub prior_claim_ref: String,
    pub baseline_turn_ref: String,
    pub later_turn_ref: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CopingAggregateRequest {
    pub affected_person_ref: String,
    pub scope: Option<ClaimScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CopingVadDelta {
    pub valence: f32,
    pub arousal: f32,
    pub dominance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CopingOutcomeView {
    pub claim_ref: String,
    pub affected_person_ref: String,
    pub strategy_ref: String,
    pub strategy: CopingStrategy,
    pub vad_delta: CopingVadDelta,
    pub confidence: f32,
    pub successful: bool,
    pub observed_n: u64,
    pub scope: ClaimScope,
    pub approval: String,
    pub source: Option<String>,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
    pub evidence_refs: Vec<String>,
    pub made_by: Option<crate::provenance::made_by::MadeBy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CopingOutcomeReceipt {
    pub outcome: CopingOutcomeView,
    pub superseded_claim_refs: Vec<String>,
    pub receipt_ref: String,
}

/// Every admitted active strategy aggregate, including unsuccessful observations.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CopingAggregate {
    pub affected_person_ref: String,
    pub outcomes: Vec<CopingOutcomeView>,
    pub observed_n: u64,
}

impl Memory<'_> {
    pub fn coping_outcome_record_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &CopingOutcomeRecordRequest,
    ) -> MemoryResult<CopingOutcomeReceipt> {
        let person = self.resolve_ref(&input.affected_person_ref)?;
        let baseline = self.resolve_ref(&input.baseline_turn_ref)?;
        let later = self.resolve_ref(&input.later_turn_ref)?;
        let now = self.vault.store.clock.now_recorded_at();
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let snapshot = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            self.coping_observation_guard(&txn, owner, &lane, person, baseline, later)?;
            self.vault
                .coping_turn_observation_in_txn(&txn, &baseline, &later, now)?
        };
        let value = CopingOutcomeValue::new(
            person,
            baseline,
            input.strategy,
            snapshot.0,
            input.confidence,
            1,
        )?;
        let receipt = self.claim_record_scoped_guarded(
            &ScopedClaimInput {
                id: None,
                predicate: COPING_OUTCOME_PREDICATE.to_owned(),
                subject_ref: person.to_hex(),
                value: crate::serialize::msgpack_value_to_json(&coping_outcome_value(&value)),
                confidence: input.confidence,
                source: "observed".to_owned(),
                scope: input.scope.clone(),
                sensitivity: input.sensitivity,
                evidence_turn_refs: vec![baseline.to_hex(), later.to_hex()],
                valid_from: Some(now),
                valid_to: None,
                occurred_at: Some(now),
                learned_at: Some(now),
                salience: None,
            },
            &|txn| {
                self.coping_observation_guard(txn, owner, &lane, person, baseline, later)?;
                if self
                    .vault
                    .coping_turn_observation_in_txn(txn, &baseline, &later, now)?
                    != snapshot
                {
                    return Err(Error::InvalidClaimBody(
                        "VAD evidence changed; record the observation again",
                    ));
                }
                Ok(())
            },
        )?;
        let claim = self.resolve_ref(&receipt.claim_short_id)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let body = self
            .vault
            .get_claim_in_txn(&txn, &claim)?
            .ok_or(Error::EntityNotFound)?;
        Ok(CopingOutcomeReceipt {
            outcome: self.coping_outcome_view_in_txn(&txn, claim, &body)?,
            superseded_claim_refs: Vec::new(),
            receipt_ref: receipt.receipt_ref,
        })
    }

    pub fn coping_outcome_update_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &CopingOutcomeUpdateRequest,
    ) -> MemoryResult<CopingOutcomeReceipt> {
        let prior = self.resolve_ref(&input.prior_claim_ref)?;
        let baseline = self.resolve_ref(&input.baseline_turn_ref)?;
        let later = self.resolve_ref(&input.later_turn_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let now = self.vault.store.clock.now_recorded_at();
        self.with_verified_actor_write_txn(|txn| {
            require_readable(&lane, txn, &[prior])?;
            let body = self
                .vault
                .get_claim_in_txn(txn, &prior)?
                .ok_or(Error::EntityNotFound)?;
            let prior_value = decode_coping_outcome_claim(&body)?
                .ok_or_else(|| MemoryError::bad_request("prior claim must be coping.outcome"))?;
            self.coping_observation_guard(
                txn,
                owner,
                &lane,
                prior_value.affected_person(),
                baseline,
                later,
            )?;
            let inputs = [prior, baseline, later];
            let bytes = inputs
                .iter()
                .map(|id| self.vault.get_raw_in(txn, id)?.ok_or(Error::EntityNotFound))
                .collect::<crate::Result<Vec<_>>>()?;
            let read = bytes.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let birth = RowBirth::written(
                WriteActor::new(self.actor, self.actor_class),
                MadeByClass::Concluded,
                "vault.affect.coping.update",
                &inputs,
                &read,
                now,
            )
            .ok_or_else(|| MemoryError::bad_request("coping updates require evidence"))?;
            let envelope = self.claim_envelope(
                crate::claim::ClaimSource::Inferred,
                "vault.affect.coping.update",
                body.approval,
            )?;
            let result = self.vault.update_coping_outcome_from_turn_vad_in_txn(
                txn,
                &prior,
                &baseline,
                &later,
                input.confidence,
                now,
                Some(&envelope),
            )?;
            crate::provenance::birth::stamp_birth_if_absent_in_txn(
                &self.vault.store,
                txn,
                &result.active_claim_id,
                &birth,
            )?;
            let active = self
                .vault
                .get_claim_in_txn(txn, &result.active_claim_id)?
                .ok_or(Error::EntityNotFound)?;
            let decision = super::authorship::decision(
                WriteActor::new(self.actor, self.actor_class),
                "coping_outcome",
                "approved",
                "gate.affect.coping.turn_vad",
                Some(result.active_claim_id),
                blake3::hash(&crate::claim::encode_claim_body(&active)?)
                    .as_bytes()
                    .to_vec(),
                now,
            );
            self.vault
                .store
                .append_gate_decision_in_txn(txn, &decision)?;
            Ok(CopingOutcomeReceipt {
                outcome: self.coping_outcome_view_in_txn(txn, result.active_claim_id, &active)?,
                superseded_claim_refs: result
                    .superseded_claim_ids
                    .iter()
                    .map(EntityId::to_hex)
                    .collect(),
                receipt_ref: format!("gate:{}", decision.decision_id.to_hex()),
            })
        })
    }

    pub fn coping_aggregate_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &CopingAggregateRequest,
    ) -> MemoryResult<CopingAggregate> {
        let person = self.resolve_ref(&input.affected_person_ref)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.affect_owner_in_txn(&txn, owner)?;
        self.coping_aggregate_in_txn(&txn, person, input.scope.as_ref())
    }

    pub(super) fn affect_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
    ) -> crate::Result<()> {
        if owner.revalidate_in_txn(self.vault, txn)? != self.actor {
            return Err(Error::InvalidClaimBody(
                "affect owner proof must name the caller",
            ));
        }
        Ok(())
    }

    fn coping_observation_guard(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
        lane: &crate::claim::ScopedRead<'_>,
        person: EntityId,
        baseline: EntityId,
        later: EntityId,
    ) -> crate::Result<()> {
        self.affect_owner_in_txn(txn, owner)?;
        require_readable(lane, txn, &[person, baseline, later])?;
        if self.vault.get_entity_type_in_txn(txn, &person)? != Some(ENTITY_TYPE_PERSON)
            || !crate::affect::state_inputs::spoke_in(self.vault, txn, &person, &baseline)?
            || !crate::affect::state_inputs::spoke_in(self.vault, txn, &person, &later)?
        {
            return Err(Error::InvalidClaimBody(
                "coping evidence must belong to the affected PERSON",
            ));
        }
        for turn in [baseline, later] {
            let annotation = crate::affect::vad_annotation_claim_id(ENTITY_TYPE_TURN, &turn)?;
            if self
                .vault
                .get_entity_type_in_txn(txn, &annotation)?
                .is_some()
            {
                require_readable(lane, txn, &[annotation])?;
                self.produced_from([annotation]);
            }
        }
        self.produced_from([person, baseline, later]);
        Ok(())
    }

    pub(super) fn coping_aggregate_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
        scope: Option<&ClaimScope>,
    ) -> MemoryResult<CopingAggregate> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        require_readable(&lane, txn, &[person])?;
        if self.vault.get_entity_type_in_txn(txn, &person)? != Some(ENTITY_TYPE_PERSON) {
            return Err(MemoryError::bad_request(
                "coping aggregate requires a PERSON",
            ));
        }
        let mut outcomes = Vec::new();
        let mut observed_n = 0_u64;
        for id in self.vault.claims_for_subject_in_txn(txn, &person)? {
            let Some((_, _, bytes)) = lane.get_entities_parts_in_txn(txn, &[id])?.pop().flatten()
            else {
                continue;
            };
            let body = crate::claim::decode_claim_body(&bytes, true)?;
            if body.predicate != COPING_OUTCOME_PREDICATE
                || !claim_consolidatable(&body)
                || body.subject != ClaimSubject::Entity(person)
                || scope.is_some_and(|scope| *scope != ClaimScope::of_body(&body))
                || !crate::gate::claim_consolidation_eligible_in_txn(
                    &self.vault.store,
                    txn,
                    &id,
                    crate::gate::ConsolidationReader::CopingOutcome,
                )?
            {
                continue;
            }
            let outcome = self.coping_outcome_view_in_txn(txn, id, &body)?;
            observed_n = observed_n
                .checked_add(outcome.observed_n)
                .ok_or_else(|| MemoryError::bad_request("coping observation count overflow"))?;
            outcomes.push(outcome);
        }
        outcomes.sort_by(|a, b| a.claim_ref.cmp(&b.claim_ref));
        self.produced_from([person]);
        Ok(CopingAggregate {
            affected_person_ref: person.to_hex(),
            outcomes,
            observed_n,
        })
    }

    fn coping_outcome_view_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        body: &ClaimBody,
    ) -> MemoryResult<CopingOutcomeView> {
        let value = decode_coping_outcome_claim(body)?
            .ok_or_else(|| MemoryError::bad_request("claim must be coping.outcome"))?;
        let birth = crate::provenance::birth::row_birth_in_txn(&self.vault.store, txn, &id)?;
        let mut evidence = birth
            .as_ref()
            .map(|birth| {
                birth
                    .made_by
                    .inputs
                    .iter()
                    .map(|input| input.row)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if let Some(value) = &body.evidence {
            collect_refs(value, &mut evidence);
        }
        evidence.push(value.strategy_ref());
        evidence.sort();
        evidence.dedup();
        let producers = std::iter::once(id)
            .chain(evidence.iter().copied())
            .collect::<Vec<_>>();
        require_readable(&self.read_lane(ClaimReadStatus::Recorded)?, txn, &producers)?;
        self.produced_from(producers);
        let delta = value.vad_delta();
        Ok(CopingOutcomeView {
            claim_ref: id.to_hex(),
            affected_person_ref: value.affected_person().to_hex(),
            strategy_ref: value.strategy_ref().to_hex(),
            strategy: value.strategy(),
            vad_delta: CopingVadDelta {
                valence: delta.valence(),
                arousal: delta.arousal(),
                dominance: delta.dominance(),
            },
            confidence: value.confidence(),
            successful: value.successful(),
            observed_n: value.observed_n(),
            scope: ClaimScope::of_body(body),
            approval: body.approval.as_str().to_owned(),
            source: body.source.map(|source| source.as_str().to_owned()),
            valid_from: body.valid_from,
            valid_to: body.valid_to,
            evidence_refs: evidence.iter().map(EntityId::to_hex).collect(),
            made_by: birth.map(|birth| birth.made_by),
        })
    }
}

pub(super) fn require_readable(
    lane: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    ids: &[EntityId],
) -> crate::Result<()> {
    if lane
        .entities_readable_in_txn(txn, ids)?
        .iter()
        .any(|readable| !readable)
    {
        return Err(Error::EntityNotFound);
    }
    Ok(())
}

pub(super) fn collect_refs(value: &rmpv::Value, refs: &mut Vec<EntityId>) {
    match value {
        rmpv::Value::String(text) => {
            if let Some(text) = text.as_str() {
                if let Ok(id) = EntityId::from_hex(text) {
                    refs.push(id);
                }
            }
        }
        rmpv::Value::Binary(bytes) if bytes.len() == 16 => {
            if let Ok(bytes) = bytes.as_slice().try_into() {
                if let Ok(id) = EntityId::from_bytes(bytes) {
                    refs.push(id);
                }
            }
        }
        rmpv::Value::Array(items) => {
            for item in items {
                collect_refs(item, refs);
            }
        }
        rmpv::Value::Map(entries) => {
            for (_, value) in entries {
                collect_refs(value, refs);
            }
        }
        _ => {}
    }
}
