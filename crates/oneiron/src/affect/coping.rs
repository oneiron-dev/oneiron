//! Coping outcomes: which strategy a person used and how their affect moved.
//! Entry: `CopingOutcomeValue`, the typed `coping.outcome` claim body.
//! Definitions are local to this module; affect types come from the parent.

use crate::ports::EntityStoreRead;

use super::{Vad, VadDelta};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimLifecycleStatus, ClaimSource, claim_consolidatable, encode_claim_body};
use crate::edge::EdgeKind;
use crate::error::ClaimError;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::vault::{CLAIM_OF_DEFAULT_WEIGHT, SUPERSEDES_DEFAULT_WEIGHT};

use crate::write_envelope::coping_outcome::coping_outcome_evidence_value;
pub(crate) use crate::write_envelope::coping_outcome::validate_coping_outcome_claim_structure;
pub use crate::write_envelope::coping_outcome::{
    COPING_OUTCOME_PREDICATE, CopingOutcomeRecord, CopingOutcomeUpdate, CopingOutcomeValue,
    CopingStrategy, coping_delta_successful, coping_outcome_claim_candidate, coping_outcome_value,
    decode_coping_outcome_claim, decode_coping_outcome_value,
};

impl Vault {
    /// Updates an active `coping.outcome` claim from two turn-level VAD
    /// annotations. The baseline turn supplies the before state; the later
    /// turn supplies the after state.
    pub fn update_coping_outcome_from_turn_vad(
        &self,
        prior_claim_id: &EntityId,
        baseline_turn_id: &EntityId,
        later_turn_id: &EntityId,
        confidence: f32,
        now: u64,
    ) -> Result<CopingOutcomeUpdate> {
        self.with_write_txn_grouped(|txn| {
            self.update_coping_outcome_from_turn_vad_in_txn(
                txn,
                prior_claim_id,
                baseline_turn_id,
                later_turn_id,
                confidence,
                now,
                None,
            )
        })
    }

    /// The same update inside the caller's write, including both annotation reads.
    pub(crate) fn update_coping_outcome_from_turn_vad_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        prior_claim_id: &EntityId,
        baseline_turn_id: &EntityId,
        later_turn_id: &EntityId,
        confidence: f32,
        now: u64,
        envelope: Option<&crate::WriteEnvelope>,
    ) -> Result<CopingOutcomeUpdate> {
        let (delta, _, _) =
            self.coping_turn_observation_in_txn(txn, baseline_turn_id, later_turn_id, now)?;
        self.update_coping_outcome_from_turn_vad_delta_in_txn(
            txn,
            prior_claim_id,
            *later_turn_id,
            delta,
            confidence,
            now,
            Some(*baseline_turn_id),
            envelope,
        )
    }

    /// Shared measurement for the first observation and later aggregate updates.
    pub(crate) fn coping_turn_observation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        baseline_turn_id: &EntityId,
        later_turn_id: &EntityId,
        now: u64,
    ) -> Result<(VadDelta, super::VadAnnotation, super::VadAnnotation)> {
        let baseline = self
            .turn_vad_annotation_in_txn(txn, baseline_turn_id)?
            .ok_or(Error::InvalidClaimBody(
                "baseline turn VAD annotation missing",
            ))?;
        let later = self
            .turn_vad_annotation_in_txn(txn, later_turn_id)?
            .ok_or(Error::InvalidClaimBody("later turn VAD annotation missing"))?;
        if baseline_turn_id == later_turn_id
            || baseline.annotated_at > later.annotated_at
            || later.annotated_at > now
        {
            return Err(Error::InvalidClaimBody(
                "coping observation needs ordered, non-future turns",
            ));
        }
        let delta = VadDelta::new(
            later.vad.valence - baseline.vad.valence,
            later.vad.arousal - baseline.vad.arousal,
            later.vad.dominance - baseline.vad.dominance,
        )?;
        Ok((delta, baseline, later))
    }

    /// Supersedes an active `coping.outcome` claim with an updated aggregate
    /// derived from a later turn-level VAD delta.
    pub fn update_coping_outcome_from_turn_vad_delta(
        &self,
        prior_claim_id: &EntityId,
        turn_id: EntityId,
        vad_delta: VadDelta,
        confidence: f32,
        now: u64,
    ) -> Result<CopingOutcomeUpdate> {
        self.update_coping_outcome_from_turn_vad_delta_checked(
            prior_claim_id,
            turn_id,
            vad_delta,
            confidence,
            now,
            None,
        )
    }

    fn update_coping_outcome_from_turn_vad_delta_checked(
        &self,
        prior_claim_id: &EntityId,
        turn_id: EntityId,
        vad_delta: VadDelta,
        confidence: f32,
        now: u64,
        expected_strategy_ref: Option<EntityId>,
    ) -> Result<CopingOutcomeUpdate> {
        self.with_write_txn_grouped(|txn| {
            self.update_coping_outcome_from_turn_vad_delta_in_txn(
                txn,
                prior_claim_id,
                turn_id,
                vad_delta,
                confidence,
                now,
                expected_strategy_ref,
                None,
            )
        })
    }

    fn update_coping_outcome_from_turn_vad_delta_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        prior_claim_id: &EntityId,
        turn_id: EntityId,
        vad_delta: VadDelta,
        confidence: f32,
        now: u64,
        expected_strategy_ref: Option<EntityId>,
        envelope: Option<&crate::WriteEnvelope>,
    ) -> Result<CopingOutcomeUpdate> {
        let raw = self
            .store
            .port_entity_record(wtxn, prior_claim_id)?
            .map(|row| row.encode())
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        let prior_body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if prior_body.predicate != COPING_OUTCOME_PREDICATE {
            return Err(Error::InvalidClaimBody("claim is not a coping.outcome"));
        }
        if prior_body.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::Claim(ClaimError::ClaimAlreadyClosed {
                status: prior_body.lifecycle,
            }));
        }
        if !claim_consolidatable(&prior_body)
            || !crate::gate::claim_consolidation_eligible_in_txn(
                &self.store,
                wtxn,
                prior_claim_id,
                crate::gate::ConsolidationReader::CopingOutcome,
            )?
        {
            return Err(Error::InvalidClaimBody("claim is not consolidatable"));
        }
        let prior_value = decode_coping_outcome_claim(&prior_body)?
            .ok_or(Error::InvalidClaimBody("claim is not a coping.outcome"))?;
        if let Some(expected_strategy_ref) = expected_strategy_ref
            && prior_value.strategy_ref() != expected_strategy_ref
        {
            return Err(Error::InvalidClaimBody(
                "baseline turn must match coping.outcome strategyRef",
            ));
        }
        let prior_valid_from = prior_body.valid_from.ok_or(Error::InvalidClaimBody(
            "coping.outcome valid_from is required",
        ))?;
        if now < prior_valid_from || now < header.occurred_start {
            return Err(Error::InvalidClaimBody(
                "coping.outcome update timestamp must not precede active valid_from",
            ));
        }
        let updated_value = prior_value.with_observation(vad_delta, confidence)?;
        let ClaimSubject::Entity(subject) = prior_body.subject else {
            return Err(Error::InvalidClaimBody(
                "coping.outcome subject must be an entity",
            ));
        };

        let new_claim_id = self.store.clock.entity_id()?;
        let mut closed = prior_body.clone();
        closed.lifecycle = ClaimLifecycleStatus::Superseded;
        closed.valid_to = Some(now);
        let closed_data = encode_claim_body(&closed)?;

        let mut updated_body = ClaimBody::new(
            COPING_OUTCOME_PREDICATE,
            prior_body.subject,
            coping_outcome_value(&updated_value),
            updated_value.confidence(),
            prior_body.approval,
            ClaimLifecycleStatus::Active,
        )?;
        updated_body.salience = prior_body.salience;
        updated_body.evidence = Some(coping_outcome_evidence_value(
            turn_id,
            vad_delta,
            confidence,
            expected_strategy_ref,
        ));
        if let Some(envelope) = envelope {
            updated_body.evidence = Some(crate::write_envelope::write_envelope_evidence(
                envelope,
                updated_body.evidence,
            ));
        }
        updated_body.source = Some(ClaimSource::Inferred);
        updated_body.valid_from = Some(now);
        updated_body.world = prior_body.world;
        updated_body.scope = prior_body.scope;
        updated_body.rel = prior_body.rel;
        updated_body.scope_facet = prior_body.scope_facet;
        updated_body.scope_project = prior_body.scope_project;
        let updated_data = encode_claim_body(&updated_body)?;

        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![
                BatchOp::Put {
                    id: *prior_claim_id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: header.occurred_start,
                        end: now,
                    },
                    learned_at: header.learned_at,
                    row_version: None,
                    data: closed_data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
                BatchOp::Put {
                    id: new_claim_id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: now,
                        end: u64::MAX,
                    },
                    learned_at: now,
                    row_version: None,
                    data: updated_data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
                BatchOp::Edge {
                    src: new_claim_id,
                    kind: EdgeKind::ClaimOf,
                    tgt: subject,
                    weight: CLAIM_OF_DEFAULT_WEIGHT,
                    vad: Vad::NEUTRAL,
                },
                BatchOp::EdgeWithCreatedAt {
                    src: new_claim_id,
                    kind: EdgeKind::Supersedes,
                    tgt: *prior_claim_id,
                    weight: SUPERSEDES_DEFAULT_WEIGHT,
                    created_at: now,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(CopingOutcomeUpdate {
            prior_claim_id: *prior_claim_id,
            active_claim_id: new_claim_id,
            superseded_claim_ids: vec![*prior_claim_id],
            value: updated_value,
        })
    }
}
