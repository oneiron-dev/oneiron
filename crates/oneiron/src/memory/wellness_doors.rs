//! Per-person wellness projections reuse the measured state index and configured action modes.
use serde::{Deserialize, Serialize};

use super::coping_doors::{collect_refs, require_readable};
use super::{Memory, MemoryError, MemoryResult};
use crate::affect::state_index::StateIndex;
use crate::claim::ClaimReadStatus;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::maintenance::action_mode::{ActionModePolicy, ActionModeRule};
use crate::{EntityId, Error, WriteActor};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WellnessPolicyConfigureRequest {
    /// None clears the policy. No built-in bands or population cutoffs are substituted.
    pub policy: Option<ActionModePolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WellnessPersonRequest {
    pub affected_person_ref: String,
}

/// Non-clinical measurements and advisory mode, never a diagnosis or a truth revision.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WellnessProjection {
    pub affected_person_ref: String,
    pub policy: Option<ActionModePolicy>,
    pub state_index: StateIndex,
    pub mode: Option<ActionModeRule>,
    pub coping: super::coping_doors::CopingAggregate,
    pub source_refs: Vec<String>,
    pub receipt_ref: Option<String>,
}

impl Memory<'_> {
    pub fn wellness_policy_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> MemoryResult<Option<ActionModePolicy>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.affect_owner_in_txn(&txn, owner)?;
        drop(txn);
        Ok(self.vault.action_mode_policy()?)
    }

    pub fn wellness_policy_configure_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &WellnessPolicyConfigureRequest,
    ) -> MemoryResult<Option<ActionModePolicy>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.affect_owner_in_txn(&txn, owner)?;
        drop(txn);
        Ok(self
            .vault
            .set_action_mode_policy(owner, input.policy.clone())?)
    }

    pub fn wellness_derive_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &WellnessPersonRequest,
    ) -> MemoryResult<WellnessProjection> {
        self.wellness_projection_as_owner(owner, input, true)
    }

    pub fn wellness_get_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &WellnessPersonRequest,
    ) -> MemoryResult<WellnessProjection> {
        self.wellness_projection_as_owner(owner, input, false)
    }

    fn wellness_projection_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &WellnessPersonRequest,
        refresh: bool,
    ) -> MemoryResult<WellnessProjection> {
        let person = self.resolve_ref(&input.affected_person_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let now = self.vault.store.clock.now_recorded_at();
        self.with_verified_actor_write_txn(|txn| {
            self.affect_owner_in_txn(txn, owner)?;
            require_readable(&lane, txn, &[person])?;
            if self.vault.get_entity_type_in_txn(txn, &person)?
                != Some(crate::registry::ENTITY_TYPE_PERSON)
            {
                return Err(MemoryError::bad_request(
                    "wellness projection requires a PERSON",
                ));
            }
            let measured = self
                .vault
                .project_action_mode_in_txn(txn, &person, now, refresh)?;
            let coping = self.coping_aggregate_in_txn(txn, person, None)?;
            let mut refs = vec![person];
            if let Some(claim) = &measured.state_index.claim {
                let claim = EntityId::from_hex(claim)?;
                refs.push(claim);
                let body = self
                    .vault
                    .get_claim_in_txn(txn, &claim)?
                    .ok_or(Error::EntityNotFound)?;
                let mut inputs = Vec::new();
                if let Some(evidence) = &body.evidence {
                    collect_refs(evidence, &mut inputs);
                }
                for id in &inputs {
                    if self.vault.get_entity_type_in_txn(txn, id)?
                        != Some(crate::registry::ENTITY_TYPE_CLAIM)
                    {
                        continue;
                    }
                    if let Some(body) = self.vault.get_claim_in_txn(txn, id)? {
                        if let Some(evidence) = &body.evidence {
                            collect_refs(evidence, &mut refs);
                        }
                    }
                }
                refs.extend(inputs);
            }
            for outcome in &coping.outcomes {
                refs.push(EntityId::from_hex(&outcome.claim_ref)?);
                for reference in &outcome.evidence_refs {
                    refs.push(EntityId::from_hex(reference)?);
                }
            }
            // Annotation claims are separate evidence, not the factual claims the person stated.
            for turn in refs.clone() {
                if self.vault.get_entity_type_in_txn(txn, &turn)?
                    == Some(crate::registry::ENTITY_TYPE_TURN)
                {
                    let annotation = crate::affect::vad_annotation_claim_id(
                        crate::registry::ENTITY_TYPE_TURN,
                        &turn,
                    )?;
                    if self
                        .vault
                        .get_entity_type_in_txn(txn, &annotation)?
                        .is_some()
                    {
                        refs.push(annotation);
                    }
                }
            }
            refs.sort();
            refs.dedup();
            require_readable(&lane, txn, &refs)?;
            self.produced_from(refs.iter().copied());
            let mut projection = WellnessProjection {
                affected_person_ref: person.to_hex(),
                policy: measured.policy,
                state_index: measured.state_index,
                mode: measured.mode,
                coping,
                source_refs: refs.iter().map(EntityId::to_hex).collect(),
                receipt_ref: None,
            };
            if refresh {
                let bytes = serde_json::to_vec(&projection)
                    .map_err(|_| MemoryError::bad_request("invalid wellness projection"))?;
                let target = projection
                    .state_index
                    .claim
                    .as_deref()
                    .map(EntityId::from_hex)
                    .transpose()?;
                let decision = super::authorship::decision(
                    WriteActor::new(self.actor, self.actor_class),
                    "wellness_projection",
                    "approved",
                    "gate.affect.wellness.configured_policy",
                    target,
                    bytes,
                    now,
                );
                projection.receipt_ref = Some(format!("gate:{}", decision.decision_id.to_hex()));
                self.vault
                    .store
                    .append_gate_decision_in_txn(txn, &decision)?;
            }
            Ok(projection)
        })
    }
}
