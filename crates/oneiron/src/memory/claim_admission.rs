//! Explicit claim positions on the public door; the ordinary candidate writer still owns the write.
use super::{
    ClaimInput, CommitOutcome, CommitReceipt, Memory, MemoryError, MemoryResult, RecordRefusal,
};
use crate::claim::ClaimApprovalStatus;
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::{EntityId, Error};
use serde::{Deserialize, Serialize};

/// The explicit relationship position. The claim codec currently admits one relationship per row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ClaimRelationships {
    All(AllRelationships),
    Relationships(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AllRelationships {
    All,
}

/// A claim's position, never a credential ceiling. No axis is inferred when one is absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimScope {
    pub world_id: String,
    pub scope_facet_id: String,
    pub scope_relationship_id: ClaimRelationships,
    pub scope_project_id: String,
}

/// Public claim admission. Provenance is host-authored; made_by is not an input field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopedClaimInput {
    pub id: Option<String>,
    pub predicate: String,
    pub subject_ref: String,
    pub value: serde_json::Value,
    pub confidence: f32,
    pub source: String,
    pub scope: ClaimScope,
    /// Optional sensitivity band, in 0..=3, independent of the four position axes.
    pub sensitivity: Option<u8>,
    #[serde(default)]
    pub evidence_turn_refs: Vec<String>,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
    pub occurred_at: Option<u64>,
    pub learned_at: Option<u64>,
    pub salience: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopedCommitRequest {
    pub claims: Vec<ScopedClaimInput>,
}

impl ClaimScope {
    pub(super) fn of_body(body: &crate::claim::ClaimBody) -> Self {
        Self {
            world_id: body
                .world
                .unwrap_or_else(crate::claim::base_world_id)
                .to_hex(),
            scope_facet_id: body.scope_facet.to_hex(),
            scope_relationship_id: body
                .rel
                .map_or(ClaimRelationships::All(AllRelationships::All), |id| {
                    ClaimRelationships::Relationships(vec![id.to_hex()])
                }),
            scope_project_id: body.scope_project.to_hex(),
        }
    }
}

impl Memory<'_> {
    /// Upserts through the existing candidate writer with this credential's explicit placement.
    pub fn claim_upsert_scoped(&self, input: &ScopedClaimInput) -> MemoryResult<CommitReceipt> {
        self.commit_scoped_one(input, false)
    }

    /// Per-element admission and receipts, as on the ordinary commit door.
    pub fn commit_scoped(
        &self,
        claims: &[ScopedClaimInput],
        proposed: bool,
    ) -> MemoryResult<Vec<CommitOutcome>> {
        super::caps::check_batch_len("claims", claims.len())?;
        let row = if proposed {
            "vault.claims.seed"
        } else {
            "vault.commit"
        };
        Ok(claims
            .iter()
            .enumerate()
            .map(
                |(index, input)| match self.commit_scoped_one(input, proposed) {
                    Ok(receipt) => CommitOutcome::Landed(receipt),
                    Err(error) => {
                        let refusal = RecordRefusal::from_error(&error, format!("/claims/{index}"));
                        let receipt_ref = refusal.receipt(self, row);
                        CommitOutcome::Refused {
                            refusal,
                            receipt_ref,
                        }
                    }
                },
            )
            .collect())
    }

    fn commit_scoped_one(
        &self,
        input: &ScopedClaimInput,
        proposed: bool,
    ) -> MemoryResult<CommitReceipt> {
        self.commit_scoped_one_guarded(input, proposed, !proposed, &|_| Ok(()))
    }

    /// A family-owned first record uses the same scoped admission without closing peers.
    pub(super) fn claim_record_scoped_guarded(
        &self,
        input: &ScopedClaimInput,
        guard: &dyn Fn(&heed::RoTxn<'_>) -> crate::Result<()>,
    ) -> MemoryResult<CommitReceipt> {
        self.commit_scoped_one_guarded(input, false, false, guard)
    }

    fn commit_scoped_one_guarded(
        &self,
        input: &ScopedClaimInput,
        proposed: bool,
        replace: bool,
        guard: &dyn Fn(&heed::RoTxn<'_>) -> crate::Result<()>,
    ) -> MemoryResult<CommitReceipt> {
        let world = self.resolve_ref(&input.scope.world_id)?;
        let facet = self.resolve_ref(&input.scope.scope_facet_id)?;
        let project = self.resolve_ref(&input.scope.scope_project_id)?;
        let relationship = match &input.scope.scope_relationship_id {
            ClaimRelationships::All(AllRelationships::All) => None,
            ClaimRelationships::Relationships(ids) if ids.len() == 1 => {
                Some(self.resolve_ref(&ids[0])?)
            }
            ClaimRelationships::Relationships(_) => {
                return Err(MemoryError::bad_request(
                    "a claim relationship position is all or exactly one relationship",
                ));
            }
        };
        if input.sensitivity.is_some_and(|band| band > 3) {
            return Err(MemoryError::bad_request("sensitivity must be in 0..=3"));
        }
        let mut annotations = serde_json::Map::from_iter([
            ("facet".into(), serde_json::Value::String(facet.to_hex())),
            (
                "scopeProjectId".into(),
                serde_json::Value::String(project.to_hex()),
            ),
        ]);
        if let Some(band) = input.sensitivity {
            annotations.insert("sensitivity".into(), band.into());
        }
        let claim = ClaimInput {
            id: input.id.clone(),
            predicate: input.predicate.clone(),
            subject_ref: input.subject_ref.clone(),
            value: input.value.clone(),
            confidence: input.confidence,
            source: input.source.clone(),
            world_ref: (world != crate::claim::base_world_id()).then(|| world.to_hex()),
            relationship_ref: relationship.map(|id| id.to_hex()),
            scope: Some(serde_json::Value::Object(annotations)),
            valid_from: input.valid_from,
            valid_to: input.valid_to,
            occurred_at: input.occurred_at,
            learned_at: input.learned_at,
            salience: input.salience,
            confidence_details: None,
        };
        super::caps::check_claim_input(&claim)?;
        let lane = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let evidence = lane
            .read(
                &input
                    .evidence_turn_refs
                    .iter()
                    .map(|reference| self.resolve_ref(reference).map(crate::claim::PointRead::id))
                    .collect::<MemoryResult<Vec<_>>>()?,
                None,
            )?
            .value;
        let mut inputs = Vec::new();
        let mut bytes = Vec::new();
        for row in evidence {
            let row = row
                .filter(|row| row.entity_type == crate::registry::ENTITY_TYPE_TURN)
                .ok_or_else(|| MemoryError::bad_request("evidence must name a readable TURN"))?;
            inputs.push(row.id);
            bytes.push(
                row.body
                    .ok_or_else(|| MemoryError::bad_request("evidence has no body"))?,
            );
        }
        let at = self.vault.store.clock.now_recorded_at();
        let read: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
        let birth = RowBirth::written(
            crate::write_envelope::WriteActor::new(self.actor, self.actor_class),
            MadeByClass::of_source(self.claim_source(&input.source)?),
            "vault.claims.upsert",
            &inputs,
            &read,
            at,
        )
        .ok_or_else(|| {
            MemoryError::bad_request("a concluded claim must name its evidence turns")
        })?;
        self.commit_one_guarded_with_birth(
            &claim,
            replace,
            proposed.then_some(ClaimApprovalStatus::Proposed),
            || {},
            &|txn| {
                guard(txn)?;
                self.admit_claim_position(txn, world, facet, project, input.sensitivity)?;
                if self.vault.get_entity_type_in_txn(txn, &facet)?
                    != Some(crate::registry::ENTITY_TYPE_FACET)
                {
                    return Err(Error::InvalidClaimBody("scope facet must name a FACET"));
                }
                if lane
                    .entities_readable_in_txn(txn, &inputs)?
                    .iter()
                    .any(|readable| !readable)
                {
                    return Err(Error::InvalidClaimBody(
                        "claim evidence is no longer readable",
                    ));
                }
                Ok(())
            },
            Some(&birth),
        )
    }

    fn admit_claim_position(
        &self,
        txn: &heed::RoTxn<'_>,
        world: EntityId,
        facet: EntityId,
        project: EntityId,
        sensitivity: Option<u8>,
    ) -> crate::Result<()> {
        let refused = || {
            Error::Claim(crate::error::ClaimError::ActorLacksClaimAuthority {
                reason: "the caller credential does not admit this claim position",
            })
        };
        if self
            .birth_position
            .world
            .is_some_and(|bound| bound != world)
            || self
                .birth_position
                .facet
                .is_some_and(|bound| bound != facet)
        {
            return Err(refused());
        }
        let Some(proof) = self.read_proof.as_ref() else {
            return if self.transport_invocation {
                Err(refused())
            } else {
                Ok(())
            };
        };
        if proof.claims().holder_ref != self.actor.to_hex()
            || !proof.claims().records.is_empty()
            || !proof.claims().channels.is_empty()
            || !self.vault.capability_slip_is_live_in_txn(txn, proof)?
        {
            return Err(refused());
        }
        let verb = ["core:write", "write", "core:propose"]
            .into_iter()
            .find(|verb| proof.allows_verb(verb))
            .ok_or_else(refused)?;
        let mut position = Scope::top();
        position.worlds = ScopeAxis::from_iter([ScopeId(world)]);
        position.facets = ScopeAxis::from_iter([ScopeId(facet)]);
        position.audience = ScopeAxis::from_iter([ScopeId(project)]);
        position.bands = ScopeAxis::from_iter([crate::registry::ENTITY_TYPE_CLAIM]);
        position.verbs = ScopeAxis::from_iter([verb.to_owned()]);
        position.sensitivity = crate::federation::SensitivityCeiling::AtMost(
            match sensitivity.unwrap_or(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND) {
                0 => crate::federation::Sensitivity::Public,
                1 => crate::federation::Sensitivity::Private,
                2 => crate::federation::Sensitivity::Sensitive,
                _ => crate::federation::Sensitivity::Restricted,
            },
        );
        if !position.is_narrowing_of(proof.scope()) {
            return Err(refused());
        }
        Ok(())
    }
}
