//! Curator grading data and minimum-force proposals; never applies or deletes.
use super::super::{DreamerAdmittedAttempt, DreamerRunnerStore, EnqueueDreamerAttemptOutcome};
use super::{CURATOR_FACET, invalid, load_row, proposals};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimDemotionRung, claim_demotion_rung};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EntityId, Result, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};

/// Owner-set rubric dial for the memory-curator maintenance pass.
const RUBRIC: SideTable<(), CuratorRubric, LegacyJson> =
    SideTable::new(&side_table::DREAMER_CURATOR_RUBRIC);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CuratorTrigger {
    Nightly,
    Idle,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CuratorRubric {
    pub minimum_age_secs: u64,
    pub edge_weight_factor: f32,
    pub confidence_factor: f32,
    pub cadence_secs: u64,
}
impl CuratorRubric {
    fn validate(&self) -> Result<()> {
        if self.cadence_secs == 0
            || ![self.edge_weight_factor, self.confidence_factor]
                .iter()
                .all(|x| x.is_finite() && (0.0..1.0).contains(x))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl Vault {
    pub fn set_curator_rubric(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        rubric: &CuratorRubric,
    ) -> Result<()> {
        rubric.validate()?;
        self.with_write_txn(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            RUBRIC.put(&self.store, txn, &(), rubric)?;
            Ok(())
        })
    }
    pub fn schedule_curator(
        &self,
        _trigger: CuratorTrigger,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let rubric: CuratorRubric = load_row(self, RUBRIC, include_str!("curator_defaults.json"))?;
        rubric.validate()?;
        DreamerRunnerStore::new(self).enqueue_maintenance(
            CURATOR_FACET,
            Value::Nil,
            format!("curator:{}", now / rubric.cadence_secs),
            now,
        )
    }
}
fn owned_consolidation(body: &crate::ClaimBody, actor: EntityId) -> bool {
    let Some(Value::Map(evidence)) = &body.evidence else {
        return false;
    };
    let actors: Vec<_> = evidence
        .iter()
        .filter(|(key, _)| key.as_str() == Some("actor_entity_ref"))
        .collect();
    let provenance: Vec<_> = evidence
        .iter()
        .filter(|(key, _)| key.as_str() == Some("provenance"))
        .collect();
    if actors.len() != 1
        || provenance.len() != 1
        || actors[0].1 != Value::Binary(actor.as_bytes().to_vec())
    {
        return false;
    }
    let Value::Map(provenance) = &provenance[0].1 else {
        return false;
    };
    provenance
        .iter()
        .filter(|(key, _)| key.as_str() == Some("surface"))
        .count()
        == 1
        && provenance.iter().any(|(key, value)| {
            key.as_str() == Some("surface")
                && matches!(value.as_str(), Some("dreamer" | "dreamer.runner"))
        })
}
pub(super) fn run(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<Vec<EntityId>> {
    let rubric: CuratorRubric = load_row(vault, RUBRIC, include_str!("curator_defaults.json"))?;
    rubric.validate()?;
    let actor = vault.dreamer_authority()?.entity_ref();
    let txn = vault.store.env.read_txn()?;
    let mut candidates = Vec::new();
    for row in vault.store.entities.iter(&txn)? {
        let (id, bytes) = row?;
        let Some(header) = EntityMetadataHeader::parse(&bytes) else {
            return Err(invalid());
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || bytes.len() == ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let body = crate::claim::decode_claim_body(&bytes[ENTITY_METADATA_HEADER_LEN..], true)?;
        if body.source != Some(ClaimSource::Generated)
            || body.lifecycle != ClaimLifecycleStatus::Active
            || !matches!(
                body.approval,
                ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
            )
            || now.saturating_sub(header.learned_at) < rubric.minimum_age_secs
            || !owned_consolidation(&body, actor)
        {
            continue;
        }
        let id_bytes: &[u8] = &id;
        let id = EntityId::from_bytes(id_bytes.try_into().map_err(|_| invalid())?)?;
        let action = match claim_demotion_rung(&body)? {
            None => {
                serde_json::json!({"kind":"claim_of_weight","factor":rubric.edge_weight_factor})
            }
            Some(ClaimDemotionRung::Decayed) => {
                serde_json::json!({"kind":"confidence","new_confidence":body.confidence*rubric.confidence_factor})
            }
            Some(ClaimDemotionRung::Weakened) => serde_json::json!({"kind":"stale"}),
            Some(ClaimDemotionRung::Stale) => serde_json::json!({"kind":"retract"}),
        };
        candidates.push((id,serde_json::json!({"target":id.to_hex(),"source_hash":blake3::hash(&bytes[ENTITY_METADATA_HEADER_LEN..]).to_hex().to_string(),"action":action,"rubric":rubric})));
    }
    drop(txn);
    candidates
        .into_iter()
        .map(|(id, value)| {
            proposals::emit(
                vault,
                attempt.status.attempt.id,
                CURATOR_FACET,
                id,
                "dreamer.curator.proposal",
                &value,
                now,
            )
        })
        .collect()
}
