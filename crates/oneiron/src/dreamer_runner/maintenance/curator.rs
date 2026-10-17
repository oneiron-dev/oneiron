//! Curator grading data and minimum-force proposals. The curator applies only
//! what the owner approved in the run tray, one rung at a time, and never
//! deletes: its last rung is a retraction, which keeps history.
use super::super::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use super::{CURATOR_FACET, MAINTENANCE_QUEUE_KIND, invalid, load_row, proposals};
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimDemotionAction, ClaimDemotionRung, claim_demotion_rung};
use crate::edge::EdgeKind;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId, Error, Result,
    Vault,
};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The curator's finding predicate.
const PROPOSAL_PREDICATE: &str = "dreamer.curator.proposal";

/// Owner-set rubric dial for the memory-curator maintenance pass.
const RUBRIC: SideTable<(), CuratorRubric, LegacyJson> =
    SideTable::new(&side_table::DREAMER_CURATOR_RUBRIC);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CuratorTrigger {
    Nightly,
    Idle,
}
impl CuratorTrigger {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Nightly => "nightly",
            Self::Idle => "idle",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CuratorRubric {
    pub minimum_age_secs: u64,
    pub edge_weight_factor: f32,
    pub confidence_factor: f32,
    pub cadence_secs: u64,
    /// Agent-authored questions stored as policy data, not Rust prompt text.
    pub questions: CuratorQuestions,
}
/// The three questions the curator must answer from stored, verifiable facts.
/// Hosts may edit the wording through the owner-set rubric.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CuratorQuestions {
    pub authorship: String,
    pub freshness: String,
    pub least_force: String,
}
impl CuratorRubric {
    fn validate(&self) -> Result<()> {
        if self.cadence_secs == 0
            || [
                &self.questions.authorship,
                &self.questions.freshness,
                &self.questions.least_force,
            ]
            .iter()
            .any(|question| question.trim().is_empty())
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
        self.with_write_txn_grouped(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            RUBRIC.put(self, txn, &(), rubric)?;
            Ok(())
        })
    }
    /// One curator pass per rubric cadence, whichever trigger asks first.
    pub fn schedule_curator(
        &self,
        trigger: CuratorTrigger,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let store = DreamerRunnerStore::new(self);
        self.with_write_txn_grouped(|txn| {
            store.enqueue_curator_in_txn(txn, trigger, None, None, now)
        })
    }
}
impl DreamerRunnerStore<'_> {
    /// [`Vault::schedule_curator`] in a caller-owned write: the nightly wake
    /// registers the pass in the commit that takes its input.
    pub(super) fn enqueue_curator_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        trigger: CuratorTrigger,
        parent_attempt: Option<AttemptId>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let vault = self.vault();
        let rubric = match RUBRIC.get(&vault.store, &*txn, &())? {
            Some(rubric) => rubric,
            None => serde_json::from_str::<CuratorRubric>(include_str!("curator_defaults.json"))
                .map_err(|_| invalid())?,
        };
        rubric.validate()?;
        self.enqueue_kind_in_txn(
            txn,
            MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: CURATOR_FACET.into(),
                input: Value::from(trigger.as_str()),
                parent_attempt,
            },
            Some(format!("curator:{}", now / rubric.cadence_secs)),
            run_id,
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
    let mut approved = Vec::new();
    for row in EntityStoreRead::port_entity_raw_records(&vault.store, &txn)? {
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
        if body.predicate == PROPOSAL_PREDICATE {
            if body.source == Some(ClaimSource::Generated)
                && body.lifecycle == ClaimLifecycleStatus::Active
                && body.approval == ClaimApprovalStatus::Approved
                && crate::claim::session_claim_producer(&body) == Some(actor)
                && let Some(value) = body.value.as_str()
                && let Ok(value) = serde_json::from_str::<serde_json::Value>(value)
            {
                approved.push((id, value));
            }
            continue;
        }
        if body.source != Some(ClaimSource::Generated)
            || body.lifecycle != ClaimLifecycleStatus::Active
            || !matches!(
                body.approval,
                ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
            )
            || now.saturating_sub(header.learned_at) < rubric.minimum_age_secs
            || !owned_consolidation(&body, actor)
            || !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, &txn, &id)?
        {
            continue;
        }
        let prior_rung = claim_demotion_rung(&body)?;
        let action = match prior_rung {
            None => {
                serde_json::json!({"kind":"claim_of_weight","factor":rubric.edge_weight_factor})
            }
            Some(ClaimDemotionRung::Decayed) => {
                serde_json::json!({"kind":"confidence","new_confidence":body.confidence*rubric.confidence_factor})
            }
            Some(ClaimDemotionRung::Weakened) => serde_json::json!({"kind":"stale"}),
            Some(ClaimDemotionRung::Stale) => serde_json::json!({"kind":"retract"}),
        };
        let proposed_action = action["kind"].clone();
        candidates.push((id,serde_json::json!({"target":id.to_hex(),"source_hash":blake3::hash(&bytes[ENTITY_METADATA_HEADER_LEN..]).to_hex().to_string(),"action":action,"rubric":rubric,"grade":{
            "authorship":"verified_dreamer_generated",
            "freshness":{"learned_at":header.learned_at,"minimum_age_secs":rubric.minimum_age_secs},
            "least_force":{"prior_rung":prior_rung.map(|r| match r {
                ClaimDemotionRung::Decayed => "decayed",
                ClaimDemotionRung::Weakened => "weakened",
                ClaimDemotionRung::Stale => "stale",
            }),"proposed_action":proposed_action}
        }})));
    }
    drop(txn);
    // Settle before proposing: a target moved by an approval this pass waits
    // for the next pass to be graded on its new rung.
    let mut moved = BTreeSet::new();
    for (proposal, value) in approved {
        match apply_approved(vault, &value, now) {
            Ok(Some(target)) => {
                moved.insert(target);
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(
                proposal = %proposal.to_hex(),
                %error,
                "curator: an approved proposal did not apply"
            ),
        }
    }
    candidates
        .into_iter()
        .filter(|(id, _)| !moved.contains(id))
        .map(|(id, value)| {
            proposals::emit(
                vault,
                attempt.status.attempt.id,
                CURATOR_FACET,
                id,
                PROPOSAL_PREDICATE,
                &value,
                &[id],
                now,
            )
        })
        .collect()
}

/// Applies one owner-approved finding through the demotion ladder's own door.
/// The finding names its target's body hash at grading. A target whose body
/// moved since (this finding already applied, or any other write) is left
/// alone, so a replayed pass applies nothing twice. Returns the moved target.
fn apply_approved(vault: &Vault, value: &serde_json::Value, now: u64) -> Result<Option<EntityId>> {
    let target = EntityId::from_hex(value["target"].as_str().ok_or_else(invalid)?)?;
    let source_hash = value["source_hash"].as_str().ok_or_else(invalid)?;
    let action = &value["action"];
    let factor = |key: &str| -> Result<f32> {
        let x = action[key].as_f64().ok_or_else(invalid)?;
        #[allow(clippy::cast_possible_truncation, reason = "the rubric wrote an f32")]
        Ok(x as f32)
    };
    let current_weight = {
        let txn = vault.store.env.read_txn()?;
        let Some(raw) = EntityStoreRead::port_entity_raw(&vault.store, &txn, &target)? else {
            return Ok(None);
        };
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() == ENTITY_METADATA_HEADER_LEN
            || blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..])
                .to_hex()
                .as_str()
                != source_hash
        {
            return Ok(None);
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if body.lifecycle != ClaimLifecycleStatus::Active {
            return Ok(None);
        }
        match body.subject {
            ClaimSubject::Entity(subject) if action["kind"] == "claim_of_weight" => {
                let mut weight = None;
                for edge in vault.port_edges(
                    &txn,
                    &target,
                    EdgeDirection::Out,
                    Some(EdgeKind::ClaimOf),
                    None,
                )? {
                    let edge = edge?;
                    if edge.target == subject {
                        weight = Some(edge.weight);
                    }
                }
                weight
            }
            _ => None,
        }
    };
    let demotion = match action["kind"].as_str().ok_or_else(invalid)? {
        "claim_of_weight" => ClaimDemotionAction::Decay {
            new_claim_of_weight: current_weight.ok_or_else(invalid)? * factor("factor")?,
        },
        "confidence" => ClaimDemotionAction::Weaken {
            new_confidence: factor("new_confidence")?,
        },
        "stale" => ClaimDemotionAction::MarkStale,
        "retract" => {
            vault.retract_claim(&target, now)?;
            return Ok(Some(target));
        }
        _ => return Err(invalid()),
    };
    match vault.apply_claim_demotion(&target, demotion, now) {
        Ok(_) => Ok(Some(target)),
        // A critical predicate parks the demotion behind the owner's Gate
        // consent; the parked action is the applied state until it resolves.
        Err(Error::Gate(crate::error::GateError::GateWriteRejected {
            outcome: "pending", ..
        })) => Ok(Some(target)),
        Err(error) => Err(error),
    }
}
