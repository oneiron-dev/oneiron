//! Curator grading data and minimum-force findings. The curator applies one
//! rung at a time and never deletes: its last rung is a retraction, which
//! keeps history. Each rung applies as the Dreamer when its finding lands
//! (OF-023, owner ruling 10-18: "autoapply + revert rather than holdout"),
//! with the target's before-state as the inverse the owner reverts. A rung
//! on a critical target waits for the owner in the run tray (ARCH-0026: a
//! critical replacement waits), and applies once approved.
use super::super::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use super::applied::{MaintenanceInverse, MaintenanceRevert, claim_revision_in_txn};
use super::{CURATOR_FACET, MAINTENANCE_QUEUE_KIND, invalid, load_row, proposals};
use crate::attempt_queue::AttemptId;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::transition::{ClaimTransitionKind, TransitionDelta};
use crate::claim::{
    CLAIM_SCOPE_DEMOTION_RUNG_KEY, ClaimDemotionAction, ClaimDemotionRung, claim_demotion_rung,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::write_envelope::{WriteEnvelope, WriteProvenance};
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Error, Result, TimeRange, Vault, WriteActor,
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
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
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
        let critical = policy.criticality_for_predicate(&body.predicate)
            == crate::gate::PolicyCriticality::Critical;
        candidates.push((id,critical,serde_json::json!({"target":id.to_hex(),"source_hash":blake3::hash(&bytes[ENTITY_METADATA_HEADER_LEN..]).to_hex().to_string(),"action":action,"rubric":rubric,"grade":{
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
    let mut findings = Vec::new();
    for (id, critical, value) in candidates {
        if moved.contains(&id) {
            continue;
        }
        if critical {
            findings.push(proposals::emit(
                vault,
                attempt.status.attempt.id,
                CURATOR_FACET,
                id,
                PROPOSAL_PREDICATE,
                &value,
                &[id],
                now,
            )?);
            continue;
        }
        let finding = proposals::Finding {
            subject: id,
            predicate: PROPOSAL_PREDICATE,
            value: &value,
            evidence: &[id],
        };
        let landed = proposals::land(vault, CURATOR_FACET, attempt.status.attempt.id, |landing| {
            vault.with_write_txn_grouped(|txn| {
                landing.land_in_txn(vault, txn, &finding, now, |txn| {
                    apply_in_txn(vault, txn, &value, now)
                })
            })
        });
        match landed {
            Ok(finding) => findings.push(finding),
            Err(error) => tracing::warn!(
                claim = %id.to_hex(),
                %error,
                "curator: a rung did not apply"
            ),
        }
    }
    Ok(findings)
}

/// The rung one applied finding took.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Rung {
    Decay,
    Weaken,
    Stale,
    Retract,
}

/// One applied rung's inverse: the target as it stood before (its body
/// revision, confidence, stale mark, window end and ClaimOf weight), and the
/// claim carrying the rung after, the target itself or a weakening's
/// successor, at its revision then.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CuratorInverse {
    target: EntityId,
    rung: Rung,
    prior_revision: [u8; 32],
    prior_confidence: f32,
    prior_stale: bool,
    prior_valid_to: Option<u64>,
    prior_claim_of_weight: Option<f32>,
    after: EntityId,
    after_revision: [u8; 32],
}

/// The target's ClaimOf weight on its own subject, if it has one.
fn claim_of_weight_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: &EntityId,
    body: &crate::ClaimBody,
) -> Result<Option<f32>> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Ok(None);
    };
    let mut weight = None;
    for edge in vault.port_edges(
        txn,
        target,
        EdgeDirection::Out,
        Some(EdgeKind::ClaimOf),
        None,
    )? {
        let edge = edge?;
        if edge.target == subject {
            weight = Some(edge.weight);
        }
    }
    Ok(weight)
}

/// Applies one finding's rung as the Dreamer, in the finding's own write.
/// The target must still be the body the finding graded, and active.
/// Returns the target's before-state as the inverse.
fn apply_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    value: &serde_json::Value,
    now: u64,
) -> Result<MaintenanceInverse> {
    let changed = || Error::ConcurrentWrite("curator target changed before its rung applied");
    let target = EntityId::from_hex(value["target"].as_str().ok_or_else(invalid)?)?;
    let source_hash = value["source_hash"].as_str().ok_or_else(invalid)?;
    let action = &value["action"];
    let factor = |key: &str| -> Result<f32> {
        let x = action[key].as_f64().ok_or_else(invalid)?;
        #[allow(clippy::cast_possible_truncation, reason = "the rubric wrote an f32")]
        Ok(x as f32)
    };
    let raw =
        EntityStoreRead::port_entity_raw(&vault.store, &*txn, &target)?.ok_or_else(changed)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
        || raw.len() == ENTITY_METADATA_HEADER_LEN
    {
        return Err(invalid());
    }
    let hash = blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]);
    if hash.to_hex().as_str() != source_hash {
        return Err(changed());
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(changed());
    }
    let weight = claim_of_weight_in_txn(vault, &*txn, &target, &body)?;
    let dreamer = vault.dreamer_authority_in_txn(txn, now)?;
    let (rung, after) = match action["kind"].as_str().ok_or_else(invalid)? {
        "claim_of_weight" => {
            let new_claim_of_weight = weight.ok_or_else(invalid)? * factor("factor")?;
            let decay = ClaimDemotionAction::Decay {
                new_claim_of_weight,
            };
            demote_in_place_in_txn(vault, txn, target, decay, dreamer, now)?;
            (Rung::Decay, target)
        }
        "confidence" => {
            let weaken = ClaimDemotionAction::Weaken {
                new_confidence: factor("new_confidence")?,
            };
            let successor = vault.apply_claim_demotion_in_txn(txn, &target, weaken, now)?;
            (Rung::Weaken, successor.claim)
        }
        "stale" => {
            let stale = ClaimDemotionAction::MarkStale;
            demote_in_place_in_txn(vault, txn, target, stale, dreamer, now)?;
            (Rung::Stale, target)
        }
        "retract" => {
            vault.retract_claim_in_txn_as(txn, &target, now, Some(dreamer))?;
            (Rung::Retract, target)
        }
        _ => return Err(invalid()),
    };
    Ok(MaintenanceInverse::Curator(CuratorInverse {
        target,
        rung,
        prior_revision: *hash.as_bytes(),
        prior_confidence: body.confidence,
        prior_stale: body.stale,
        prior_valid_to: body.valid_to,
        prior_claim_of_weight: weight,
        after,
        after_revision: claim_revision_in_txn(vault, &*txn, &after)?.ok_or_else(invalid)?,
    }))
}

/// One in-place rung, the decay or the stale mark, as the Dreamer: a
/// MACHINE-born claim's signed history records the Dreamer's own transition,
/// never the owner's; any other claim takes the ladder's in-txn door, which
/// stages no transition.
fn demote_in_place_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    target: EntityId,
    action: ClaimDemotionAction,
    dreamer: WriteActor,
    now: u64,
) -> Result<()> {
    let raw = EntityStoreRead::port_entity_raw(&vault.store, &*txn, &target)?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if !crate::authority::machine_claim_needs_history(&vault.store, txn, &body)? {
        vault.apply_claim_demotion_in_txn(txn, &target, action, now)?;
        return Ok(());
    }
    let (kind, delta, edge) = match action {
        ClaimDemotionAction::Decay {
            new_claim_of_weight,
        } => {
            crate::edge::validate_edge_weight(new_claim_of_weight)?;
            let ClaimSubject::Entity(subject) = body.subject else {
                return Err(Error::InvalidClaimBody("decay requires entity subject"));
            };
            (
                ClaimTransitionKind::Decay,
                TransitionDelta::ClaimOfWeight(new_claim_of_weight),
                Some((subject, new_claim_of_weight)),
            )
        }
        ClaimDemotionAction::MarkStale => (ClaimTransitionKind::Stale, TransitionDelta::None, None),
        ClaimDemotionAction::Weaken { .. } => return Err(invalid()),
    };
    let next = crate::claim::transition::stage_machine_transition_as(
        vault, txn, target, kind, delta, dreamer, now,
    )?;
    let mut ops = vec![BatchOp::Put {
        id: target,
        entity_type: crate::registry::ENTITY_TYPE_CLAIM,
        occurred: TimeRange {
            start: header.occurred_start,
            end: now,
        },
        learned_at: header.learned_at,
        data: crate::claim::encode_claim_body(&next)?,
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    }];
    if let Some((subject, weight)) = edge {
        ops.push(BatchOp::SetEdgeWeight {
            src: target,
            kind: EdgeKind::ClaimOf,
            tgt: subject,
            weight,
        });
    }
    crate::batch::ClaimMaterialization::apply_demotion(vault, txn, ops)
}

/// The owner's revert of one applied rung. The claim carrying the rung must
/// still be at the revision it took; a claim a later write changed is left
/// as it is and listed. A decay or stale mark retracts the target and a
/// weakening its successor, as `owner`; then the target stands again at its
/// prior confidence and rung: in place when the weakening closed a claim
/// with no signed history, else as the Dreamer's fresh copy born of it, a
/// prior stale mark signed again on the copy. The copy carries the default
/// ClaimOf weight and no evidence, so the curator never grades it again.
pub(super) fn revert_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    inverse: &CuratorInverse,
    owner: WriteActor,
    now: u64,
    out: &mut MaintenanceRevert,
) -> Result<()> {
    if claim_revision_in_txn(vault, &*txn, &inverse.after)? != Some(inverse.after_revision) {
        out.left_alone.push(inverse.after.to_hex());
        return Ok(());
    }
    match inverse.rung {
        Rung::Decay | Rung::Stale => {
            vault.retract_claim_in_txn_as(txn, &inverse.target, now, Some(owner))?;
            out.closed.push(inverse.target);
        }
        Rung::Weaken => {
            vault.retract_claim_in_txn_as(txn, &inverse.after, now, Some(owner))?;
            out.closed.push(inverse.after);
            if vault.restore_superseded_claim_in_txn(txn, &inverse.after, &inverse.target, now)? {
                out.restored.push(inverse.target);
                return Ok(());
            }
        }
        Rung::Retract => {}
    }
    let copy = stand_copy_in_txn(vault, txn, inverse, out.finding, now)?;
    out.copied.push((inverse.target, copy));
    Ok(())
}

/// Stands the target again as the Dreamer's fresh copy at its prior
/// confidence, window end and rung, born of the target and the reverted
/// finding.
fn stand_copy_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    inverse: &CuratorInverse,
    finding: EntityId,
    now: u64,
) -> Result<EntityId> {
    let mut body = vault
        .get_claim_in_txn(&*txn, &inverse.target)?
        .ok_or(Error::EntityNotFound)?;
    // The rung the target carried before; a stale one is born weakened and
    // marked stale again, since a birth never carries the stale rung.
    let (stamp, stale) = match inverse.rung {
        Rung::Decay => (None, false),
        Rung::Weaken => (Some("decayed"), false),
        Rung::Stale => (Some("weakened"), false),
        Rung::Retract => (Some("weakened"), true),
    };
    let mut scope = match body.scope.take() {
        Some(Value::Map(entries)) => entries,
        _ => Vec::new(),
    };
    scope.retain(|(key, _)| key.as_str() != Some(CLAIM_SCOPE_DEMOTION_RUNG_KEY));
    if let Some(stamp) = stamp {
        scope.push((
            Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
            Value::from(stamp),
        ));
    }
    body.scope = (!scope.is_empty()).then_some(Value::Map(scope));
    let candidate = crate::dreamer_consolidation::on_axes_of(
        ClaimCandidate::new(
            body.predicate.clone(),
            body.subject,
            body.value.clone(),
            inverse.prior_confidence,
        )
        .with_validity(body.valid_from, inverse.prior_valid_to),
        &body,
    );
    let dreamer = WriteActor::new(
        crate::dreamer_runner::authority::dreamer_actor_id()?,
        EdgeActorClass::System,
    );
    let mut envelope = WriteEnvelope::new(
        dreamer,
        body.source.unwrap_or(ClaimSource::Generated),
        WriteProvenance::new(Value::Map(vec![
            (
                Value::from("surface"),
                Value::from(super::MAINTENANCE_REVERT_KIND),
            ),
            (
                Value::from("restores"),
                Value::Binary(inverse.target.as_bytes().to_vec()),
            ),
            (
                Value::from("revertedFinding"),
                Value::Binary(finding.as_bytes().to_vec()),
            ),
        ]))?,
        ClaimApprovalStatus::Auto,
    );
    let copy = EntityId::now();
    let birth = RowBirth::written(
        envelope.actor(),
        MadeByClass::Concluded,
        "dreamer.maintenance_revert",
        &[inverse.target, finding],
        &[],
        now,
    );
    vault.sign_retained_machine_claim_in_txn(&*txn, &copy, &candidate, &mut envelope)?;
    vault
        .batch_in()
        .claim_candidate(
            &copy,
            candidate,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .made_by(&copy, birth)
        .apply(txn)?;
    if stale {
        demote_in_place_in_txn(
            vault,
            txn,
            copy,
            ClaimDemotionAction::MarkStale,
            dreamer,
            now,
        )?;
    }
    Ok(copy)
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
