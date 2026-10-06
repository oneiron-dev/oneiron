//! Session-branch claim edits: typed usefulness, owner-held reserve, and atomic admission.
//! A branch proposal is inert source in vault_meta, never an ordinary live CLAIM.

use super::refinement_admission::{
    RefinementAdmissionProof, RefinementControl, RefinementState, RefinementTarget, put_control,
    read_control,
};
use super::refinement_custody::RefinementReceipt;
use super::{package_codec::invalid, shared_gate::checked_useful_decision};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    Vault,
    batch::{BatchOp, ClaimMaterialization, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, decode_claim_body,
        encode_claim_body,
    },
    consent::{
        AuthenticatedOwner, ComposedEffect, ConsentReceipt, EffectDigest, EffectFacts, UndoFidelity,
    },
    edge::EdgeActorClass,
    entity_id::EntityId,
    error::{Error, Result},
    llm::decision::{AnswerContract, DecisionClass, DecisionQuestion, TypedDecision},
    skill_optimize::held_out_receipt_set_digest,
    store::Store,
    temporal::TimeRange,
    write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance},
};
use serde::{Deserialize, Serialize};

/// Owner-adjudicated held-out claim labels (sorted, unique hex ids) reserved
/// for one claim base.
const RESERVE: SideTable<EntityId, Vec<String>, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_CLAIM_REFINEMENT_RESERVE);

/// The edit stays under its session tag until independently admitted. IDs in
/// this row are canonical hex, not an alternate authority for the claim body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalClaimRefinement {
    pub candidate: String,
    pub base: String,
    pub resident: String,
    pub session_tag: String,
    pub body: Vec<u8>,
    pub base_binding: String,
    pub occurred_start: u64,
    pub occurred_end: u64,
    pub learned_at: u64,
}
impl LocalClaimRefinement {
    pub fn claim_body(&self) -> Result<ClaimBody> {
        decode_claim_body(&self.body, false)
    }
}

/// The configured OF-493 answerer sees only the base and the branch proposal.
pub trait UsefulUpstreamClaimJudge {
    fn decide(
        &self,
        question: &DecisionQuestion,
        resident: EntityId,
        base: &ClaimBody,
        candidate: &ClaimBody,
    ) -> Result<TypedDecision>;
}

/// Owner-reserved labels; the scorer runs outside transactions and has no pen.
pub struct HeldOutClaimReplayCase<'a> {
    pub base: EntityId,
    pub candidate: EntityId,
    pub claim: &'a ClaimBody,
    pub held_out_receipts: &'a [String],
}
pub trait HeldOutClaimReplayScorer {
    fn score(&self, case: &HeldOutClaimReplayCase<'_>) -> Result<f32>;
}

#[derive(Debug, Clone)]
pub struct ClaimRefinementMergeAsk {
    candidate: EntityId,
    resident: EntityId,
    question: DecisionQuestion,
    binding: String,
    effect: EffectDigest,
}
impl ClaimRefinementMergeAsk {
    #[must_use]
    pub const fn effect_digest(&self) -> EffectDigest {
        self.effect
    }
    #[must_use]
    pub const fn candidate(&self) -> EntityId {
        self.candidate
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRefinementMergeReceipt {
    pub receipt_id: String,
    pub candidate: String,
    pub base: String,
    pub resident: String,
    pub session_tag: String,
    pub question: DecisionQuestion,
    pub decision: TypedDecision,
    pub consent_digest: String,
    pub binding: String,
    pub held_out_digest: String,
    pub useful_upstream: bool,
    pub before: Option<f32>,
    pub after: Option<f32>,
    pub accepted: bool,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq)]
pub enum ClaimRefinementMergeDisposition {
    PendingConsent,
    Ruled(Box<ClaimRefinementMergeReceipt>),
}
struct Snapshot {
    delta: LocalClaimRefinement,
    base_id: EntityId,
    base: ClaimBody,
    candidate: ClaimBody,
    evidence: Vec<String>,
    binding: String,
}

/// The control row survives as an identifier-only erased fence. The native
/// Proposed CLAIM owns all branch payload bytes; ASSET custody owns rulings.
pub(crate) fn claim_refinement_scope_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(
        super::refinement_admission::refinement_control_scope_exists(store, txn, id)?
            || RESERVE.contains(store, txn, id)?,
    )
}
pub(crate) fn erase_claim_refinement_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let had_control = super::refinement_admission::retire_refinement_control(store, txn, id)?;
    let had_reserve = RESERVE.delete(store, txn, id)?;
    Ok(had_control || had_reserve)
}

impl Vault {
    /// Reserve existing, owner-adjudicated claims as a hidden held-out split.
    /// This input is never supplied by the branch author or the merge callback.
    pub fn reserve_claim_refinement_holdout(
        &self,
        owner: &AuthenticatedOwner,
        base: EntityId,
        labels: &[EntityId],
    ) -> Result<()> {
        if labels.is_empty() || labels.len() > 4096 {
            return Err(invalid(
                "claim held-out reserve must be bounded and nonempty",
            ));
        }
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let original = self
                .get_claim_in_txn(txn, &base)?
                .ok_or(Error::EntityNotFound)?;
            if original.lifecycle != ClaimLifecycleStatus::Active {
                return Err(invalid("held-out claim base is not active"));
            }
            let mut unique = std::collections::BTreeSet::new();
            for label in labels {
                let body = self
                    .get_claim_in_txn(txn, label)?
                    .ok_or(Error::EntityNotFound)?;
                if !unique.insert(label.to_hex())
                    || *label == base
                    || body.subject != original.subject
                    || body.approval != ClaimApprovalStatus::Approved
                    || body.lifecycle != ClaimLifecycleStatus::Active
                    || body.source != Some(ClaimSource::UserStated)
                {
                    return Err(invalid(
                        "held-out label is not an independent owner-adjudicated claim",
                    ));
                }
            }
            // The set's sorted order is the stored JSON array order.
            RESERVE.put(
                &self.store,
                txn,
                &base,
                &unique.into_iter().collect::<Vec<_>>(),
            )?;
            Ok(())
        })
    }

    /// A local self.refine claim edit remains inert on this session branch;
    /// this door never creates or approves a CLAIM entity in the vault.
    pub fn submit_local_claim_refinement(
        &self,
        base: EntityId,
        resident: EntityId,
        session_tag: &str,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        if session_tag.is_empty()
            || session_tag.len() > 512
            || body.session_tag.as_deref() != Some(session_tag)
            || body.approval != ClaimApprovalStatus::Proposed
            || body.lifecycle != ClaimLifecycleStatus::Active
            || !matches!(
                body.source,
                Some(ClaimSource::Inferred | ClaimSource::Generated)
            )
        {
            return Err(invalid(
                "local refinement must be a proposed session-branch claim",
            ));
        }
        // The caller describes content; the engine stamps actor, source and
        // session through the ordinary candidate door, never by trusting the
        // body's proposed provenance as a persisted assertion.
        let source = body
            .source
            .ok_or_else(|| invalid("claim refinement source is missing"))?;
        let mut candidate = ClaimCandidate::new(
            &body.predicate,
            body.subject,
            body.value.clone(),
            body.confidence,
        )
        .with_validity(body.valid_from, body.valid_to)
        .with_stale(body.stale)
        .with_scope_stamps(body.scope_facet, body.scope_project);
        if let Some(salience) = body.salience {
            candidate = candidate.with_salience(salience);
        }
        if let Some(evidence) = &body.evidence {
            candidate = candidate.with_evidence(evidence.clone());
        }
        if let Some(world) = body.world {
            candidate = candidate.with_world(world);
        }
        if let Some(rel) = body.rel {
            candidate = candidate.with_relationship(rel);
        }
        if let Some(scope) = &body.scope {
            candidate = candidate.with_scope(scope.clone());
        }
        let envelope = WriteEnvelope::new(
            WriteActor::new(resident, EdgeActorClass::Agent),
            source,
            WriteProvenance::new(rmpv::Value::from("claim-refinement"))?,
            ClaimApprovalStatus::Proposed,
        )
        .with_session_tag(session_tag);
        crate::batch::secret_scan::scan_metadata_field(session_tag)?;
        let id = EntityId::now();
        self.with_write_txn(|txn| {
            require_resident(self, txn, resident)?;
            let original = self
                .get_claim_in_txn(txn, &base)?
                .ok_or(Error::EntityNotFound)?;
            if original.lifecycle != ClaimLifecycleStatus::Active
                || !same_claim_target(&original, body)
            {
                return Err(invalid("claim edit no longer revises its active base"));
            }
            self.batch_in()
                .claim_candidate(&id, candidate, &envelope, occurred, learned_at)
                .apply(txn)?;
            let stored = self
                .get_claim_in_txn(txn, &id)?
                .ok_or(Error::EntityNotFound)?;
            if stored.approval != ClaimApprovalStatus::Proposed
                || stored.session_tag.as_deref() != Some(session_tag)
                || !same_claim_target(&original, &stored)
                || crate::claim::session_claim_producer(&stored) != Some(resident)
            {
                return Err(invalid("stamped branch claim disagrees with its base"));
            }
            put_control(
                &self.store,
                txn,
                &id,
                &RefinementControl::claim(
                    base,
                    id,
                    resident,
                    claim_binding(&original)?,
                    claim_binding(&stored)?,
                ),
            )?;
            Ok(id)
        })
    }

    /// The branch row and its full proposed claim survive a refusal.
    pub fn local_claim_refinement(
        &self,
        candidate: EntityId,
    ) -> Result<Option<LocalClaimRefinement>> {
        let txn = self.store.env.read_txn()?;
        read_delta(self, &txn, candidate)
    }

    pub fn prepare_claim_refinement_merge(
        &self,
        candidate: EntityId,
        resident: EntityId,
        question: DecisionQuestion,
    ) -> Result<ClaimRefinementMergeAsk> {
        question.validate()?;
        crate::batch::secret_scan::scan_staged_payload(
            &self.store,
            &serde_json::to_vec(&question).map_err(|_| invalid("question encode failed"))?,
        )?;
        if question.id != candidate
            || question.class != DecisionClass::UsefulUpstream
            || !matches!(question.contract, AnswerContract::Noul)
            || question.accept_type
        {
            return Err(invalid(
                "claim merge needs a useful-upstream yes/no question",
            ));
        }
        let txn = self.store.env.read_txn()?;
        let snapshot = self.claim_refinement_snapshot(&txn, candidate)?;
        if snapshot.delta.resident != resident.to_hex() {
            return Err(invalid("claim merge resident moved"));
        }
        let effect = ComposedEffect::new(
            EffectFacts::new(format!(
                "claim.merge:{}:{}:{}",
                snapshot.binding,
                resident.to_hex(),
                blake3::hash(
                    &serde_json::to_vec(&question)
                        .map_err(|_| invalid("question encode failed"))?
                )
            ))?
            .with_undo_fidelity(UndoFidelity::None),
        )
        .digest();
        Ok(ClaimRefinementMergeAsk {
            candidate,
            resident,
            question,
            binding: snapshot.binding,
            effect,
        })
    }
    pub fn approve_claim_refinement_merge(
        &self,
        ask: &ClaimRefinementMergeAsk,
        owner: &AuthenticatedOwner,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn(|txn| {
            self.check_claim_refinement_ask(txn, ask)?;
            self.approve_once_in_txn(txn, owner, ask.effect)
        })
    }
    /// Typed usefulness is answered first; only a yes runs the independent
    /// host-held-out scorer. A no or tie consumes consent but never erases the branch.
    pub fn merge_local_claim_refinement(
        &self,
        ask: &ClaimRefinementMergeAsk,
        useful: &dyn UsefulUpstreamClaimJudge,
        scorer: &dyn HeldOutClaimReplayScorer,
        at: u64,
    ) -> Result<ClaimRefinementMergeDisposition> {
        let snapshot = {
            let txn = self.store.env.read_txn()?;
            let snapshot = self.check_claim_refinement_ask(&txn, ask)?;
            if crate::consent::approve_once_authorization_in_txn(&self.store, &txn, &ask.effect)?
                .is_none()
            {
                return Ok(ClaimRefinementMergeDisposition::PendingConsent);
            }
            snapshot
        };
        let decision = useful.decide(
            &ask.question,
            ask.resident,
            &snapshot.base,
            &snapshot.candidate,
        )?;
        let useful_upstream = checked_useful_decision(&ask.question, ask.resident, &decision)?;
        let (before, after) = if useful_upstream {
            let eval = |body: &ClaimBody| -> Result<f32> {
                let score = scorer.score(&HeldOutClaimReplayCase {
                    base: snapshot.base_id,
                    candidate: ask.candidate,
                    claim: body,
                    held_out_receipts: &snapshot.evidence,
                })?;
                if !score.is_finite() || !(0.0..=1.0).contains(&score) {
                    return Err(invalid("invalid held-out claim score"));
                }
                Ok(score)
            };
            (
                Some(eval(&snapshot.base)?),
                Some(eval(&snapshot.candidate)?),
            )
        } else {
            (None, None)
        };
        let accepted = matches!((before, after), (Some(a), Some(b)) if b > a);
        let receipt = ClaimRefinementMergeReceipt {
            receipt_id: EntityId::now().to_hex(),
            candidate: ask.candidate.to_hex(),
            base: snapshot.base_id.to_hex(),
            resident: ask.resident.to_hex(),
            session_tag: snapshot.delta.session_tag.clone(),
            question: ask.question.clone(),
            decision,
            consent_digest: ask.effect.to_hex(),
            binding: ask.binding.clone(),
            held_out_digest: held_out_receipt_set_digest(&snapshot.evidence),
            useful_upstream,
            before,
            after,
            accepted,
            at,
        };
        self.with_write_txn(|txn| {
            self.check_claim_refinement_ask(txn, ask)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &ask.effect)?
                    .ok_or_else(|| invalid("claim merge consent is missing"))?;
            if accepted {
                let mut admitted = snapshot.candidate.clone();
                admitted.approval = ClaimApprovalStatus::Approved;
                let data = encode_claim_body(&admitted)?;
                let proof = RefinementAdmissionProof::for_claim(
                    self,
                    txn,
                    &data,
                    &claim_binding(&snapshot.candidate)?,
                    &receipt,
                    &authorization,
                )?;
                ClaimMaterialization::apply_refinement_approval(
                    self,
                    txn,
                    BatchOp::Put {
                        id: ask.candidate,
                        entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                        occurred: TimeRange {
                            start: snapshot.delta.occurred_start,
                            end: snapshot.delta.occurred_end,
                        },
                        learned_at: snapshot.delta.learned_at,
                        data,
                        allow_maintenance: false,
                        allow_reserved_predicate: false,
                        hub_sync_imported: false,
                    },
                    proof,
                )?;
                self.supersede_claim_in_txn(txn, &ask.candidate, &snapshot.base_id, at)?;
            } else {
                crate::consent::spend_approve_once_in_txn(&self.store, txn, &authorization)?;
            }
            let mut control = read_control(&self.store, txn, &ask.candidate)?
                .ok_or_else(|| invalid("claim refinement control is missing"))?;
            control.state = if accepted {
                RefinementState::Admitted
            } else {
                RefinementState::Refused
            };
            put_control(&self.store, txn, &ask.candidate, &control)?;
            self.put_refinement_receipt_in_txn(
                txn,
                ask.candidate,
                RefinementReceipt::Claim(receipt.clone()),
                TimeRange { start: at, end: at },
                at,
            )?;
            Ok(ClaimRefinementMergeDisposition::Ruled(Box::new(receipt)))
        })
    }
    pub fn claim_refinement_merge_receipt(
        &self,
        candidate: EntityId,
    ) -> Result<Option<ClaimRefinementMergeReceipt>> {
        let txn = self.store.env.read_txn()?;
        match self.latest_refinement_receipt_in_txn(&txn, candidate)? {
            Some(RefinementReceipt::Claim(receipt)) => Ok(Some(receipt)),
            Some(RefinementReceipt::Skill(_)) => Err(invalid("wrong refinement receipt target")),
            None => Ok(None),
        }
    }
    fn check_claim_refinement_ask(
        &self,
        txn: &heed::RoTxn<'_>,
        ask: &ClaimRefinementMergeAsk,
    ) -> Result<Snapshot> {
        let snapshot = self.claim_refinement_snapshot(txn, ask.candidate)?;
        if snapshot.binding != ask.binding || snapshot.delta.resident != ask.resident.to_hex() {
            return Err(invalid("claim merge basis or resident moved"));
        }
        Ok(snapshot)
    }
    fn claim_refinement_snapshot(&self, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Snapshot> {
        let control = read_control(&self.store, txn, &id)?
            .ok_or_else(|| invalid("claim refinement control is missing"))?;
        if control.state != RefinementState::Pending
            || !matches!(control.target, RefinementTarget::Claim { .. })
            || self.latest_refinement_receipt_in_txn(txn, id)?.is_some()
        {
            return Err(invalid("claim refinement already ruled or erased"));
        }
        let delta =
            read_delta(self, txn, id)?.ok_or_else(|| invalid("claim branch edit is missing"))?;
        let base_id = EntityId::from_hex(&delta.base)?;
        let resident = EntityId::from_hex(&delta.resident)?;
        require_resident(self, txn, resident)?;
        let base = self
            .get_claim_in_txn(txn, &base_id)?
            .ok_or(Error::EntityNotFound)?;
        let candidate = delta.claim_body()?;
        if base.lifecycle != ClaimLifecycleStatus::Active
            || claim_binding(&base)? != delta.base_binding
            || !same_claim_target(&base, &candidate)
            || candidate.approval != ClaimApprovalStatus::Proposed
            || candidate.lifecycle != ClaimLifecycleStatus::Active
            || candidate.session_tag.as_deref() != Some(&delta.session_tag)
            || crate::claim::session_claim_producer(&candidate) != Some(resident)
            || claim_binding(&candidate)? != control.proposal_binding
        {
            return Err(invalid("claim branch edit no longer revises its base"));
        }
        let evidence = RESERVE
            .get(&self.store, txn, &base_id)?
            .ok_or_else(|| invalid("claim held-out reserve is missing"))?;
        if evidence.is_empty() || evidence.len() > 4096 {
            return Err(invalid("claim held-out reserve is invalid"));
        }
        let mut hash = blake3::Hasher::new_derive_key("oneiron.claim-refinement.merge.v1");
        for part in [
            id.as_bytes().to_vec(),
            serde_json::to_vec(&delta).map_err(|_| invalid("claim delta encode failed"))?,
            encode_claim_body(&base)?,
            serde_json::to_vec(&evidence).map_err(|_| invalid("reserve encode failed"))?,
        ] {
            hash.update(&(part.len() as u64).to_be_bytes());
            hash.update(&part);
        }
        for label in &evidence {
            let label_id = EntityId::from_hex(label)?;
            let body = self
                .get_claim_in_txn(txn, &label_id)?
                .ok_or(Error::EntityNotFound)?;
            if body.approval != ClaimApprovalStatus::Approved
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.source != Some(ClaimSource::UserStated)
                || body.subject != base.subject
            {
                return Err(invalid("claim held-out label moved"));
            }
            let encoded = encode_claim_body(&body)?;
            hash.update(&(encoded.len() as u64).to_be_bytes());
            hash.update(&encoded);
        }
        Ok(Snapshot {
            delta,
            base_id,
            base,
            candidate,
            evidence,
            binding: hash.finalize().to_hex().to_string(),
        })
    }
}

fn same_claim_target(base: &ClaimBody, candidate: &ClaimBody) -> bool {
    base.subject == candidate.subject
        && base.predicate == candidate.predicate
        && base.world == candidate.world
        && base.rel == candidate.rel
        && base.scope_facet == candidate.scope_facet
        && base.scope_project == candidate.scope_project
        && base.scope == candidate.scope
}
fn claim_binding(body: &ClaimBody) -> Result<String> {
    Ok(blake3::hash(&encode_claim_body(body)?).to_hex().to_string())
}
fn require_resident(vault: &Vault, txn: &heed::RoTxn<'_>, resident: EntityId) -> Result<()> {
    let valid = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &resident)?
        .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF);
    if valid {
        Ok(())
    } else {
        Err(invalid("claim refinement resident is not an agent"))
    }
}
fn read_delta(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<LocalClaimRefinement>> {
    let Some(control) = read_control(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    let RefinementTarget::Claim { base, proposal } = &control.target else {
        return Ok(None);
    };
    if control.state == RefinementState::Erased || *proposal != id.to_hex() {
        return Ok(None);
    }
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? else {
        return Err(Error::CorruptedIndex("refinement candidate without claim"));
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("refinement claim header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Err(Error::CorruptedIndex("refinement claim kind"));
    }
    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
    let session_tag = body
        .session_tag
        .ok_or_else(|| invalid("refinement claim lost session provenance"))?;
    Ok(Some(LocalClaimRefinement {
        candidate: id.to_hex(),
        base: base.clone(),
        resident: control
            .resident
            .ok_or_else(|| invalid("refinement resident missing"))?,
        session_tag,
        body: raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
        base_binding: control.base_binding,
        occurred_start: header.occurred_start,
        occurred_end: header.occurred_end,
        learned_at: header.learned_at,
    }))
}
