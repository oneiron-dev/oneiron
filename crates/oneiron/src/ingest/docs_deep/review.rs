//! The owner's one review of a source revision's derived claims (FIX 9884).
//! The claims stay Imported and Proposed, with no tray row each, until the
//! owner approves or declines the exact batch, or a standing grant for the
//! corpus approves them as they are written. Permission to derive from a
//! source never approves what the extractor said about it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{DEEP_RECEIPTS, DocsDeepReceipt, invalid};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ComposedEffect, EffectFacts,
    GrantBound,
};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::side_table::HexId;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope};
use crate::{EntityId, TimeRange, Vault};

/// The action class of a derived-claim review: the import batch review's own.
const DEEP_REVIEW_ACTION: &str = "claims.import.review";

/// The derivation a deep review names beside its source.
const DEEP_REVIEW_DERIVED: &str = "derived:ner_claims";

/// One derived claim as it was written and as the owner reviews it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsDeepReviewClaim {
    pub claim_ref: String,
    /// The ASSET_TEXT chunk its quote was found in.
    pub chunk_ref: String,
    pub segment_hash: String,
    pub source_record_id: String,
    pub predicate: String,
    pub value: Value,
    /// When it was written; its occurred window is this instant.
    pub learned_at: u64,
}

/// The owner's one review of every claim derived from a source revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsDeepReview {
    /// Each derived claim, in `claim_refs` order.
    pub claims: Vec<DocsDeepReviewClaim>,
    /// `Proposed` until the owner approves or declines the exact batch, or a
    /// standing grant approves every batch as it is written.
    pub decision: ClaimApprovalStatus,
    /// The standing grant that approved the claims, when one did.
    pub standing_grant_ref: Option<String>,
}

impl DocsDeepReview {
    pub(super) const fn proposed() -> Self {
        Self {
            claims: Vec::new(),
            decision: ClaimApprovalStatus::Proposed,
            standing_grant_ref: None,
        }
    }
}

/// One derived claim's Gate write: id, candidate, envelope, occurred window
/// and learned time.
type DeepClaimWrite = (EntityId, ClaimCandidate, WriteEnvelope, TimeRange, u64);

/// What every derived claim of one source revision is written with.
pub(super) struct DeepWrite<'a> {
    pub(super) asset: EntityId,
    pub(super) project_id: EntityId,
    pub(super) approval_digest: &'a str,
    pub(super) producer: &'a str,
    pub(super) actor: WriteActor,
}

impl DeepWrite<'_> {
    /// `claim`'s Gate write at `approval`: the same candidate whenever it is
    /// written, so an approval rewrites exactly the claim the owner saw.
    fn candidate(
        &self,
        claim: &DocsDeepReviewClaim,
        approval: ClaimApprovalStatus,
    ) -> Result<DeepClaimWrite> {
        let id = EntityId::from_hex(&claim.claim_ref)?;
        let occurred = TimeRange {
            start: claim.learned_at,
            end: claim.learned_at,
        };
        let admission = crate::ingest::ImportedEvidenceAdmission::proposed(
            crate::ingest::DOCS_EXPORT_SOURCE_ID,
            id,
            crate::ingest::ImportedEvidenceEntityResolution::subject(self.asset),
            self.actor,
            occurred,
            claim.learned_at,
        )
        .with_approval(approval);
        let (candidate, envelope) = crate::ingest::admission::imported_candidate(
            &claim.predicate,
            crate::ingest::json_to_msgpack_value(&claim.value),
            &claim.source_record_id,
            &admission,
        )?;
        let v = rmpv::Value::from;
        let rmpv::Value::Map(mut evidence) = crate::ingest::admission::imported_evidence_value(
            crate::ingest::DOCS_EXPORT_SOURCE_ID,
            &claim.source_record_id,
        ) else {
            unreachable!("imported evidence is a map")
        };
        evidence.push((
            v("derivation"),
            rmpv::Value::Map(vec![
                (v("source_ref"), v(claim.chunk_ref.as_str())),
                (v("source_hash"), v(claim.segment_hash.as_str())),
                (v("producer"), v(self.producer)),
                (v("source"), v("imported")),
                (v("derived_kind"), v("ner_claim")),
                (v("approval_digest"), v(self.approval_digest)),
            ]),
        ));
        let candidate = candidate
            .with_scope(rmpv::Value::Map(vec![(
                v("scopeProjectId"),
                rmpv::Value::Binary(self.project_id.as_bytes().to_vec()),
            )]))
            .with_evidence(rmpv::Value::Map(evidence));
        Ok((id, candidate, envelope, occurred, claim.learned_at))
    }
}

fn apply_deep_writes(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    writes: &[DeepClaimWrite],
) -> Result<()> {
    if writes.is_empty() {
        return Ok(());
    }
    let mut builder = vault.batch_in();
    for (id, candidate, envelope, occurred, learned_at) in writes {
        builder = builder.claim_candidate(id, candidate.clone(), envelope, *occurred, *learned_at);
    }
    builder.apply(txn)
}

/// The exact batch the owner decides: these claims, from this asset, by
/// this owner. Any changed or added claim changes its digest.
fn deep_review_effect(
    owner: EntityId,
    asset: EntityId,
    claims: &[DocsDeepReviewClaim],
) -> Result<ComposedEffect> {
    let content =
        serde_json::to_vec(claims).map_err(|_| invalid("docs deep review encoding failed"))?;
    let bound = GrantBound::action(
        ActorBound::new(owner.to_hex())?,
        ActionClass::new(DEEP_REVIEW_ACTION)?,
        ActionEnvelope::new([
            format!("source:{}", crate::ingest::DOCS_EXPORT_SOURCE_ID),
            DEEP_REVIEW_DERIVED.to_owned(),
            format!("asset:{}", asset.to_hex()),
            format!("claims:{}", claims.len()),
            format!("content:{}", blake3::hash(&content).to_hex()),
        ])?,
    )?;
    ComposedEffect::new(EffectFacts::new(DEEP_REVIEW_ACTION)?).with_action_requirement(bound)
}

/// The use a standing grant must contain to approve derived claims as they
/// are written: this owner's review of the docs source's derived claims in
/// `project`. A grant with no target covers every corpus.
fn deep_review_standing_use(owner: EntityId, project: EntityId) -> Result<GrantBound> {
    GrantBound::action(
        ActorBound::new(owner.to_hex())?,
        ActionClass::new(DEEP_REVIEW_ACTION)?,
        ActionEnvelope::new([
            format!("source:{}", crate::ingest::DOCS_EXPORT_SOURCE_ID),
            DEEP_REVIEW_DERIVED.to_owned(),
        ])?
        .with_target(format!("project:{}", project.to_hex()))?,
    )
}

impl Vault {
    /// Writes one batch of derived claims through the Gate, Proposed first.
    /// An active standing grant covering the corpus's derived-claim review
    /// approves them, with a use receipt. Otherwise one the Gate admits with
    /// no tray row is written again as `Auto` only when the policy trusts its
    /// source for `Auto`. Every other claim stays `Proposed` with no tray row
    /// of its own: the owner reviews the revision's claims as one batch.
    pub(super) fn admit_deep_claims_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        write: &DeepWrite<'_>,
        review: &mut DocsDeepReview,
        claims: &[DocsDeepReviewClaim],
    ) -> Result<()> {
        if claims.is_empty() {
            return Ok(());
        }
        let proposed = claims
            .iter()
            .map(|claim| write.candidate(claim, ClaimApprovalStatus::Proposed))
            .collect::<Result<Vec<_>>>()?;
        apply_deep_writes(self, txn, &proposed)?;
        let covering = deep_review_standing_use(owner, write.project_id)?;
        let grant_ref = crate::consent::load_active_standing_grants(&self.store, txn)?
            .iter()
            .find(|grant| grant.bound().contains(&covering))
            .map(|grant| grant.bound().digest().to_hex());
        if let Some(grant_ref) = grant_ref {
            let approved = claims
                .iter()
                .map(|claim| write.candidate(claim, ClaimApprovalStatus::Approved))
                .collect::<Result<Vec<_>>>()?;
            apply_deep_writes(self, txn, &approved)?;
            let digest = deep_review_effect(owner, write.asset, claims)?.digest();
            self.record_standing_grant_use_in_txn(txn, &grant_ref, digest)?;
            // A revision whose earlier claims still wait for the owner stays
            // undecided; only a grant that approved every batch decides it.
            if review.claims.is_empty() || review.decision == ClaimApprovalStatus::Approved {
                review.decision = ClaimApprovalStatus::Approved;
                review.standing_grant_ref = Some(grant_ref);
            }
        } else {
            let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
            let mut trusted = Vec::new();
            for (id, candidate, envelope, occurred, learned_at) in &proposed {
                if self.store.pending_gate_consent_in_txn(txn, id)?.is_none()
                    && self.get_claim_in_txn(txn, id)?.is_some_and(|landed| {
                        crate::gate::claim_source_trust_admits_auto(&landed, envelope, &policy)
                    })
                {
                    trusted.push((
                        *id,
                        candidate.clone(),
                        envelope.clone().with_approval(ClaimApprovalStatus::Auto),
                        *occurred,
                        *learned_at,
                    ));
                }
            }
            apply_deep_writes(self, txn, &trusted)?;
            review.decision = ClaimApprovalStatus::Proposed;
            review.standing_grant_ref = None;
        }
        for (id, ..) in &proposed {
            self.store.delete_pending_gate_consent_in_txn(txn, id)?;
        }
        review.claims.extend_from_slice(claims);
        Ok(())
    }

    /// The exact batch the owner reviews for `asset`: every derived claim
    /// on its receipt, as written. Its digest is what
    /// [`Vault::approve_docs_deep_claims`] and
    /// [`Vault::decline_docs_deep_claims`] take.
    pub fn docs_deep_review_effect(
        &self,
        owner: &AuthenticatedOwner,
        asset: EntityId,
    ) -> Result<ComposedEffect> {
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_in_txn(self, &txn)?;
        let receipt = self
            .deep_receipt_in(&txn, asset)?
            .ok_or(Error::EntityNotFound)?;
        deep_review_effect(actor, asset, &receipt.review.claims)
    }

    /// The owner's one act for the whole batch: the approve-once receipt and
    /// the Approved rewrite of every derived claim still Proposed commit in
    /// ONE write transaction, or neither does. `reviewed` is the hex digest
    /// of [`Vault::docs_deep_review_effect`] the owner was shown; a batch
    /// that changed or grew since is refused, to be shown again.
    pub fn approve_docs_deep_claims(
        &self,
        owner: &AuthenticatedOwner,
        asset: EntityId,
        reviewed: &str,
    ) -> Result<DocsDeepReceipt> {
        self.with_write_txn_grouped(|txn| {
            self.decide_docs_deep_claims_in_txn(
                txn,
                owner,
                asset,
                reviewed,
                ClaimApprovalStatus::Approved,
            )
        })
    }

    /// The owner's refusal of the whole batch: one denial receipt, and every
    /// derived claim still active retracted in the same transaction.
    pub fn decline_docs_deep_claims(
        &self,
        owner: &AuthenticatedOwner,
        asset: EntityId,
        reviewed: &str,
    ) -> Result<DocsDeepReceipt> {
        self.with_write_txn_grouped(|txn| {
            self.decide_docs_deep_claims_in_txn(
                txn,
                owner,
                asset,
                reviewed,
                ClaimApprovalStatus::Rejected,
            )
        })
    }

    fn decide_docs_deep_claims_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        asset: EntityId,
        reviewed: &str,
        decision: ClaimApprovalStatus,
    ) -> Result<DocsDeepReceipt> {
        let actor = owner.revalidate_in_txn(self, txn)?;
        let mut receipt = self
            .deep_receipt_in(txn, asset)?
            .ok_or(Error::EntityNotFound)?;
        let (_, _, _, hash, approval_digest, project_id) =
            self.deep_source_in(txn, asset, actor)?;
        if hash != receipt.derivation.source_hash {
            return Err(invalid("docs deep review names a replaced source revision"));
        }
        if receipt.review.decision != ClaimApprovalStatus::Proposed {
            return Err(invalid("docs deep review already decided"));
        }
        if receipt.review.claims.is_empty() {
            return Err(invalid("docs deep review has no claims"));
        }
        let digest = deep_review_effect(actor, asset, &receipt.review.claims)?.digest();
        if digest.to_hex() != reviewed {
            return Err(invalid("docs deep review changed since it was shown"));
        }
        let now = crate::unix_seconds_now();
        if decision == ClaimApprovalStatus::Approved {
            self.approve_once_in_txn(txn, owner, digest)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &digest)?
                    .ok_or(Error::CorruptedIndex("consent approve-once marker"))?;
            let mut waiting = Vec::new();
            for claim in &receipt.review.claims {
                let id = EntityId::from_hex(&claim.claim_ref)?;
                if self.get_claim_in_txn(txn, &id)?.is_some_and(|body| {
                    body.approval == ClaimApprovalStatus::Proposed
                        && body.lifecycle == ClaimLifecycleStatus::Active
                }) {
                    waiting.push(claim);
                }
            }
            let write = DeepWrite {
                asset,
                project_id,
                approval_digest: &approval_digest,
                producer: &receipt.derivation.producer,
                actor: WriteActor::new(actor, EdgeActorClass::Human),
            };
            // Proposed first, then Approved through the Gate, as the import
            // batch door admits an approved batch.
            for approval in [ClaimApprovalStatus::Proposed, ClaimApprovalStatus::Approved] {
                let writes = waiting
                    .iter()
                    .map(|claim| write.candidate(claim, approval))
                    .collect::<Result<Vec<_>>>()?;
                apply_deep_writes(self, txn, &writes)?;
            }
            crate::consent::spend_approve_once_in_txn(&self.store, txn, &authorization)?;
            // An approved commitment series projects from this approval's
            // transaction, as one approved anywhere else does.
            for claim in waiting {
                if claim.predicate != crate::commitment::PREDICATE_COMMITMENT_RECORD {
                    continue;
                }
                let id = EntityId::from_hex(&claim.claim_ref)?;
                if let Some(body) = self.get_claim_in_txn(txn, &id)? {
                    self.index_consented_commitment_series_in_txn(txn, &body, &id, now)?;
                }
            }
        } else {
            self.deny_consent_in_txn(txn, owner, digest)?;
            for claim in &receipt.review.claims {
                let id = EntityId::from_hex(&claim.claim_ref)?;
                if self
                    .get_claim_in_txn(txn, &id)?
                    .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Active)
                {
                    self.retract_claim_in_txn(txn, &id, now)?;
                }
                self.store.delete_pending_gate_consent_in_txn(txn, &id)?;
            }
        }
        receipt.review.decision = decision;
        DEEP_RECEIPTS.put(&self.store, txn, &HexId(asset), &receipt)?;
        Ok(receipt)
    }
}
