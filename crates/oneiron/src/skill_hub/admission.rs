//! Consent-bound held-out admission, using the existing host scorer and lifecycle write door.
use super::{HubActivationAsk, admission_view::AdmissionSnapshot, package_codec::invalid};
use crate::{
    Vault,
    claim::ClaimApprovalStatus,
    consent::{AuthenticatedOwner, ConsentReceipt},
    entity_id::EntityId,
    error::Result,
    skill::SkillLifecycle,
    skill_optimize::{HeldOutReplayCase, HeldOutReplayScorer},
    temporal::TimeRange,
};

/// Durable ruling with both actual scores, exact consent, content and source.
/// IDs are canonical hex strings to keep this envelope transport-neutral.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubAdmissionReceipt {
    pub receipt_id: String,
    pub candidate: String,
    pub content_hash: String,
    pub binding: String,
    pub consent_digest: String,
    pub publisher: String,
    pub publisher_grant: String,
    pub hub_id: String,
    pub hub_ref: String,
    pub evidence_skill: String,
    pub held_out_digest: String,
    pub held_out_count: usize,
    pub before: f32,
    pub after: f32,
    pub accepted: bool,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq)]
pub enum HubAdmissionDisposition {
    PendingConsent,
    Ruled(Box<HubAdmissionReceipt>),
}
impl Vault {
    /// The human answer, bound to the ask shown. A stale ask mints no consent.
    pub fn approve_marketplace_activation(
        &self,
        ask: &HubActivationAsk,
        owner: &AuthenticatedOwner,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn(|txn| {
            self.check_hub_ask_in_txn(txn, ask)?;
            self.approve_once_in_txn(txn, owner, ask.effect)
        })
    }
    /// Scores real held-out local outcomes outside all transactions. No built-in
    /// scorer, trust shortcut, caller score, or optimizer-origin marker exists.
    /// A rejection consumes this decision; new content/evidence needs a fresh ask.
    pub fn admit_marketplace_skill(
        &self,
        ask: &HubActivationAsk,
        scorer: &dyn HeldOutReplayScorer,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<HubAdmissionDisposition> {
        let snapshot = {
            let txn = self.store.env.read_txn()?;
            let snapshot = self.check_hub_ask_in_txn(&txn, ask)?;
            if crate::consent::approve_once_authorization_in_txn(&self.store, &txn, &ask.effect)?
                .is_none()
            {
                return Ok(HubAdmissionDisposition::PendingConsent);
            }
            snapshot
        };
        let instructions = snapshot
            .package
            .files
            .iter()
            .find(|file| file.path == "SKILL.md")
            .ok_or_else(|| invalid("candidate has no instructions"))?;
        let instructions = std::str::from_utf8(&instructions.content)
            .map_err(|_| invalid("instructions are not UTF-8"))?;
        let before = score(
            scorer,
            ask,
            &snapshot,
            &snapshot.baseline.version,
            &snapshot.baseline_instructions,
        )?;
        let after = score(
            scorer,
            ask,
            &snapshot,
            &snapshot.record.version,
            instructions,
        )?;
        self.with_write_txn(|txn| {
            self.check_hub_ask_in_txn(txn, ask)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &ask.effect)?
                    .ok_or_else(|| invalid("human install consent is missing"))?;
            let receipt = admission_receipt(ask, &snapshot, before, after, learned_at)?;
            if receipt.accepted {
                self.activate_scored_hub_record_in_txn(
                    txn,
                    &ask.candidate,
                    &snapshot.record,
                    occurred,
                    learned_at,
                    &authorization,
                )?;
            }
            crate::consent::spend_approve_once_in_txn(&self.store, txn, &authorization)?;
            let encoded_receipt = serde_json::to_vec(&receipt)
                .map_err(|_| invalid("admission receipt encode failed"))?;
            let mut history_key = b"skill_hub/admission-history/v1\0".to_vec();
            history_key.extend_from_slice(receipt.receipt_id.as_bytes());
            self.store
                .vault_meta
                .put(txn, &history_key, &encoded_receipt)?;
            self.store.vault_meta.put(
                txn,
                &receipt_key(&ask.candidate),
                &serde_json::to_vec(&receipt)
                    .map_err(|_| invalid("admission receipt encode failed"))?,
            )?;
            Ok(HubAdmissionDisposition::Ruled(Box::new(receipt)))
        })
    }
    pub(super) fn activate_scored_hub_record_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        candidate: &EntityId,
        record: &crate::skill::SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
        authorization: &crate::consent::ApproveOnceAuthorization,
    ) -> Result<()> {
        let mut admitted = record.clone();
        admitted.approval_status = ClaimApprovalStatus::Approved;
        admitted.lifecycle_status = SkillLifecycle::Active;
        let data = crate::skill::encode_skill_record(&admitted)?;
        let proof =
            super::admission_guard::HubAdmissionProof::consent(*candidate, &data, authorization);
        self.admit_hub_skill_record_in_txn(txn, occurred, learned_at, data, proof)
    }
    /// Reads the most recent hub admission ruling (including a scored refusal).
    pub fn hub_admission_receipt(
        &self,
        candidate: &EntityId,
    ) -> Result<Option<HubAdmissionReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &receipt_key(candidate))?
            .map(|raw| {
                serde_json::from_slice(&raw).map_err(|_| invalid("invalid admission receipt"))
            })
            .transpose()
    }
    pub(super) fn check_hub_ask_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        ask: &HubActivationAsk,
    ) -> Result<AdmissionSnapshot> {
        let current = self.hub_admission_snapshot(
            txn,
            ask.candidate,
            &ask.source,
            &ask.publisher,
            ask.evidence_skill,
        )?;
        if current.binding != ask.binding {
            return Err(invalid(
                "content, source, consent posture or held-out evidence moved",
            ));
        }
        Ok(current)
    }
}
fn score(
    scorer: &dyn HeldOutReplayScorer,
    ask: &HubActivationAsk,
    snapshot: &AdmissionSnapshot,
    version: &str,
    instructions: &str,
) -> Result<f32> {
    let score = scorer.score(&HeldOutReplayCase {
        skill: ask.evidence_skill,
        skill_id: &snapshot.baseline.skill_id,
        version,
        instructions,
        held_out_receipts: &snapshot.evidence,
    })?;
    if !score.is_finite() || !(0.0..=1.0).contains(&score) {
        return Err(invalid("invalid host held-out score"));
    }
    Ok(score)
}
fn admission_receipt(
    ask: &HubActivationAsk,
    snapshot: &AdmissionSnapshot,
    before: f32,
    after: f32,
    at: u64,
) -> Result<HubAdmissionReceipt> {
    Ok(HubAdmissionReceipt {
        receipt_id: EntityId::now().to_hex(),
        candidate: ask.candidate.to_hex(),
        content_hash: snapshot.package.content_hash()?.to_hex(),
        binding: ask.binding.clone(),
        consent_digest: ask.effect.to_hex(),
        publisher: ask.publisher.identity.clone(),
        publisher_grant: ask.publisher.grant_ref.clone(),
        hub_id: ask.source.hub_id.to_hex(),
        hub_ref: ask.source.ref_string.clone(),
        evidence_skill: ask.evidence_skill.to_hex(),
        held_out_digest: crate::skill_optimize::held_out_receipt_set_digest(&snapshot.evidence),
        held_out_count: snapshot.evidence.len(),
        before,
        after,
        accepted: after > before,
        at,
    })
}
fn receipt_key(candidate: &EntityId) -> Vec<u8> {
    let mut key = b"skill_hub/admission-receipt/v1\0".to_vec();
    key.extend_from_slice(candidate.as_bytes());
    key
}
