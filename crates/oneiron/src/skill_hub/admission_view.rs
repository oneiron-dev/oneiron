//! Engine-computed install asks: trust changes presentation, never authorization.
use super::package_codec::{encode_hub_package, invalid};
use super::{ForeignSkillPublisher, HubPackage, HubRef, SkillHubTrustTier};
use crate::{
    Vault,
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    claim::ClaimApprovalStatus,
    consent::{ComposedEffect, EffectDigest, EffectFacts, UndoFidelity},
    entity_id::EntityId,
    error::{Error, Result},
    skill::{SkillLifecycle, SkillRecord},
};

/// Ordered friction. Every variant still needs the same human approve-once receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HubAskSurface {
    OneTap,
    SummarizedReview,
    FullReview,
}
#[must_use]
pub fn hub_ask_surface(
    tier: SkillHubTrustTier,
    scan: crate::skill_scan::ActivationPosture,
) -> HubAskSurface {
    let trust = match tier {
        SkillHubTrustTier::Verified => HubAskSurface::OneTap,
        SkillHubTrustTier::Community => HubAskSurface::SummarizedReview,
        SkillHubTrustTier::Untrusted => HubAskSurface::FullReview,
    };
    if matches!(
        scan,
        crate::skill_scan::ActivationPosture::ProposedRequired { .. }
    ) {
        HubAskSurface::FullReview
    } else {
        trust
    }
}
/// An immutable ask binds bytes, capabilities, source, publisher, evidence and baseline.
/// No public constructor or mutable fields: a caller can display an ask, not rewrite it.
#[derive(Debug, Clone)]
pub struct HubActivationAsk {
    pub(super) candidate: EntityId,
    pub(super) evidence_skill: EntityId,
    pub(super) source: HubRef,
    pub(super) publisher: ForeignSkillPublisher,
    pub(super) binding: String,
    pub(super) effect: EffectDigest,
    pub(super) surface: HubAskSurface,
    capabilities: super::SkillCapabilitySurface,
    content_hash: crate::skill::SkillContentHash,
}
impl HubActivationAsk {
    #[must_use]
    pub const fn effect_digest(&self) -> EffectDigest {
        self.effect
    }
    #[must_use]
    pub const fn surface(&self) -> HubAskSurface {
        self.surface
    }
    #[must_use]
    pub const fn candidate(&self) -> EntityId {
        self.candidate
    }
    #[must_use]
    pub fn capabilities(&self) -> &super::SkillCapabilitySurface {
        &self.capabilities
    }
    #[must_use]
    pub const fn content_hash(&self) -> crate::skill::SkillContentHash {
        self.content_hash
    }
    #[must_use]
    pub fn source(&self) -> &HubRef {
        &self.source
    }
}
pub(super) struct AdmissionSnapshot {
    pub(super) record: SkillRecord,
    pub(super) package: HubPackage,
    pub(super) baseline: SkillRecord,
    pub(super) baseline_instructions: String,
    pub(super) evidence: Vec<String>,
    pub(super) binding: String,
    pub(super) surface: HubAskSurface,
}
impl Vault {
    /// Builds the ask from a locally stored Candidate and an admitted publisher.
    /// `evidence_skill` names an active local evaluation baseline with real attributed
    /// outcomes. The held-out split is engine-selected, never caller-supplied evidence.
    pub fn prepare_marketplace_activation(
        &self,
        candidate: EntityId,
        source: &HubRef,
        publisher: &ForeignSkillPublisher,
        evidence_skill: EntityId,
    ) -> Result<HubActivationAsk> {
        let txn = self.store.env.read_txn()?;
        let snapshot =
            self.hub_admission_snapshot(&txn, candidate, source, publisher, evidence_skill)?;
        let effect = ComposedEffect::new(
            EffectFacts::new(format!("skill.install:{}", snapshot.binding))?
                .with_undo_fidelity(UndoFidelity::None),
        )
        .digest();
        let content_hash = snapshot.package.content_hash()?;
        Ok(HubActivationAsk {
            capabilities: snapshot.package.capabilities,
            content_hash,
            candidate,
            evidence_skill,
            source: source.clone(),
            publisher: publisher.clone(),
            binding: snapshot.binding,
            effect,
            surface: snapshot.surface,
        })
    }
    pub(super) fn hub_admission_snapshot(
        &self,
        txn: &heed::RoTxn<'_>,
        candidate: EntityId,
        source: &HubRef,
        publisher: &ForeignSkillPublisher,
        evidence_skill: EntityId,
    ) -> Result<AdmissionSnapshot> {
        self.check_publisher_in_txn(txn, publisher)?;
        if publisher.hub != source.hub_id || candidate == evidence_skill {
            return Err(invalid("invalid publisher or evidence baseline"));
        }
        let hub = self.hub_record_in_txn(txn, &source.hub_id)?;
        let record = read_skill(self, txn, &candidate)?;
        if record.lifecycle_status != SkillLifecycle::Candidate
            || record.approval_status == ClaimApprovalStatus::Rejected
        {
            return Err(invalid("admission requires an open candidate"));
        }
        if record
            .governance_tier
            .is_some_and(|tier| tier.is_protected())
        {
            return Err(invalid("protected skill requires its owner lifecycle door"));
        }
        let package = self.stored_hub_package_in_txn(txn, &candidate)?;
        let declared =
            super::folder::package_from_source(&record, package.files.clone(), package.format)?;
        if declared.capabilities != package.capabilities
            || declared.record.skill_id != record.skill_id
            || declared.record.version != record.version
            || declared.record.desc != record.desc
        {
            return Err(invalid(
                "file manifest and requested capability surface disagree",
            ));
        }
        if record.content_hash != Some(package.content_hash()?)
            || record.skill_id != package.record.skill_id
            || record.version != package.record.version
            || record.desc != package.record.desc
        {
            return Err(invalid("stored package and candidate disagree"));
        }
        self.check_hub_source_alias(txn, &candidate, source, package.content_hash()?)?;
        let baseline = read_skill(self, txn, &evidence_skill)?;
        if baseline.lifecycle_status != SkillLifecycle::Active {
            return Err(invalid("held-out baseline is not active"));
        }
        let baseline_instructions =
            self.hub_baseline_instructions(txn, &evidence_skill, &baseline)?;
        let evidence =
            crate::skill_reliability::attributed_outcome_receipts(self, txn, &evidence_skill)?
                .into_iter()
                .filter(|receipt| {
                    crate::skill_optimize::receipt_is_held_out(&evidence_skill, receipt)
                })
                .collect::<Vec<_>>();
        if evidence.is_empty() || evidence.len() > 4096 {
            return Err(invalid("held-out reserve is empty or exceeds replay bound"));
        }
        let posture = crate::skill_scan::scan_gate_for_activation_in_txn(
            &self.store,
            txn,
            package.content_hash()?,
        )?;
        let surface = hub_ask_surface(hub.trust_tier, posture);
        let binding_parts = BindingInputs {
            candidate,
            evidence_skill,
            record: &record,
            package: &package,
            baseline: &baseline,
            baseline_instructions: &baseline_instructions,
            evidence: &evidence,
            source,
            publisher,
            hub: &hub,
            scan: format!("{posture:?}"),
            surface,
        };
        let binding = snapshot_binding(&binding_parts)?;
        Ok(AdmissionSnapshot {
            record,
            package,
            baseline,
            baseline_instructions,
            evidence,
            binding,
            surface,
        })
    }
    fn check_hub_source_alias(
        &self,
        txn: &heed::RoTxn<'_>,
        candidate: &EntityId,
        source: &HubRef,
        content_hash: crate::skill::SkillContentHash,
    ) -> Result<()> {
        let source_value = source.to_value()?;
        let provenance = self.active_claims_for_predicate_in_txn(
            txn,
            candidate,
            super::PREDICATE_SKILL_HUB_PROVENANCE,
        )?;
        let content_hex = content_hash.to_hex();
        if !provenance.iter().any(|(_, body, _)| {
            super::support::map_value(&body.value, "hubRef") == Some(&source_value)
                && super::support::map_text(&body.value, "contentHash")
                    == Some(content_hex.as_str())
        }) {
            return Err(invalid(
                "source is not a current provenance alias of these bytes",
            ));
        }
        Ok(())
    }
}
struct BindingInputs<'a> {
    candidate: EntityId,
    evidence_skill: EntityId,
    record: &'a SkillRecord,
    package: &'a HubPackage,
    baseline: &'a SkillRecord,
    baseline_instructions: &'a str,
    evidence: &'a [String],
    source: &'a HubRef,
    publisher: &'a ForeignSkillPublisher,
    hub: &'a super::SkillHubRecord,
    scan: String,
    surface: HubAskSurface,
}
fn snapshot_binding(input: &BindingInputs<'_>) -> Result<String> {
    let BindingInputs {
        candidate,
        evidence_skill,
        record,
        package,
        baseline,
        baseline_instructions,
        evidence,
        source,
        publisher,
        hub,
        scan,
        surface,
    } = input;
    let mut source_bytes = Vec::new();
    rmpv::encode::write_value(&mut source_bytes, &source.to_value()?)
        .map_err(|_| invalid("source binding encode failed"))?;
    let parts = [
        candidate.as_bytes().to_vec(),
        evidence_skill.as_bytes().to_vec(),
        baseline_instructions.as_bytes().to_vec(),
        crate::skill::encode_skill_record(record)?,
        encode_hub_package(package)?,
        crate::skill::encode_skill_record(baseline)?,
        crate::skill_optimize::held_out_receipt_set_digest(evidence).into_bytes(),
        source_bytes,
        publisher.identity.as_bytes().to_vec(),
        publisher.grant_ref.as_bytes().to_vec(),
        super::encode_skill_hub_record(hub)?,
        scan.as_bytes().to_vec(),
        vec![*surface as u8],
    ];
    let mut hash = blake3::Hasher::new_derive_key("oneiron.skill-hub.activation.v1");
    for part in parts {
        hash.update(&(part.len() as u64).to_be_bytes());
        hash.update(&part);
    }
    Ok(hash.finalize().to_hex().to_string())
}
pub(super) fn read_skill(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<SkillRecord> {
    let raw = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
        return Err(invalid("entity is not a skill"));
    }
    crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])
}
