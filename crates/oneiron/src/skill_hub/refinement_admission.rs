//! Content-free refinement identity and the transaction-local exact-admission
//! capability. A ruling carrier is never proof; only this private constructor
//! can bind a consented usefulness-yes and held-out win to promoted bytes.

use super::{ClaimRefinementMergeReceipt, SharedSkillMergeReceipt, package_codec::invalid};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
    registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL},
    store::Store,
};
use serde::{Deserialize, Serialize};

// Permanent candidate origin, keyed only by entity ID. The value is the hash
// of the first native Proposed bytes, never the body or an approval receipt.
const CLAIM_ORIGIN: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_CLAIM_ORIGIN);
const SKILL_ORIGIN: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_SKILL_ORIGIN);
/// Content-free refinement control row for one candidate.
const CONTROL: SideTable<EntityId, RefinementControl, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_CONTROL);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RefinementState {
    Pending,
    Refused,
    Admitted,
    Erased,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum RefinementTarget {
    Skill { base: String, fork: String },
    Claim { base: String, proposal: String },
}
impl RefinementTarget {
    fn base(&self) -> &str {
        match self {
            Self::Skill { base, .. } | Self::Claim { base, .. } => base,
        }
    }
    fn kind(&self) -> u8 {
        match self {
            Self::Skill { .. } => ENTITY_TYPE_SKILL,
            Self::Claim { .. } => ENTITY_TYPE_CLAIM,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RefinementControl {
    pub(super) target: RefinementTarget,
    pub(super) resident: Option<String>,
    pub(super) base_binding: String,
    pub(super) proposal_binding: String,
    pub(super) state: RefinementState,
}
impl RefinementControl {
    pub(super) fn claim(
        base: EntityId,
        candidate: EntityId,
        resident: EntityId,
        base_binding: String,
        proposal_binding: String,
    ) -> Self {
        Self {
            target: RefinementTarget::Claim {
                base: base.to_hex(),
                proposal: candidate.to_hex(),
            },
            resident: Some(resident.to_hex()),
            base_binding,
            proposal_binding,
            state: RefinementState::Pending,
        }
    }
    pub(super) fn skill(
        base: EntityId,
        fork: EntityId,
        base_binding: String,
        proposal_binding: String,
    ) -> Self {
        Self {
            target: RefinementTarget::Skill {
                base: base.to_hex(),
                fork: fork.to_hex(),
            },
            resident: None,
            base_binding,
            proposal_binding,
            state: RefinementState::Pending,
        }
    }
}
pub(super) fn read_control(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<RefinementControl>> {
    CONTROL.get(store, txn, id)
}
pub(super) fn put_control(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    control: &RefinementControl,
) -> Result<()> {
    CONTROL.put(store, txn, id, control)
}
pub(crate) fn refinement_control_scope_exists(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(read_control(store, txn, id)?.is_some_and(|row| row.state != RefinementState::Erased))
}
pub(crate) fn retire_refinement_control(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(mut row) = read_control(store, txn, id)? else {
        return Ok(false);
    };
    if row.state == RefinementState::Erased {
        return Ok(false);
    }
    if matches!(row.target, RefinementTarget::Skill { .. }) {
        // The offer's source assertion is not a permanent deletion marker.
        // Retain only the content-free typed control/erased-ID fact.
        super::shared_delta::SHARED_DELTA.delete(store, txn, id)?;
    }
    row.state = RefinementState::Erased;
    put_control(store, txn, id, &row)?;
    Ok(true)
}

/// No public constructor. The score/decision/consent assertions run in the
/// same transaction that applies the exact body transition. A receipt can be
/// imported or replayed, but cannot construct this proof.
#[derive(Debug)]
pub(crate) struct RefinementAdmissionProof {
    candidate: EntityId,
    base: EntityId,
    kind: u8,
    bytes: blake3::Hash,
    proposal_binding: String,
    basis: String,
    decision_digest: blake3::Hash,
    consent_digest: String,
}
impl RefinementAdmissionProof {
    pub(super) fn for_claim(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        data: &[u8],
        proposal_binding: &str,
        receipt: &ClaimRefinementMergeReceipt,
        authorization: &crate::consent::ApproveOnceAuthorization,
    ) -> Result<Self> {
        if !receipt.accepted
            || !receipt.useful_upstream
            || !matches!((receipt.before, receipt.after), (Some(before), Some(after)) if after > before)
        {
            return Err(invalid(
                "claim refinement has no accepted decision and held-out win",
            ));
        }
        let candidate = EntityId::from_hex(&receipt.candidate)?;
        let base = EntityId::from_hex(&receipt.base)?;
        crate::consent::spend_approve_once_in_txn(&vault.store, txn, authorization)?;
        Self::new(
            candidate,
            base,
            ENTITY_TYPE_CLAIM,
            data,
            proposal_binding,
            &receipt.binding,
            &receipt.decision,
            &receipt.consent_digest,
        )
    }
    pub(super) fn for_skill(
        candidate: EntityId,
        base: EntityId,
        data: &[u8],
        proposal_binding: &str,
        receipt: &SharedSkillMergeReceipt,
    ) -> Result<Self> {
        if !receipt.accepted
            || !receipt.useful_upstream
            || !matches!((receipt.before, receipt.after), (Some(before), Some(after)) if after > before)
            || receipt.delta.candidate != candidate.to_hex()
            || receipt.delta.base != base.to_hex()
        {
            return Err(invalid(
                "skill refinement has no accepted decision and held-out win",
            ));
        }
        Self::new(
            candidate,
            base,
            ENTITY_TYPE_SKILL,
            data,
            proposal_binding,
            &receipt.binding,
            &receipt.decision,
            &receipt.consent_digest,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "the private proof pins each independent admission basis and consent axis"
    )]
    fn new(
        candidate: EntityId,
        base: EntityId,
        kind: u8,
        data: &[u8],
        proposal_binding: &str,
        basis: &str,
        decision: &crate::llm::decision::TypedDecision,
        consent_digest: &str,
    ) -> Result<Self> {
        Ok(Self {
            candidate,
            base,
            kind,
            bytes: blake3::hash(data),
            proposal_binding: proposal_binding.to_owned(),
            basis: basis.to_owned(),
            decision_digest: blake3::hash(
                &serde_json::to_vec(decision)
                    .map_err(|_| invalid("decision proof encode failed"))?,
            ),
            consent_digest: consent_digest.to_owned(),
        })
    }
    pub(crate) const fn candidate(&self) -> EntityId {
        self.candidate
    }
    pub(crate) fn binds_claim(&self, candidate: &EntityId, data: &[u8]) -> bool {
        self.candidate == *candidate
            && self.kind == ENTITY_TYPE_CLAIM
            && self.bytes == blake3::hash(data)
    }
    fn binds(
        &self,
        candidate: &EntityId,
        kind: u8,
        data: &[u8],
        control: &RefinementControl,
    ) -> bool {
        self.candidate == *candidate
            && self.kind == kind
            && control.target.base() == self.base.to_hex()
            && control.target.kind() == kind
            && control.proposal_binding == self.proposal_binding
            && matches!(
                control.state,
                RefinementState::Pending | RefinementState::Refused
            )
            && blake3::hash(data) == self.bytes
            && !self.basis.is_empty()
            && !self.consent_digest.is_empty()
            && self.decision_digest != blake3::hash(&[])
    }
}

/// A sealed transition of a stored claim that already carries the refinement
/// marker continues that admitted refinement: the marker passed this guard
/// once, and the proof binds this exact Put to that row. A succession (a
/// weakening or a facet fork) continues its predecessor; an in-place
/// transition (a demotion or a close) continues the row it rewrites.
fn continues_admitted_refinement(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &crate::claim::ClaimBody,
    transition: Option<&crate::batch::VerifiedClaimTransition>,
) -> Result<bool> {
    let Some(proof) = transition else {
        return Ok(false);
    };
    if !proof.matches_body(store, txn, id, body)? {
        return Ok(false);
    }
    let carrier = proof.predecessor().unwrap_or(*id);
    let Some(raw) = store.entities.get(txn, carrier.as_bytes())? else {
        return Ok(false);
    };
    let prior =
        crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok(declares_refinement(&prior))
}

fn declares_refinement(body: &crate::claim::ClaimBody) -> bool {
    body.evidence.as_ref().is_some_and(|evidence| {
        evidence.as_map().is_some_and(|fields| {
            fields.iter().any(|(key, value)| {
                key.as_str() == Some("provenance") && value.as_str() == Some("claim-refinement")
            })
        })
    })
}
fn declares_skill_refinement(record: &crate::skill::SkillRecord) -> bool {
    record.provenance.as_map().is_some_and(|fields| {
        fields.iter().any(|(key, value)| {
            key.as_str() == Some("source") && value.as_str() == Some("shared-skill-delta")
        })
    })
}
/// The useful-upstream requirement survives replay, same-byte aliases and
/// deletion even when the receiver has no locally submitted delta row.
pub(crate) fn skill_refinement_origin_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(SKILL_ORIGIN.get(store, txn, id)?.is_some())
}
/// The ordinary put chokepoint stages the first native Candidate/Proposed
/// origin after validation, for local and replicated writes alike. Delete
/// never removes these content-free facts.
pub(crate) fn stage_refinement_origin(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    claim: Option<&crate::claim::ClaimBody>,
    skill: Option<&crate::skill::SkillRecord>,
    data: &[u8],
) -> Result<()> {
    let table = if claim.is_some_and(|body| {
        body.approval == crate::claim::ClaimApprovalStatus::Proposed && declares_refinement(body)
    }) {
        CLAIM_ORIGIN
    } else if skill.is_some_and(|record| {
        record.lifecycle_status == crate::skill::SkillLifecycle::Candidate
            && declares_skill_refinement(record)
    }) {
        SKILL_ORIGIN
    } else {
        return Ok(());
    };
    let digest = blake3::hash(data);
    if let Some(prior) = table.get(store, txn, id)? {
        if prior != *digest.as_bytes() {
            return Err(invalid("refinement origin changed"));
        }
    } else {
        table.put(store, txn, id, digest.as_bytes())?;
    }
    Ok(())
}

/// The shared materialization door asks this BEFORE any gate or entity write.
pub(crate) fn validate_refinement_admission(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
    data: &[u8],
    proof: Option<&RefinementAdmissionProof>,
    transition: Option<&crate::batch::VerifiedClaimTransition>,
) -> Result<()> {
    let origin = CLAIM_ORIGIN.get(store, txn, id)?;
    let skill_origin = SKILL_ORIGIN.get(store, txn, id)?;
    let control = read_control(store, txn, id)?;
    if let Some(ref origin) = origin {
        if kind != ENTITY_TYPE_CLAIM {
            return Err(Error::CorruptedIndex("refinement origin binding"));
        }
        if control.is_none() {
            let same_stored_proposal = crate::ports::EntityStoreRead::port_entity_raw(
                store, txn, id,
            )?
            .is_some_and(|raw| raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) == Some(data));
            let body = crate::claim::decode_claim_body(data, true)?;
            if !same_stored_proposal
                || body.approval != crate::claim::ClaimApprovalStatus::Proposed
                || !declares_refinement(&body)
                || origin != blake3::hash(data).as_bytes()
            {
                return Err(invalid("refinement origin requires exact local admission"));
            }
            return Ok(());
        }
    }
    if let Some(ref skill_origin) = skill_origin {
        if kind != ENTITY_TYPE_SKILL {
            return Err(Error::CorruptedIndex("skill refinement origin binding"));
        }
        if control.is_none() {
            let same_stored_candidate = crate::ports::EntityStoreRead::port_entity_raw(
                store, txn, id,
            )?
            .is_some_and(|raw| raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) == Some(data));
            let record = crate::skill::decode_skill_record(data)?;
            if !same_stored_candidate
                || record.lifecycle_status != crate::skill::SkillLifecycle::Candidate
                || !declares_skill_refinement(&record)
                || skill_origin != blake3::hash(data).as_bytes()
            {
                return Err(invalid(
                    "skill refinement origin requires useful-upstream admission",
                ));
            }
            return Ok(());
        }
    }
    let Some(control) = control else {
        if kind == ENTITY_TYPE_SKILL {
            let record = crate::skill::decode_skill_record(data)?;
            if declares_skill_refinement(&record)
                && record.lifecycle_status != crate::skill::SkillLifecycle::Candidate
            {
                return Err(invalid(
                    "skill refinement origin cannot publish without proof",
                ));
            }
        }
        // A first Proposed copy may arrive before control. Its id is pinned
        // as an origin fact by stage_refinement_origin in this same put.
        if kind == ENTITY_TYPE_CLAIM {
            let body = crate::claim::decode_claim_body(data, true)?;
            if declares_refinement(&body)
                && (body.approval != crate::claim::ClaimApprovalStatus::Proposed
                    || body.session_tag.is_none())
                && !continues_admitted_refinement(store, txn, id, &body, transition)?
            {
                return Err(invalid(
                    "refinement origin cannot publish without local proof",
                ));
            }
        }
        return Ok(());
    };
    if kind == ENTITY_TYPE_CLAIM && origin.is_none() {
        return Err(Error::CorruptedIndex("refinement proposal origin"));
    }
    if kind == ENTITY_TYPE_SKILL && skill_origin.is_none() {
        return Err(Error::CorruptedIndex("skill refinement proposal origin"));
    }
    if control.state == RefinementState::Erased {
        return Err(invalid("erased refinement id cannot be reused"));
    }
    if control.target.kind() != kind {
        return Err(invalid("refinement kind cannot change"));
    }
    match (kind, control.state) {
        (ENTITY_TYPE_CLAIM, RefinementState::Pending | RefinementState::Refused) => {
            let same_proposed =
                crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?.is_some_and(
                    |raw| raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) == Some(data),
                ) && crate::claim::decode_claim_body(data, false)?.approval
                    == crate::claim::ClaimApprovalStatus::Proposed;
            if !same_proposed && !proof.is_some_and(|p| p.binds(id, kind, data, &control)) {
                return Err(invalid("claim refinement requires exact admission proof"));
            }
        }
        (ENTITY_TYPE_SKILL, RefinementState::Pending | RefinementState::Refused)
            if crate::skill::decode_skill_record(data)?.lifecycle_status
                == crate::skill::SkillLifecycle::Active
                && !proof.is_some_and(|p| p.binds(id, kind, data, &control)) =>
        {
            return Err(invalid("shared skill requires exact refinement proof"));
        }
        _ => {}
    }
    Ok(())
}
