//! Imported and hub-derived instruction authority at the single SKILL materialization door.
use super::package_codec::invalid;
use crate::side_table::{self, Raw, SideTable, StagedRow};
use crate::{
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    claim::ClaimSource,
    entity_id::EntityId,
    error::{Error, Result},
    skill::{SkillLifecycle, SkillRecord},
    store::Store,
};

/// Origin marker for a hub-materialized skill (imported flag, optional
/// forked-from parent id); survives deletion so it cannot be laundered by
/// delete/recreate.
///
/// The write half of this table is a [`StagedRow`] built here for
/// [`crate::batch::put_apply::apply`] (outside this module) to commit inside
/// its own put transaction alongside the rest of the entity write.
const ORIGIN: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::SKILL_HUB_ORIGIN);

/// An exact-body activation authorization. Post-fit proof alone may suppress
/// the advisory scan's independent approval rewrite; other doors keep it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HubAdmissionKind {
    MarketplacePostFit(crate::skill::SkillContentHash),
    PackPostFit(crate::skill::SkillContentHash),
    OwnerConsent,
    HeldOut,
    Bootstrap,
    Optimized,
}
#[derive(Debug)]
pub(crate) struct HubAdmissionProof {
    id: EntityId,
    binding: blake3::Hash,
    kind: HubAdmissionKind,
}
impl HubAdmissionProof {
    fn new(id: EntityId, data: &[u8], kind: HubAdmissionKind) -> Self {
        Self {
            id,
            binding: blake3::hash(data),
            kind,
        }
    }
    pub(in crate::skill_hub) fn marketplace(
        id: EntityId,
        data: &[u8],
        hash: crate::skill::SkillContentHash,
    ) -> Self {
        Self::new(id, data, HubAdmissionKind::MarketplacePostFit(hash))
    }
    pub(in crate::skill_hub) fn post_fit(
        id: EntityId,
        data: &[u8],
        hash: crate::skill::SkillContentHash,
    ) -> Self {
        Self::new(id, data, HubAdmissionKind::PackPostFit(hash))
    }
    pub(in crate::skill_hub) fn bootstrap(id: EntityId, data: &[u8]) -> Self {
        Self::new(id, data, HubAdmissionKind::Bootstrap)
    }
    pub(in crate::skill_hub) fn optimized(id: EntityId, data: &[u8]) -> Self {
        Self::new(id, data, HubAdmissionKind::Optimized)
    }
    pub(in crate::skill_hub) fn consent(
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        data: &[u8],
        authorization: &crate::consent::ApproveOnceAuthorization,
    ) -> Result<Self> {
        crate::consent::spend_approve_once_in_txn(store, txn, authorization)?;
        Ok(Self::new(id, data, HubAdmissionKind::OwnerConsent))
    }
    pub(in crate::skill_hub) fn held_out(
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        data: &[u8],
        authorization: &crate::consent::ApproveOnceAuthorization,
    ) -> Result<Self> {
        crate::consent::spend_approve_once_in_txn(store, txn, authorization)?;
        Ok(Self::new(id, data, HubAdmissionKind::HeldOut))
    }
    pub(in crate::skill_hub) fn id(&self) -> EntityId {
        self.id
    }
    pub(crate) fn binds(&self, id: &EntityId, data: &[u8]) -> bool {
        self.id == *id && self.binding == blake3::hash(data)
    }
    /// Called after the SKILL materialization guard verified this exact proof.
    /// A post-fit signal was already resolved by the host; scan is not consent.
    pub(crate) fn resolved_post_fit(
        &self,
        id: &EntityId,
        data: &[u8],
        record: &SkillRecord,
    ) -> bool {
        let hash = match self.kind {
            HubAdmissionKind::MarketplacePostFit(hash) | HubAdmissionKind::PackPostFit(hash) => {
                hash
            }
            _ => return false,
        };
        self.binds(id, data)
            && record.content_hash == Some(hash)
            && record.source == ClaimSource::Imported
    }
}

/// Post-fit proof has already resolved advisory signals; all other writes
/// retain the existing scan consent escalation at the batch chokepoint.
pub(crate) fn scan_skill_admission(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    record: &mut SkillRecord,
    proof: Option<&HubAdmissionProof>,
) -> Result<bool> {
    let encoded = crate::skill::encode_skill_record(record)?;
    if proof.is_some_and(|proof| proof.resolved_post_fit(id, &encoded, record)) {
        Ok(false)
    } else {
        crate::skill_scan::escalate_activation_approval_in_txn(store, txn, id, record)
    }
}

impl crate::Vault {
    pub(in crate::skill_hub) fn admit_hub_skill_record_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        occurred: crate::TimeRange,
        learned_at: u64,
        data: Vec<u8>,
        proof: HubAdmissionProof,
    ) -> Result<()> {
        self.admit_hub_skill_record_with_refinement_in_txn(
            txn, occurred, learned_at, data, proof, None,
        )
    }

    pub(in crate::skill_hub) fn admit_hub_skill_record_with_refinement_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        occurred: crate::TimeRange,
        learned_at: u64,
        data: Vec<u8>,
        proof: HubAdmissionProof,
        refinement: Option<super::refinement_admission::RefinementAdmissionProof>,
    ) -> Result<()> {
        let candidate = proof.id();
        let mode = crate::batch::ApplyOpsGateMode::new(false, true).with_hub_admission(proof);
        let mode = match refinement {
            Some(refinement) => mode.with_refinement_admission(refinement),
            None => mode,
        };
        crate::batch::apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id: candidate,
                entity_type: crate::registry::ENTITY_TYPE_SKILL,
                occurred,
                learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            mode,
        )
    }
}
fn origin(record: &SkillRecord) -> Vec<u8> {
    let mut out = vec![u8::from(record.source == ClaimSource::Imported)];
    if let Some(parent) = record.forked_from {
        out.extend_from_slice(parent.as_bytes());
    }
    out
}
/// Read-only preflight. Its optional marker is staged only after all remote-refusal checks.
/// Markers survive deletion, so delete/recreate cannot launder a governed id into owner-authored content.
pub(crate) fn check_hub_skill_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    record: &SkillRecord,
    replaces_source: bool,
    proof: Option<&HubAdmissionProof>,
) -> Result<Option<StagedRow>> {
    super::package_codec::check_source_binding_update(store, txn, id, record, replaces_source)?;
    let marked = ORIGIN.get(store, txn, id)?;
    let current_origin = origin(record);
    if let Some(marked) = &marked
        && marked.as_slice() != current_origin.as_slice()
    {
        return Err(invalid(
            "hub or fork origin cannot be removed, including after deletion",
        ));
    }
    if marked.is_none() && !has_import_origin(store, txn, record)? {
        return Ok(None);
    }
    let prior = store
        .entities
        .get(txn, id.as_bytes())?
        .map(|raw| {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
                return Err(invalid("skill id type changed"));
            }
            crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])
        })
        .transpose()?;
    if let Some(prior) = &prior
        && origin(prior) != current_origin
    {
        return Err(invalid("hub or fork origin is immutable"));
    }
    let unchanged_active = prior
        .as_ref()
        .is_some_and(|prior| prior.lifecycle_status == SkillLifecycle::Active)
        && prior
            .as_ref()
            .map(crate::skill_optimize::skill_body_binding_digest)
            .transpose()?
            == Some(crate::skill_optimize::skill_body_binding_digest(record)?);
    if record.lifecycle_status == SkillLifecycle::Active && !unchanged_active {
        // Code-bearing hub source stays Candidate until a foreign microVM can
        // execute and return its typed result. The in-process JS runtime
        // deliberately refuses Foreign; a held-out text score is not that
        // sandbox qualification. Imported ancestry keeps this guard on forks.
        if record.role == crate::skill::SkillRole::Callable {
            return Err(invalid(
                "imported callable activation requires foreign sandbox qualification",
            ));
        }
        if record.source == ClaimSource::Imported
            && let Some(hash) = record.content_hash
            && super::import_receipt::marketplace_hash_blocked_in_txn(store, txn, hash)?
        {
            return Err(invalid("marketplace hash rule blocks activation"));
        }
        let proof = proof.ok_or_else(|| {
            invalid("hub or fork activation requires local consent and held-out replay")
        })?;
        let encoded = crate::skill::encode_skill_record(record)?;
        if !proof.binds(id, &encoded) {
            return Err(invalid(
                "hub admission proof does not bind this exact record",
            ));
        }
    }
    marked
        .is_none()
        .then(|| ORIGIN.stage(id, &current_origin))
        .transpose()
}

/// A local owner-authored fork is not a marketplace import. Imported ancestry
/// stays governed across arbitrary forks; missing or cyclic ancestry refuses.
fn has_import_origin(store: &Store, txn: &heed::RoTxn<'_>, record: &SkillRecord) -> Result<bool> {
    if record.source == ClaimSource::Imported {
        return Ok(true);
    }
    let mut parent = record.forked_from;
    let mut seen = std::collections::BTreeSet::new();
    while let Some(id) = parent {
        if seen.len() >= 128 || !seen.insert(id) {
            return Err(invalid("invalid skill fork ancestry"));
        }
        if ORIGIN.contains(store, txn, &id)? {
            return Ok(true);
        }
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or_else(|| invalid("skill fork ancestry is missing"))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("skill ancestor header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
            return Err(invalid("skill ancestor changed type"));
        }
        let prior = crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if prior.source == ClaimSource::Imported {
            return Ok(true);
        }
        parent = prior.forked_from;
    }
    Ok(false)
}
