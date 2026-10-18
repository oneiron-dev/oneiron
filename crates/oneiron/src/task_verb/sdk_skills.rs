//! Owner-bound library doors over the existing conversion, lifecycle and admission engines.
use serde::{Deserialize, Serialize};

use crate::claim::ClaimApprovalStatus;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::skill_convert::{ConvertOutcome, ConvertRequest, SkillRefiner};
use crate::skill_hub::{HubAdmissionDisposition, HubAdmissionReceipt, HubRef};
use crate::{EntityId, Error, TimeRange, Vault};

use super::sdk::{HubConsentReceipt, HubSkillReceipts, HubSkillRequest};

/// Conversion accepts references, never caller-authored trusted skill bytes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillConvertRequest {
    pub message_refs: Vec<EntityId>,
    #[serde(default)]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SkillConvertReceipt {
    Created { entity: EntityId },
    DupPointer { entity: EntityId },
    MergeProposed { existing: EntityId, proposal: EntityId },
}

impl SkillConvertReceipt {
    pub fn rows(&self) -> Vec<EntityId> {
        match self {
            Self::Created { entity } | Self::DupPointer { entity } => vec![*entity],
            Self::MergeProposed { existing, proposal } => vec![*existing, *proposal],
        }
    }
}

pub fn skill_convert_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillConvertRequest,
    refiner: &dyn SkillRefiner,
) -> MemoryResult<SkillConvertReceipt> {
    owner.revalidate(vault)?;
    let request = ConvertRequest {
        message_refs: input.message_refs.clone(),
        hint: input.hint.clone(),
    };
    let at = vault.now_recorded_at();
    Ok(match crate::skill_convert::convert_messages_to_skill(
        vault, &request, refiner, TimeRange { start: at, end: at }, at,
    )? {
        ConvertOutcome::Created(entity) => SkillConvertReceipt::Created { entity },
        ConvertOutcome::DupPointer(entity) => SkillConvertReceipt::DupPointer { entity },
        ConvertOutcome::MergeProposed { existing, proposal } => {
            SkillConvertReceipt::MergeProposed { existing, proposal }
        }
    })
}

/// Public archive spelling of the engine's existing soft-retired Quarantined state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SkillLibraryLifecycle {
    Candidate,
    Active,
    Stale,
    Archived,
    Superseded,
}

impl From<SkillLifecycle> for SkillLibraryLifecycle {
    fn from(state: SkillLifecycle) -> Self {
        match state {
            SkillLifecycle::Candidate => Self::Candidate,
            SkillLifecycle::Active => Self::Active,
            SkillLifecycle::Stale => Self::Stale,
            SkillLifecycle::Quarantined => Self::Archived,
            SkillLifecycle::Superseded => Self::Superseded,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillLibraryListRequest {
    #[serde(default)]
    pub after: Option<EntityId>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillLibraryPage {
    pub skills: Vec<SkillLibraryView>,
    pub next_after: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillSourceEvidence {
    pub message_ref: EntityId,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillStaleView {
    pub reason: String,
    pub deleted_refs: Vec<EntityId>,
}

/// A birth pin, not today's head of the parent. None means the engine retained no pin.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillForkLineage {
    pub parent: EntityId,
    pub parent_version: Option<String>,
    pub parent_document: Option<EntityId>,
    pub parent_frontier: Option<Vec<u8>>,
    pub parent_available: bool,
    pub hub_sources: Vec<HubRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillLibraryDependency {
    pub skill_id: String,
    pub min_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillLibraryCall {
    pub reference: String,
    pub arguments: serde_json::Value,
    pub returns: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillCapabilityView {
    pub bins: Vec<String>,
    pub env: Vec<String>,
    pub mcp: Vec<String>,
    pub allowed_tools: Vec<String>,
}

/// Exact source bytes; source absence is distinct from an empty file tree.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillLibraryFile {
    pub path: String,
    pub content: Vec<u8>,
}

/// Scanner evidence remains separate from consent and owner rules.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SkillLibraryScan {
    pub content_hash: String,
    pub provider: String,
    pub scanned_at: u64,
    pub verdict: String,
    pub risk_level: String,
    pub completeness: String,
    pub governance: String,
    pub scanned_at_declared: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillLibraryView {
    pub entity: EntityId,
    pub skill_id: String,
    pub desc: String,
    pub version: String,
    pub content_hash: Option<String>,
    pub lifecycle: SkillLibraryLifecycle,
    pub approval: ClaimApprovalStatus,
    pub loadable: bool,
    pub source: String,
    pub role: String,
    pub call: Option<SkillLibraryCall>,
    pub governance_tier: Option<String>,
    pub generated: bool,
    pub human_authored: bool,
    pub dependencies: Vec<SkillLibraryDependency>,
    pub provenance: serde_json::Value,
    pub source_messages: Vec<SkillSourceEvidence>,
    pub stale: Option<SkillStaleView>,
    pub lineage: Vec<SkillForkLineage>,
    pub files: Option<Vec<SkillLibraryFile>>,
    pub capabilities: Option<SkillCapabilityView>,
    pub scans: Vec<SkillLibraryScan>,
    pub receipts: HubSkillReceipts,
}

/// Rows used by a library read, including ancestry and its hub aliases.
impl SkillLibraryView {
    pub fn rows(&self) -> Vec<EntityId> {
        std::iter::once(self.entity)
            .chain(self.source_messages.iter().map(|source| source.message_ref))
            .chain(self.receipts.sources.iter().map(|source| source.hub_id))
            .chain(self.lineage.iter().flat_map(|hop| {
                std::iter::once(hop.parent).chain(hop.hub_sources.iter().map(|source| source.hub_id))
            }))
            .collect()
    }
}

fn skill(vault: &Vault, entity: &EntityId) -> MemoryResult<SkillRecord> {
    vault.get_skill_record(entity)?.ok_or_else(|| Error::EntityNotFound.into())
}

pub fn skill_library_get_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubSkillRequest,
) -> MemoryResult<SkillLibraryView> {
    owner.revalidate(vault)?;
    let record = skill(vault, &input.entity)?;
    let source_refs = crate::skill_convert::source_message_refs(&record)?;
    let (files, capabilities, source_messages) = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let package = vault.runtime_skill_package_in_txn(&txn, &input.entity, &record)?;
        let (files, capabilities) = match package {
            Some(package) => (
                Some(package.files.into_iter().map(|file| SkillLibraryFile {
                    path: file.path, content: file.content,
                }).collect()),
                Some(SkillCapabilityView {
                    bins: package.capabilities.bins.into_iter().collect(),
                    env: package.capabilities.env.into_iter().collect(),
                    mcp: package.capabilities.mcp.into_iter().collect(),
                    allowed_tools: package.capabilities.allowed_tools.into_iter().collect(),
                }),
            ),
            None => (None, None),
        };
        let source_messages = source_refs.into_iter().map(|message_ref| {
            Ok(SkillSourceEvidence {
                available: crate::vault::live_entity_row_in_txn(&vault.store, &txn, &message_ref)?.is_live(),
                message_ref,
            })
        }).collect::<crate::Result<Vec<_>>>()?;
        (files, capabilities, source_messages)
    };
    let mut lineage = Vec::new();
    let mut child = record.clone();
    let mut seen = std::collections::BTreeSet::from([input.entity]);
    while let Some(parent) = child.forked_from {
        if !seen.insert(parent) {
            return Err(MemoryError::bad_request("cyclic skill fork ancestry"));
        }
        let provenance = crate::msgpack_value_to_json(&child.provenance);
        let parent_record = vault.get_skill_record(&parent)?;
        lineage.push(SkillForkLineage {
            parent,
            parent_version: provenance.get("forkOfVersion").and_then(serde_json::Value::as_str).map(str::to_owned),
            // The existing fork law retains a row/version, not a document pin.
            parent_document: None,
            parent_frontier: None,
            parent_available: parent_record.is_some(),
            hub_sources: vault.skill_hub_sources(&parent)?,
        });
        let Some(parent) = parent_record else { break };
        child = parent;
    }
    let scans = match record.content_hash {
        Some(hash) => vault.skill_scan_verdicts_for_content_hash(hash)?.into_iter().map(|claim| {
            serde_json::from_value(crate::msgpack_value_to_json(&claim.value))
                .map_err(|_| MemoryError::bad_request("invalid stored skill scan receipt"))
        }).collect::<MemoryResult<Vec<_>>>()?,
        None => Vec::new(),
    };
    let stale = crate::skill_convert::skill_stale_note(vault, &input.entity)?.map(|note| SkillStaleView {
        reason: note.reason, deleted_refs: note.deleted_refs,
    });
    Ok(SkillLibraryView {
        entity: input.entity,
        content_hash: record.content_hash.map(|hash| hash.to_hex()),
        lifecycle: record.lifecycle_status.into(),
        approval: record.approval_status,
        loadable: crate::skill::skill_loadable(&record),
        source: record.source.as_str().to_owned(),
        role: record.role.as_str().to_owned(),
        call: record.call.map(|call| SkillLibraryCall {
            reference: call.reference, arguments: call.arguments, returns: call.returns,
        }),
        governance_tier: record.governance_tier.map(|tier| tier.as_str().to_owned()),
        generated: record.generated,
        human_authored: record.human_authored,
        dependencies: record.dependencies.into_iter().map(|dependency| SkillLibraryDependency {
            skill_id: dependency.skill_id, min_version: dependency.min_version,
        }).collect(),
        provenance: crate::msgpack_value_to_json(&record.provenance),
        skill_id: record.skill_id,
        desc: record.desc,
        version: record.version,
        source_messages, stale, lineage, files, capabilities, scans,
        receipts: super::sdk::hub_skill_receipts_as_owner(vault, owner, input)?,
    })
}

pub fn skill_library_list_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillLibraryListRequest,
) -> MemoryResult<SkillLibraryPage> {
    owner.revalidate(vault)?;
    if input.limit == 0 {
        return Err(MemoryError::bad_request("limit must be positive"));
    }
    let ids = vault.entities_by_type_page(crate::registry::ENTITY_TYPE_SKILL, input.after.as_ref(), input.limit)?;
    let next_after = ids.last().copied();
    let mut skills = Vec::new();
    for entity in ids {
        if vault.get_skill_record(&entity)?.is_some() {
            skills.push(skill_library_get_as_owner(vault, owner, &HubSkillRequest { entity })?);
        }
    }
    Ok(SkillLibraryPage { skills, next_after })
}

/// Changes only lifecycle/approval, inside the same owner-checked write and ordinary batch gate.
fn lifecycle_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    entity: EntityId,
    lifecycle: SkillLifecycle,
) -> MemoryResult<()> {
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &entity)?.is_live() {
            return Err(Error::EntityNotFound);
        }
        let prior = vault.read_skill_record_in_txn(txn, &entity)?;
        let mut updated = prior.clone();
        updated.lifecycle_status = lifecycle;
        if lifecycle == SkillLifecycle::Quarantined {
            updated.approval_status = ClaimApprovalStatus::Approved;
        }
        crate::skill::validate_skill_update(&prior, &updated)?;
        let at = vault.now_recorded_at();
        vault.apply_skill_record_body(
            txn, &entity, TimeRange { start: at, end: at }, at,
            crate::skill::encode_skill_record(&updated)?, false,
        )
    })?;
    Ok(())
}

pub fn skill_archive_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubSkillRequest,
) -> MemoryResult<SkillLibraryView> {
    lifecycle_as_owner(vault, owner, input.entity, SkillLifecycle::Quarantined)?;
    vault.skill_invocations.cancel_skill(&input.entity);
    skill_library_get_as_owner(vault, owner, input)
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillLibraryForkRequest {
    pub parent: EntityId,
    #[serde(default)]
    pub entity: Option<EntityId>,
    pub skill_id: String,
}

pub fn skill_library_fork_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillLibraryForkRequest,
) -> MemoryResult<SkillLibraryView> {
    let entity = input.entity.unwrap_or_else(EntityId::now);
    let at = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        vault.fork_skill_record_in_txn(
            txn, &input.parent, &entity, &input.skill_id, TimeRange { start: at, end: at }, at,
        )
    })?;
    skill_library_get_as_owner(vault, owner, &HubSkillRequest { entity })
}

/// A hub restore repeats its existing exact-consent and held-out admission, not a bare flip.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillRestoreAdmission {
    pub source: HubRef,
    pub publisher: String,
    pub evidence_skill: EntityId,
    #[serde(default)]
    pub effect_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillLibraryRestoreRequest {
    pub entity: EntityId,
    #[serde(default)]
    pub admission: Option<SkillRestoreAdmission>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SkillLibraryRestoreReceipt {
    Restored { skill: Box<SkillLibraryView>, admission: Option<HubAdmissionReceipt> },
    PendingAdmission { entity: EntityId, content_hash: String, effect_digest: String },
    Refused { entity: EntityId, admission: HubAdmissionReceipt },
}

pub fn skill_restore_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillLibraryRestoreRequest,
    scorer: Option<&dyn crate::skill_optimize::HeldOutReplayNotes>,
) -> MemoryResult<SkillLibraryRestoreReceipt> {
    owner.revalidate(vault)?;
    let record = skill(vault, &input.entity)?;
    if record.lifecycle_status != SkillLifecycle::Quarantined {
        return Err(MemoryError::bad_request("restore requires an archived skill"));
    }
    {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        for source in crate::skill_convert::source_message_refs(&record)? {
            if !crate::vault::live_entity_row_in_txn(&vault.store, &txn, &source)?.is_live() {
                return Err(MemoryError::bad_request("restore source evidence is unavailable"));
            }
        }
    }
    let admission = if let Some(admission) = &input.admission {
        let publisher = vault.admit_skill_publisher(owner, &admission.publisher, admission.source.hub_id)?;
        let ask = vault.prepare_marketplace_activation(
            input.entity, &admission.source, &publisher, admission.evidence_skill,
        )?;
        let digest = ask.effect_digest().to_hex();
        let Some(shown) = &admission.effect_digest else {
            return Ok(SkillLibraryRestoreReceipt::PendingAdmission {
                entity: input.entity, content_hash: ask.content_hash().to_hex(), effect_digest: digest,
            });
        };
        if shown != &digest {
            return Err(MemoryError::bad_request("restore admission moved; prepare it again"));
        }
        let scorer = scorer.ok_or_else(|| MemoryError::new(
            crate::memory::MEMORY_CODE_MODEL_UNAVAILABLE, "no held-out skill judge is registered", &[],
        ))?;
        vault.approve_marketplace_activation(&ask, owner)?;
        let at = vault.now_recorded_at();
        match vault.admit_marketplace_skill(&ask, scorer, TimeRange { start: at, end: at }, at)? {
            HubAdmissionDisposition::Ruled(receipt) if receipt.accepted => Some(*receipt),
            HubAdmissionDisposition::Ruled(receipt) => return Ok(SkillLibraryRestoreReceipt::Refused {
                entity: input.entity, admission: *receipt,
            }),
            HubAdmissionDisposition::PendingConsent => return Err(MemoryError::bad_request("restore needs current owner consent")),
        }
    } else {
        // The normal hub/fork activation gate refuses without its admission proof.
        lifecycle_as_owner(vault, owner, input.entity, SkillLifecycle::Active)?;
        None
    };
    Ok(SkillLibraryRestoreReceipt::Restored {
        skill: Box::new(skill_library_get_as_owner(vault, owner, &HubSkillRequest { entity: input.entity })?),
        admission,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillHashRuleRequest {
    pub content_hash: String,
    pub blocked: bool,
}

pub fn skill_hash_rule_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillHashRuleRequest,
) -> MemoryResult<HubConsentReceipt> {
    let hash = crate::skill::SkillContentHash::parse_hex(&input.content_hash)?;
    Ok(vault.set_marketplace_blocked_hash(owner, hash, input.blocked)?.into())
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillCodeAutoInstallRequest {
    pub enabled: bool,
}

pub fn skill_code_auto_install_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillCodeAutoInstallRequest,
) -> MemoryResult<HubConsentReceipt> {
    Ok(vault.set_marketplace_code_auto_install(owner, input.enabled)?.into())
}
