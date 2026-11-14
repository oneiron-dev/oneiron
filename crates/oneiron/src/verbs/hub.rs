//! Typed owner doors over configured hubs, foreign publishers and pinned imports.
//! Fetch, scanning, admission and hook authority stay in the existing hub engine.
use serde::{Deserialize, Serialize};

use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::memory::{Memory, MemoryResult};
use crate::runtime_hooks::HookGrant;
use crate::skill_hub::pack_catalog::{PackHookBinding, PackHookQualification, PackInstallReceipt};
use crate::skill_hub::{HubSyncDisposition, SkillHubKind, SkillHubRecord, TrackedHubRef};
use crate::{EntityId, TimeRange, Vault};

use super::PackPutReceipt;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::hub::{
    ClawHubSearchRequest, HookGrantRequest, HubConsentOutcome, HubHookBindRequest,
    HubHookGoldenRun, HubHookQualifyRequest, HubImportRequest, HubPackRequest, HubRefRequest,
    HubRefSetRequest, HubSkillImported, HubSkillPermissionRequest, HubSkillProposalSettleRequest,
    HubSkillProposalSettled, HubSkillReceipts, HubSkillRequest, HubSkillSyncOutcome,
    HubSkillSyncReceipt, SkillHubPutRequest, SkillHubRequest, SkillPublisherAdmission,
    SkillPublisherRequest,
};

/// The actual engine consent decision, not an inferred successful HTTP status.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HubConsentReceipt {
    pub outcome: HubConsentOutcome,
    pub decision: String,
    pub grant_ref: Option<String>,
}

impl From<ConsentReceipt> for HubConsentReceipt {
    fn from(receipt: ConsentReceipt) -> Self {
        let outcome = match &receipt {
            ConsentReceipt::Denied { .. } => HubConsentOutcome::Denied,
            ConsentReceipt::Revoked { .. } => HubConsentOutcome::Revoked,
            _ => HubConsentOutcome::Approved,
        };
        Self {
            outcome,
            decision: receipt
                .decision_id()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            grant_ref: crate::consent::consent_receipt_grant_ref(&receipt),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillHubConfigured {
    pub hub: EntityId,
    pub consent: HubConsentReceipt,
}

impl From<HubSyncDisposition> for HubSkillSyncReceipt {
    fn from(disposition: HubSyncDisposition) -> Self {
        match disposition {
            HubSyncDisposition::Applied => Self {
                outcome: HubSkillSyncOutcome::Applied,
                proposal: None,
                approval: None,
            },
            HubSyncDisposition::Proposed {
                proposal_id,
                approval,
            } => Self {
                outcome: HubSkillSyncOutcome::Proposed,
                proposal: Some(proposal_id),
                approval: Some(approval),
            },
            HubSyncDisposition::RefusedByPolicy => Self {
                outcome: HubSkillSyncOutcome::RefusedByPolicy,
                proposal: None,
                approval: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HubHookQualificationReceipt {
    pub put: PackPutReceipt,
    pub replays: Vec<HubHookReplay>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HubHookReplay {
    pub hook: String,
    pub entries: Vec<super::HookReplayRow>,
    /// The test did not replay this hook in full: no entry, or an entry's
    /// inputs are gone. The verdict still stands.
    pub unreplayed: bool,
    /// Each golden input the pack declares for this verb hook, run once.
    pub golden: Vec<HubHookGoldenRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HubHookBindingRow {
    pub id: EntityId,
    pub binding: PackHookBinding,
    /// The owner's assignment, or the author's ceiling when none was set.
    pub grant: HookGrant,
}

/// The owner sets or changes a binding's read grant. This does not change
/// the author whose authority its outcomes run under.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookGrantSetRequest {
    pub binding: EntityId,
    pub grant: HookGrant,
}

/// The effective grant of one live binding, including its default when no
/// manual grant has been assigned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookGrantView {
    pub binding: EntityId,
    pub grant: HookGrant,
}

pub fn skill_hub_put_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillHubPutRequest,
) -> MemoryResult<SkillHubConfigured> {
    let record = SkillHubRecord::new(
        input.kind,
        &input.endpoint,
        input.trust_tier,
        input.sync_policy,
    )?;
    let at = vault.now_recorded_at();
    let consent = vault.configure_skill_hub(
        owner,
        &input.hub,
        &record,
        TimeRange { start: at, end: at },
        at,
    )?;
    Ok(SkillHubConfigured {
        hub: input.hub,
        consent: consent.into(),
    })
}

pub fn skill_hub_get_as_owner(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: &SkillHubRequest,
) -> MemoryResult<SkillHubRecord> {
    Ok(vault.skill_hub_record(&input.hub)?)
}

pub fn skill_publisher_admit_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillPublisherRequest,
) -> MemoryResult<SkillPublisherAdmission> {
    let publisher = vault.admit_skill_publisher(owner, &input.identity, input.hub)?;
    Ok(SkillPublisherAdmission {
        hub: input.hub,
        identity: publisher.identity().to_owned(),
        grant_ref: publisher.grant_ref().to_owned(),
    })
}

pub fn skill_publisher_revoke_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillPublisherRequest,
) -> MemoryResult<HubConsentReceipt> {
    Ok(vault
        .revoke_skill_publisher(owner, &input.identity, input.hub)?
        .into())
}

pub fn hub_ref_get_as_owner(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: &HubRefRequest,
) -> MemoryResult<Option<TrackedHubRef>> {
    Ok(vault.hub_ref_sync(&input.hub, &input.ref_string)?)
}

pub fn hub_ref_set_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubRefSetRequest,
) -> MemoryResult<TrackedHubRef> {
    Ok(vault.set_hub_ref_sync(owner, input.hub_ref.clone(), input.sync_policy)?)
}

pub fn hub_pack_install_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubImportRequest,
) -> MemoryResult<PackPutReceipt> {
    Ok(vault
        .install_pack_from_hub(
            owner,
            input.hub_ref.hub_id,
            &input.hub_ref.ref_string,
            input.hub_ref.pin.clone(),
            &input.publisher,
        )?
        .into())
}

pub fn hub_pack_sync_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubPackRequest,
) -> MemoryResult<PackPutReceipt> {
    Ok(vault.sync_pack_from_hub(owner, &input.name)?.into())
}

pub fn hub_pack_get_as_owner(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: &HubPackRequest,
) -> MemoryResult<Option<PackInstallReceipt>> {
    Ok(vault.installed_pack(&input.name)?)
}

pub fn hub_skill_import_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubImportRequest,
) -> MemoryResult<HubSkillImported> {
    Ok(HubSkillImported {
        entity: vault.import_skill_from_hub_ref(
            owner,
            input.hub_ref.hub_id,
            &input.hub_ref.ref_string,
            input.hub_ref.pin.clone(),
            &input.publisher,
        )?,
    })
}

pub fn hub_skill_sync_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubSkillRequest,
) -> MemoryResult<HubSkillSyncReceipt> {
    Ok(vault.sync_skill_from_hub_ref(owner, &input.entity)?.into())
}

pub fn hub_skill_proposal_settle_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubSkillProposalSettleRequest,
) -> MemoryResult<HubSkillProposalSettled> {
    let approval =
        vault.settle_hub_update_proposal(owner, &input.entity, &input.proposal, input.accept)?;
    Ok(HubSkillProposalSettled {
        entity: input.entity,
        proposal: input.proposal,
        approval,
    })
}

pub fn hub_skill_receipts_as_owner(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: &HubSkillRequest,
) -> MemoryResult<HubSkillReceipts> {
    hub_skill_receipts(vault, input)
}

/// [`hub_skill_receipts_as_owner`]'s read, which asks no proof of its own:
/// for a library view whose door admitted its reader (FIX 8167).
pub(crate) fn hub_skill_receipts(
    vault: &Vault,
    input: &HubSkillRequest,
) -> MemoryResult<HubSkillReceipts> {
    let sources = vault.skill_hub_sources(&input.entity)?;
    let mut imports = Vec::new();
    for source in &sources {
        if let Some(receipt) = vault.hub_import_receipt(&input.entity, source)? {
            imports.push(receipt);
        }
    }
    Ok(HubSkillReceipts {
        sources,
        imports,
        admission: vault.hub_admission_receipt(&input.entity)?,
    })
}

pub fn hub_skill_permissions_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubSkillPermissionRequest,
) -> MemoryResult<HubConsentReceipt> {
    let at = vault.now_recorded_at();
    Ok(vault
        .approve_marketplace_permission_ask(
            owner,
            &input.entity,
            &input.hub_ref,
            TimeRange { start: at, end: at },
            at,
        )?
        .into())
}

pub fn hub_hooks_bind_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubHookBindRequest,
) -> MemoryResult<Vec<EntityId>> {
    Ok(vault.bind_pack_hooks(owner, &input.pack)?)
}

pub fn hub_hooks_list_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &super::EmptyRequest,
) -> MemoryResult<Vec<HubHookBindingRow>> {
    owner.revalidate(vault)?;
    Ok(vault
        .pack_hook_bindings_with_grants()?
        .into_iter()
        .map(|(id, binding, grant)| HubHookBindingRow { id, binding, grant })
        .collect())
}

pub fn hook_grant_set_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HookGrantSetRequest,
) -> MemoryResult<HookGrantView> {
    vault.set_hook_grant(owner, input.binding, input.grant.clone())?;
    Ok(HookGrantView {
        binding: input.binding,
        grant: input.grant.clone(),
    })
}

pub fn hook_grant_get_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HookGrantRequest,
) -> MemoryResult<HookGrantView> {
    owner.revalidate(vault)?;
    Ok(HookGrantView {
        binding: input.binding,
        grant: vault.effective_hook_grant(input.binding)?,
    })
}

pub fn hub_hooks_qualify_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    runtime: &dyn crate::runtime_hooks::HookBodyRuntime,
    input: &HubHookQualifyRequest,
) -> MemoryResult<HubHookQualificationReceipt> {
    let qualified = vault.qualify_pack_hooks(owner, runtime, input.source)?;
    Ok(qualification_receipt(qualified))
}

/// [`hub_hooks_qualify_as_owner`], beside the rows its answer is read from
/// ([`Vault::qualify_pack_hooks_listing`]): the pack source and every row
/// each hook's listing replay lists. Every listed row is named; an empty
/// list means no rows.
///
/// # Errors
/// As [`hub_hooks_qualify_as_owner`].
pub fn hub_hooks_qualify_as_owner_listing(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    runtime: &dyn crate::runtime_hooks::HookBodyRuntime,
    input: &HubHookQualifyRequest,
) -> MemoryResult<(HubHookQualificationReceipt, Vec<EntityId>)> {
    let (qualified, rows) = vault.qualify_pack_hooks_listing(owner, runtime, input.source)?;
    Ok((qualification_receipt(qualified), rows))
}

/// A hook pack's test as its wire receipt.
fn qualification_receipt(qualified: PackHookQualification) -> HubHookQualificationReceipt {
    HubHookQualificationReceipt {
        put: qualified.disposition.into(),
        replays: qualified
            .replays
            .into_iter()
            .map(|replay| HubHookReplay {
                hook: replay.hook,
                entries: replay
                    .entries
                    .into_iter()
                    .map(super::HookReplayRow::from)
                    .collect(),
                unreplayed: replay.unreplayed,
                golden: replay
                    .golden
                    .into_iter()
                    .map(|run| HubHookGoldenRun {
                        index: run.index,
                        verb: run.verb,
                        ran: run.result.is_some(),
                        passed: run.passed,
                    })
                    .collect(),
            })
            .collect(),
    }
}

pub fn hub_hooks_qualify_embedded(
    memory: &Memory<'_>,
    input: &HubHookQualifyRequest,
) -> MemoryResult<HubHookQualificationReceipt> {
    let _owner = memory.embedded_owner("vault.packs.hooks.qualify")?;
    super::host_only(memory, "vault.packs.hooks.qualify", input)
}

pub fn skill_hub_clawhub_search_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ClawHubSearchRequest,
) -> MemoryResult<crate::skill_hub::ClawHubSearchReply> {
    owner.revalidate(vault)?;
    let hub = vault.skill_hub_record(&input.hub)?;
    if hub.kind != SkillHubKind::HttpIndex {
        return Err(crate::memory::MemoryError::bad_request(
            "ClawHub search requires a configured HTTP hub",
        ));
    }
    let adapter = crate::skill_hub::HttpEndpointSkillHubAdapter::new(input.hub, &hub.endpoint)?;
    Ok(adapter.search_clawhub(
        &input.q,
        input.limit,
        input.highlighted_only,
        input.non_suspicious_only,
        input.response_limit_bytes,
    )?)
}

/// Explicit owner-selected import; the native door revalidates the proof before
/// fetching and uses the normal publisher, fit, scan and import writer.
pub fn skill_hub_clawhub_import_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &crate::skill_hub::ClawHubImportRequest,
) -> MemoryResult<crate::skill_hub::ClawHubImportReply> {
    Ok(vault.import_clawhub_skill(owner, input)?)
}
