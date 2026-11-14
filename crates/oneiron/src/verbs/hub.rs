//! Typed owner doors over configured hubs, foreign publishers and pinned imports.
//! Fetch, scanning, admission and hook authority stay in the existing hub engine.
use serde::{Deserialize, Serialize};

use crate::check_in::{AppliedCheckIn, CheckInDecision};
use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::runtime_hooks::HookGrant;
use crate::skill_hub::pack_catalog::{PackHookBinding, PackHookQualification, PackInstallReceipt};
use crate::skill_hub::{
    HubAdmissionReceipt, HubImportReceipt, HubRef, HubSyncDisposition, HubSyncPolicy, SkillHubKind,
    SkillHubRecord, SkillHubTrustTier, TrackedHubRef,
};
use crate::{EntityId, TimeRange, Vault};

use super::PackPutReceipt;

/// A configured hub's identity, never a fabricated source row.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillHubRequest {
    pub hub: EntityId,
}

/// The owner's configurable source. Trust changes presentation, not authority.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillHubPutRequest {
    pub hub: EntityId,
    pub kind: SkillHubKind,
    pub endpoint: String,
    pub trust_tier: SkillHubTrustTier,
    pub sync_policy: HubSyncPolicy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HubConsentOutcome {
    Approved,
    Denied,
    Revoked,
}

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

/// The publisher's offer-only authority is bounded to this one hub.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillPublisherRequest {
    pub hub: EntityId,
    pub identity: String,
}

/// `vault.skill_hubs.publishers.admit`'s request: the publisher and its one
/// hub, as [`SkillPublisherRequest`], and an approved check-in the owner
/// applies.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillPublisherAdmitRequest {
    pub hub: EntityId,
    pub identity: String,
    /// Another asker's approved check-in for this exact admission, 32 hex:
    /// the owner applies it on their own proof, and the admission's writer
    /// spends it (ROLES-CHECKIN 2k8). Omitted: the owner's own admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillPublisherAdmission {
    pub hub: EntityId,
    pub identity: String,
    pub grant_ref: String,
    /// The decision the admission ran on: the owner's own proof, naming the
    /// asker's approved check-in it applied (ROLES-CHECKIN 2k8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<CheckInDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HubRefRequest {
    pub hub: EntityId,
    pub ref_string: String,
}

/// Changes only the ref policy. Fetching and trusting are separate actions.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HubRefSetRequest {
    pub hub_ref: HubRef,
    pub sync_policy: HubSyncPolicy,
}

/// The exact pinned source to fetch, and its admitted foreign publisher.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HubImportRequest {
    pub hub_ref: HubRef,
    pub publisher: String,
}

/// `vault.skills.import`'s request: the pinned source and its publisher, as
/// [`HubImportRequest`], and an approved check-in the owner applies.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HubSkillImportRequest {
    pub hub_ref: HubRef,
    pub publisher: String,
    /// Another asker's approved check-in for this exact import, 32 hex: the
    /// owner applies it on their own proof, and the import's commit writer
    /// spends it (ROLES-CHECKIN 2k8). It needs a commit or content_hash pin,
    /// so the ask names the exact bytes. Omitted: the owner's own import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HubPackRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HubSkillRequest {
    pub entity: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HubSkillImported {
    pub entity: EntityId,
    /// The decision the import ran on: the owner's own proof, naming the
    /// asker's approved check-in it applied (ROLES-CHECKIN 2k8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<CheckInDecision>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HubSkillSyncOutcome {
    Applied,
    Proposed,
    RefusedByPolicy,
}

/// A proposal never changes the trusted content or effective capabilities.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HubSkillSyncReceipt {
    pub outcome: HubSkillSyncOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<crate::claim::ClaimApprovalStatus>,
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
#[serde(deny_unknown_fields)]
pub struct HubSkillProposalSettleRequest {
    pub entity: EntityId,
    pub proposal: EntityId,
    pub accept: bool,
}

/// Approved means the proposal's exact package landed; Rejected closes only
/// the proposal and leaves the working skill and its capabilities unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HubSkillProposalSettled {
    pub entity: EntityId,
    pub proposal: EntityId,
    pub approval: crate::claim::ClaimApprovalStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HubSkillReceipts {
    pub sources: Vec<HubRef>,
    pub imports: Vec<HubImportReceipt>,
    pub admission: Option<HubAdmissionReceipt>,
}

/// The source-specific permission ask the owner answers; no first-alias guess.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HubSkillPermissionRequest {
    pub entity: EntityId,
    pub hub_ref: HubRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HubHookQualifyRequest {
    pub source: EntityId,
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

/// One golden input of a verb hook, as the qualification ran it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HubHookGoldenRun {
    /// Its place in the hook's `golden.json`, from 0.
    pub index: usize,
    pub verb: String,
    /// The hook's selector took the call, so its body ran.
    pub ran: bool,
    /// The body returned the expected outcome.
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HubHookBindRequest {
    pub pack: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HubHookBindingRow {
    pub id: EntityId,
    pub binding: PackHookBinding,
    /// The owner's assignment, or the author's ceiling when none was set.
    pub grant: HookGrant,
}

/// The binding claim named by `vault.packs.hooks.list`, not its CODE id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookGrantRequest {
    pub binding: EntityId,
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

/// `vault.skill_hubs.publishers.admit`: the admission widens the publisher's
/// grant (ARCH-0082 #act-table "Widen another's grant"). The owner's own
/// admission goes on their own proof, never gated, and the answer records
/// that decision (`check_in`). With `check_in_ref` the owner applies another
/// asker's approved check-in for this exact admission: the mint's writer
/// spends it after the hub is read there, so a refusal leaves it eligible
/// and admits no one (ROLES-CHECKIN 2k8; Engine RULING P25-SHAPE Q1 = A).
///
/// # Errors
///
/// `BAD_REQUEST` for a malformed `check_in_ref`; no such hub; the mint's
/// refusals; a check-in that is not an approved ask for this admission.
pub fn skill_publisher_admit_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillPublisherAdmitRequest,
) -> MemoryResult<SkillPublisherAdmission> {
    let applied = match super::shared::check_in_ref(input.check_in_ref.as_deref())? {
        Some(id) => Some(AppliedCheckIn {
            id,
            verb: "vault.skill_hubs.publishers.admit",
            effect_digest: skill_publisher_admit_effect_digest(input)?,
        }),
        None => None,
    };
    let (publisher, decision) = vault.admit_skill_publisher_applying(
        owner,
        &input.identity,
        input.hub,
        applied.as_ref(),
    )?;
    Ok(SkillPublisherAdmission {
        hub: input.hub,
        identity: publisher.identity().to_owned(),
        grant_ref: publisher.grant_ref().to_owned(),
        check_in: decision,
    })
}

/// The digest of the owner's publisher admission `request`: the effect an
/// asker's `vault.check_in.open` names for
/// `vault.skill_hubs.publishers.admit`, and the one the admission spends
/// (2k8; P25-SHAPE Q1 = A). It is
/// [`crate::check_in::standing_grant_effect_digest`] over the one Grant the
/// admission mints: the publisher's offer from that hub.
///
/// # Errors
///
/// An identity the admission would refuse as malformed.
pub fn skill_publisher_admit_effect_digest(
    request: &SkillPublisherAdmitRequest,
) -> MemoryResult<[u8; 32]> {
    let bound = crate::skill_hub::skill_publisher_grant(&request.identity, request.hub)?;
    Ok(crate::check_in::standing_grant_effect_digest(&bound))
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

/// `vault.skills.import`: the import admits its publisher and lands the
/// skill behind the owner's fit (the verb's act, "Widen another's grant",
/// ARCH-0082 #act-table). The owner's own import goes on their own proof,
/// never gated, and the answer records that decision (`check_in`). With
/// `check_in_ref` the owner applies another asker's approved check-in for
/// this exact import: the source must be pinned to a commit or a content
/// hash, so the ask names the bytes, and the import's commit writer spends
/// it after every check of the commit, so a refusal leaves it eligible
/// (ROLES-CHECKIN 2k8; Engine RULING P25-SHAPE Q1 = A).
///
/// # Errors
///
/// `BAD_REQUEST` for a malformed `check_in_ref`, or one on a source pinned
/// by tag, semver or nothing; the import's refusals; a check-in that is not
/// an approved ask for this import.
pub fn hub_skill_import_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubSkillImportRequest,
) -> MemoryResult<HubSkillImported> {
    let applied = match super::shared::check_in_ref(input.check_in_ref.as_deref())? {
        Some(id) => {
            if !matches!(
                input.hub_ref.pin,
                crate::skill_hub::HubPin::Commit(_) | crate::skill_hub::HubPin::ContentHash(_)
            ) {
                return Err(MemoryError::bad_request(
                    "check_in_ref needs a commit or content_hash pin, so the ask names the exact bytes",
                ));
            }
            Some(AppliedCheckIn {
                id,
                verb: "vault.skills.import",
                effect_digest: hub_skill_import_effect_digest(input)?,
            })
        }
        None => None,
    };
    let (entity, decision) = vault.import_skill_from_hub_ref_applying(
        owner,
        input.hub_ref.hub_id,
        &input.hub_ref.ref_string,
        input.hub_ref.pin.clone(),
        &input.publisher,
        applied.as_ref(),
    )?;
    Ok(HubSkillImported {
        entity,
        check_in: Some(decision),
    })
}

/// The digest of the owner's hub skill import `request`: the effect an
/// asker's `vault.check_in.open` names for `vault.skills.import`, and the
/// one the import spends (2k8; P25-SHAPE Q1 = A). BLAKE3, key derived from
/// `oneiron check_in hub skill import v1`, over the request's MessagePack
/// encoding with field names, without its `check_in_ref`: the hub ref with
/// its pin, and the publisher.
///
/// # Errors
///
/// The request does not encode.
pub fn hub_skill_import_effect_digest(request: &HubSkillImportRequest) -> MemoryResult<[u8; 32]> {
    let import = HubSkillImportRequest {
        check_in_ref: None,
        ..request.clone()
    };
    let encoded = rmp_serde::to_vec_named(&import)
        .map_err(|_| crate::error::Error::InvariantViolation("hub skill import encode"))?;
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in hub skill import v1");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
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

/// Queries the public ClawHub-compatible API on a configured HTTP hub's origin.
/// Query metadata never grants trust or supplies a content hash for import.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClawHubSearchRequest {
    pub hub: EntityId,
    pub q: String,
    pub limit: Option<i64>,
    pub highlighted_only: Option<bool>,
    pub non_suspicious_only: Option<bool>,
    /// Defaults to the existing 2 MiB HTTP index budget; not sent upstream.
    pub response_limit_bytes: Option<usize>,
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
/// fetching and uses the normal publisher, fit, scan and import writer. The
/// owner's own import goes on their own proof, never gated, and an imported
/// answer records that decision (`check_in`). With `check_in_ref` the owner
/// applies another asker's approved check-in for this exact import: it
/// needs `expected_content_hash`, so the ask names the bytes, and the
/// import's commit writer spends it (ROLES-CHECKIN 2k8; Engine RULING
/// P25-2K8-SCOPE Q1 = A). A provider error spends nothing.
///
/// # Errors
///
/// `BAD_REQUEST` for a malformed `check_in_ref`, or one without
/// `expected_content_hash`, before any fetch; the import's refusals; a
/// check-in that is not an approved ask for this import.
pub fn skill_hub_clawhub_import_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &crate::skill_hub::ClawHubImportRequest,
) -> MemoryResult<crate::skill_hub::ClawHubImportReply> {
    let applied = match super::shared::check_in_ref(input.check_in_ref.as_deref())? {
        Some(id) => {
            if input.expected_content_hash.is_none() {
                return Err(MemoryError::bad_request(
                    "check_in_ref needs expected_content_hash, so the ask names the exact bytes",
                ));
            }
            Some(AppliedCheckIn {
                id,
                verb: "vault.skill_hubs.clawhub.import",
                effect_digest: clawhub_import_effect_digest(input)?,
            })
        }
        None => None,
    };
    Ok(vault.import_clawhub_skill(owner, input, applied.as_ref())?)
}

/// The digest of the owner's ClawHub import `request`: the effect an
/// asker's `vault.check_in.open` names for `vault.skill_hubs.clawhub.import`,
/// and the one the import spends (2k8; P25-2K8-SCOPE Q1 = A). BLAKE3, key
/// derived from `oneiron check_in clawhub import v1`, over the request's
/// MessagePack encoding with field names, without its `check_in_ref` and its
/// `response_limit_bytes`, a transport budget that pins nothing.
///
/// # Errors
///
/// The request does not encode.
pub fn clawhub_import_effect_digest(
    request: &crate::skill_hub::ClawHubImportRequest,
) -> MemoryResult<[u8; 32]> {
    let import = crate::skill_hub::ClawHubImportRequest {
        check_in_ref: None,
        response_limit_bytes: None,
        ..request.clone()
    };
    let encoded = rmp_serde::to_vec_named(&import)
        .map_err(|_| crate::error::Error::InvariantViolation("clawhub import encode"))?;
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in clawhub import v1");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}
