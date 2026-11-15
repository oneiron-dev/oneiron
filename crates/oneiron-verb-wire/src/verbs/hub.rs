//! Moved from `crates/oneiron/src/verbs/hub.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_hub::admission::HubAdmissionReceipt;
use crate::skill_hub::import_receipt::HubImportReceipt;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::skill_source::hub_record::HubRef;
use oneiron_store::write_envelope::skill_source::hub_record::HubSyncPolicy;
use oneiron_store::write_envelope::skill_source::hub_record::SkillHubKind;
use oneiron_store::write_envelope::skill_source::hub_record::SkillHubTrustTier;
use serde::Deserialize;
use serde::Serialize;

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

/// The publisher's offer-only authority is bounded to this one hub.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillPublisherRequest {
    pub hub: EntityId,
    pub identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillPublisherAdmission {
    pub hub: EntityId,
    pub identity: String,
    pub grant_ref: String,
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
    pub approval: Option<oneiron_contracts::claim::ClaimApprovalStatus>,
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
    pub approval: oneiron_contracts::claim::ClaimApprovalStatus,
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

/// The binding claim named by `vault.packs.hooks.list`, not its CODE id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookGrantRequest {
    pub binding: EntityId,
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
