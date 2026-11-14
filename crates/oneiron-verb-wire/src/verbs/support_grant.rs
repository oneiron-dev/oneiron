//! Moved from `crates/oneiron/src/verbs/support_grant.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::support_grant::SupportGrantStatus;
use crate::authority::support_grant::SupportHolderClass;
use oneiron_authority::authority::CommReach;
use oneiron_authority::authority::SupportRepair;
use oneiron_authority::federation::Scope;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// `vault.support_grants.mint`'s input: the support PERSON, its class and
/// own public key, the exact bounds, and why.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantMintRequest {
    /// The support PERSON: a live person of this vault, no owner of it,
    /// that the owner selected or authored the ordinary way.
    pub holder: EntityId,
    /// `human` for a named support person, `agent` for a support agent.
    pub holder_class: SupportHolderClass,
    /// The support party's own Ed25519 public key, 64 hex. It keeps the
    /// private key; nothing delivers one.
    pub holder_key: String,
    /// The exact bounds: named worlds, no empty axis, a sensitivity ceiling.
    /// Its verbs axis names `propose` or `write` only when the owner
    /// selects them; bottom or `read` alone is read-only.
    pub scope: Scope,
    /// Exact records the grant reads; a relationship's rows open to support
    /// only when named here. Empty: every record inside `scope`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<EntityId>,
    /// Lifetime in seconds, 1..=86400; one hour when omitted. More time is
    /// a fresh mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Why the owner lets support in, 1..=256 bytes.
    pub purpose: String,
    /// The support ticket the visit serves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_ref: Option<String>,
    /// The owner's cap on whom the support holder may message (FIX 3899),
    /// signed into the slip: `parent`, `subtree`, `project` or `vault`.
    /// Outside a run, anything narrower than `vault` reaches the vault's
    /// owners only. Absent is `vault`; a wider reach later is a new mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<CommReach>,
    /// The repairs the owner lets the support holder run (FIX 4407), each
    /// by its own id; none when omitted. Naming them all still runs each
    /// alone, never the whole housekeeping pass.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub repairs: BTreeSet<SupportRepair>,
}

/// One support grant as the owner reviews it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantView {
    /// The grant's id: its slip id, 64 hex.
    pub grant_ref: String,
    pub holder: EntityId,
    pub holder_class: String,
    pub scope: Scope,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<String>,
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_ref: Option<String>,
    /// The owner PERSON who approved it (hex).
    pub approved_by: String,
    /// Recording time of the owner's mint (Unix seconds).
    pub approved_at: u64,
    /// The wall deadline (Unix seconds); the grant ends at it.
    pub wall_expires_at: u64,
    pub status: SupportGrantStatus,
    /// Whom the support holder may message (FIX 3899): the reach the owner
    /// set at mint, `vault` when he set none.
    pub comm: CommReach,
    /// The one-tap revoke command: `vault.support_grants.revoke`.
    pub revoke_command: String,
    /// The repairs the support holder may run (FIX 4407).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub repairs: BTreeSet<SupportRepair>,
}

/// `vault.support_grants.mint`'s answer: the credential for the support
/// party, who proves each request with their own key, and the grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantMintAnswer {
    /// The `v2.slip.` credential. It carries no private key.
    pub slip: String,
    pub grant: SupportGrantView,
    /// The Gate receipt of the owner's mint (hex).
    pub decision_ref: String,
}

/// `vault.support_grants.list`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantListRequest {
    /// Also list expired, revoked and ended grants.
    #[serde(default)]
    pub include_inactive: bool,
    /// At most this many, newest first; 500 when omitted, and never more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `vault.support_grants.list`'s answer, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantList {
    pub grants: Vec<SupportGrantView>,
}

/// `vault.support_grants.revoke`'s input: the grant, by its id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantRevokeRequest {
    /// The grant's id (its slip id), 64 hex.
    pub grant_ref: String,
}

/// `vault.support_grants.revoke`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantRevokeAnswer {
    pub grant_ref: String,
    pub holder: EntityId,
    /// False when the grant was already revoked and this call changed
    /// nothing.
    pub changed: bool,
    /// Recording time of this revoke; absent when it changed nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    /// The Gate receipt of this revoke (hex); absent when it changed nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_ref: Option<String>,
    /// Always false: what support already read, and outside effects already
    /// completed, are not recalled by a revoke.
    pub delivered_recallable: bool,
}
