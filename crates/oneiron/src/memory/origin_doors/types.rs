//! Origin authority, checkout binding, export, publication, register and mirror records.
//! `OriginRepoRequest` is the first of its records.
//! These are local definitions; `memory::origin_doors` re-exports them.

use serde::{Deserialize, Serialize};

use crate::EntityId;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::origin_doors::types::{
    CheckoutDoorBindRequest, CheckoutDoorBinding, CodeExportRequest, CodeExportResult,
    OriginAuthoritySetRequest, OriginAuthorityView, OriginMirrorCleared, OriginMirrorSetRequest,
    OriginMirrorStrategyRequest, OriginMirrorView, OriginPublicationState, OriginPublicationView,
    OriginPublicationsRequest, OriginPublicationsView, OriginRegisterRequest, OriginRegistered,
    OriginRepoRequest,
};

/// `vault.code.origin.lfs_path_policy.set`: replaces one served origin's
/// ordered LFS path rules when its policy is at `expected_revision` (0 for
/// an origin whose owner never set one). An empty rule list sets the
/// default back: every path repository-large.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginLfsPathPolicySetRequest {
    /// The served name, with no `.git` suffix.
    pub repo: String,
    /// The revision the owner read: the set refuses a policy that moved.
    pub expected_revision: u64,
    /// First match wins; an unmatched path is repository-large.
    pub rules: Vec<crate::origin::lfs::OriginLfsPathRule>,
}

/// One served origin's LFS path policy, as stored.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginLfsPathPolicyView {
    pub repo: String,
    pub repo_id: EntityId,
    /// 0 for an origin whose owner never set a policy.
    pub revision: u64,
    pub rules: Vec<crate::origin::lfs::OriginLfsPathRule>,
    /// The class of a path no rule matches: always repository-large.
    pub default_class: crate::origin::lfs::LfsAssetClass,
}
