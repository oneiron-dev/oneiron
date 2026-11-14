//! Moved from `crates/oneiron/src/memory/repo_doors/custody.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::origin_doors::types::OriginPublicationState;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `self.code.checkout.bind`: materializes the run's own live checkout
/// lease of the admitted repo's served store, through the unchanged GitWire
/// port. The lease is one the run's actor holds for the run's TASK; no
/// lease is minted here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoCheckoutBindInput {
    /// The CODE anchor the run's Grant admits; its stored repo is the
    /// served store.
    pub repo: EntityId,
    /// The full Git ref the run edits through this checkout.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The checkout id, 32 lower-hex characters.
    pub checkout: String,
    /// The live lease epoch.
    pub epoch: u64,
    /// The door base the checkout's remote points at, ending in `/git`:
    /// HTTPS, or HTTP on loopback only. It grants nothing and selects no
    /// object store; with none the worktree gets no remote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// `self.code.checkout.bind`'s answer. No host path is shown.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoCheckoutBindOutput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub checkout: String,
    pub epoch: u64,
    /// `<endpoint>/lease/<checkout>.<epoch>/<repo>.git`, the worktree's
    /// fetch and push URL, when an endpoint was named. It holds a
    /// redemption right only; every request still needs the holder's
    /// credential and the run's Grant.
    pub remote_url: Option<String>,
}

/// `self.code.export`: one finalized, promoted CodeRevision exported from
/// the run's own materialized checkout through the unchanged engine export
/// and origin publication protocol. The engine regenerates every byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoExportInput {
    pub repo: EntityId,
    /// The full ref to advance, such as `refs/heads/main`.
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub checkout: String,
    pub epoch: u64,
    /// The finalized, promoted CodeRevision.
    pub revision: EntityId,
    /// The value the advance is decided against; `None` means the ref must
    /// not exist yet. It is never discovered for the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_old_oid: Option<String>,
}

/// `self.code.export`'s answer: what the publication protocol decided.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoExportOutput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub revision: EntityId,
    pub git_commit: String,
    /// The publication id.
    pub receipt: EntityId,
    pub status: OriginPublicationState,
    /// The one Grant the publication policy admitted the export under.
    pub grant: EntityId,
    pub ref_was_already_applied: bool,
    pub wire_replayed: bool,
    pub wire_rejected: bool,
}
