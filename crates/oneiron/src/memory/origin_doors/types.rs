//! Origin authority, checkout binding, export, publication, register and mirror records.
//! `OriginRepoRequest` is the first of its records.
//! These are local definitions; `memory::origin_doors` re-exports them.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::origin::residence::{OriginAuthority, OriginResidence};

/// One served repository, by the name its `/git/{repo}` route serves.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginRepoRequest {
    /// The served name, with no `.git` suffix.
    pub repo: String,
}

/// The owner cutover of one existing served repository. It installs the next
/// authority epoch; it never creates a repository.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginAuthoritySetRequest {
    pub repo: String,
    /// The epoch the owner read; `None` for a repository with no authority
    /// yet. A cutover whose epoch moved since is refused.
    pub expected_epoch: Option<u64>,
    pub residence: OriginResidence,
    /// The writer host machine id; this install machine when absent.
    pub writer: Option<String>,
    /// This copy serves reads only, at every ref.
    #[serde(default)]
    pub mirror: bool,
}

/// One served repository authority and the host reading it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginAuthorityView {
    pub repo: String,
    /// This install machine: the writer to name to make this host the
    /// origin. `None` before the install has a machine id.
    pub host: Option<String>,
    /// `None`: no cutover yet, so this vault is the origin with no lease.
    pub authority: Option<OriginAuthority>,
}

/// Materializes a live checkout lease the caller holds on a served
/// repository. No lease is minted here: `checkout` and `epoch` name one that
/// exists.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckoutDoorBindRequest {
    pub repo: String,
    /// The checkout id, 32 lower-hex characters.
    pub checkout: String,
    /// The live lease epoch.
    pub epoch: u64,
    /// The door base the checkout remote points at, ending in `/git`: HTTPS,
    /// or HTTP on loopback only, with no credential, query or fragment.
    pub endpoint: String,
}

/// The owned checkout, with its lease-bound remote. It holds a redemption
/// right only; every request still needs the credential of the holder.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckoutDoorBinding {
    pub repo: String,
    pub checkout: String,
    pub epoch: u64,
    /// The engine-owned worktree the lease materialized.
    pub checkout_path: String,
    /// `<endpoint>/lease/<checkout>.<epoch>/<repo>.git`, as both the fetch
    /// and push URL of the worktree.
    pub remote_url: String,
}

/// Exports one finalized, promoted CodeRevision through the origin
/// publication protocol, from a live checkout of `repo` the caller holds.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeExportRequest {
    pub repo: String,
    /// The checkout id, 32 lower-hex characters.
    pub checkout: String,
    /// The live lease epoch.
    pub epoch: u64,
    /// The finalized CodeRevision.
    pub revision: EntityId,
    /// The full ref to advance, such as `refs/heads/main`.
    pub ref_name: String,
    /// The value the advance is decided against; `None` means the ref must
    /// not exist yet. It is never discovered for the caller.
    pub expected_old_oid: Option<String>,
    /// The door base the returned clone URL names, ending in `/git`.
    pub endpoint: String,
}

/// What the publication protocol decided for one export. The record status
/// and the wire flags are what the engine wrote, not a client acknowledgement.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeExportResult {
    pub revision: EntityId,
    pub git_commit: String,
    /// `<endpoint>/<repo>.git`.
    pub remote_url: String,
    /// The publication id.
    pub receipt: EntityId,
    pub publication: OriginPublicationView,
    /// The repository already carried the commit before this call.
    pub ref_was_already_applied: bool,
    /// The git wire answered from a durable record without re-running it.
    pub wire_replayed: bool,
    /// The git wire refused the ref effect this call drove.
    pub wire_rejected: bool,
}

/// One served repository ref at one commit.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginPublicationsRequest {
    pub repo: String,
    /// The full ref name.
    pub ref_name: String,
    /// The commit the ref was advanced to, 40 lower-hex characters.
    pub git_commit: String,
}

/// Every durable publication of that ref to that commit, in every status,
/// ordered by publication id. Historical `published` is not current
/// advertisement; a fresh clone proves that.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginPublicationsView {
    pub repo: String,
    pub publications: Vec<OriginPublicationView>,
}

/// Where one publication stands, as its journal row records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginPublicationState {
    Prepared,
    Published,
    Failed,
    Conflicted,
}

/// One durable publication record.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginPublicationView {
    /// The publication id.
    pub receipt: EntityId,
    /// The object-store-derived repository id.
    pub repo_id: EntityId,
    pub ref_name: String,
    pub git_commit: String,
    /// The source the publication descends from: the export intent or the
    /// receive-pack admission claim. Not the CodeRevision provenance.
    pub provenance_receipt: EntityId,
    /// The `repo.publication` claim, once one landed.
    pub publication_claim: Option<EntityId>,
    /// The principal behind the advance; `None` once erased.
    pub actor: Option<EntityId>,
    pub status: OriginPublicationState,
    pub failure: Option<String>,
    pub created_at: u64,
    pub finished_at: Option<u64>,
}

/// Registers a new, empty repository for smart-HTTP and vault-LFS. The first
/// authenticated push publishes its content; this call imports no host path.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginRegisterRequest {
    /// The served name, with no `.git` suffix.
    pub repo: String,
    /// The short branch name HEAD points at, such as `main`. Required: no
    /// ambient Git init.defaultBranch setting decides the repository's HEAD.
    pub default_branch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginRegistered {
    pub repo: String,
    /// The object-store-derived repository id, also used by vault-LFS.
    pub repo_id: EntityId,
    pub default_branch: String,
}

/// The owner's outbound mirror setup. The token is already in custody,
/// bound to `origin:mirror-push`; this request never carries its value.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginMirrorSetRequest {
    pub repo: String,
    /// HTTPS, with no credential, query or fragment.
    pub url: String,
    pub secret_ref: String,
    /// `x-access-token` when absent.
    pub user: Option<String>,
    /// At least 60 seconds; the configured cadence is the mirror's RPO.
    pub every_secs: u64,
    /// `ask_me`, `schedule` or `full_auto`. Absent: the same URL keeps its
    /// strategy, and a new mirror or URL asks first (`ask_me`).
    #[serde(default)]
    pub sync_strategy: Option<crate::origin::mirror_strategy::OriginMirrorSyncStrategy>,
}

/// The owner's change of one mirror's sync strategy. It changes nothing
/// else: never the URL, the custody record, the cadence or what was pushed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginMirrorStrategyRequest {
    pub repo: String,
    pub sync_strategy: crate::origin::mirror_strategy::OriginMirrorSyncStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorView {
    pub repo: String,
    pub mirror: Option<crate::origin::mirror::OriginMirrorTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorCleared {
    pub repo: String,
    /// The remote retains the refs and bytes it already holds.
    pub cleared: bool,
}
