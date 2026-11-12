//! Moved from `crates/oneiron/src/origin/secret_purge.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;

/// Plans a purge of one served repository.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSecretPurgeRequest {
    /// The served name, with no `.git` suffix.
    pub repo: String,
    /// The marks to purge, by id (`vault.code.secrets.get`); absent purges
    /// every readable mark.
    #[serde(default)]
    pub marks: Option<Vec<EntityId>>,
}

/// Names one purge plan.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSecretPurgeIdRequest {
    pub plan: EntityId,
}

/// One published ref the purge moves to its masked copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoSecretPurgeRefMove {
    pub ref_name: String,
    /// The object the ref names now.
    pub old_oid: String,
    /// Its masked copy, which the ref names after the execute.
    pub new_oid: String,
}

/// One keep-ref owner whose object reaches a purged blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoSecretPurgeKeepRoot {
    /// The owner's kind: `change`, `engine_export`, `conflict`,
    /// `snapshot`, `publish_request`, `mirror_work`, `publication` or
    /// `recovery`.
    pub kind: String,
    pub owner: String,
    /// The object it keeps.
    pub oid: String,
    /// Whether the execute releases it: a change-index owner, which keeps
    /// a published commit after its ref moves. Every other owner stays
    /// with the flow that holds it, and keeps its object.
    pub releases: bool,
}

/// What a purge never reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoSecretPurgeOutstanding {
    /// Vault backups and checkpoints taken before the purge keep the old
    /// objects.
    BackupsAndCheckpoints,
    /// Clones, forks and mirrors outside this vault keep them; no remote
    /// is pushed.
    OutsideCopies,
    /// Run and proposal working-copy snapshots keep the bytes they
    /// captured.
    RepoSnapshots,
    /// Code documents keep their stored text.
    CodeDocuments,
    /// LFS objects stay; the purge rewrites Git objects only.
    LfsObjects,
}

/// What one confirmation of a purge does, frozen when it was planned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoSecretPurgePlan {
    pub plan: EntityId,
    /// The owner who planned it; only that owner executes it.
    pub owner: EntityId,
    pub repo: String,
    /// The served store's id.
    pub store: EntityId,
    /// The marks it purges, sorted.
    pub marks: Vec<EntityId>,
    pub moves: Vec<RepoSecretPurgeRefMove>,
    /// The blobs whose bytes leave the store's history, sorted.
    pub purged_blobs: Vec<String>,
    /// How many trees, commits and tags are re-encoded above them: each
    /// gets a new object id.
    pub rewritten_objects: u64,
    /// How many signed commits and tags lose their signature.
    pub signatures_dropped: u64,
    pub keep_roots: Vec<RepoSecretPurgeKeepRoot>,
    pub outstanding: Vec<RepoSecretPurgeOutstanding>,
    pub planned_at: u64,
}

/// Where an executed purge ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoSecretPurgeState {
    /// Every ref moved and no purged blob is left in the served store.
    CompleteLocal,
    /// A ref did not move, or a purged blob is still in the store: a ref,
    /// a keep-ref or a worktree the plan does not move still reaches it.
    Partial,
    /// A published ref or a selected mark moved since the plan; nothing
    /// was done. Plan again.
    Stale,
}

/// One ref move as the execute left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoSecretPurgeRefOutcome {
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
    /// The ref names `new_oid`, published.
    pub moved: bool,
    /// Why the publication refused the move.
    pub failure: Option<String>,
}

/// The receipt of one executed plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoSecretPurgeReceipt {
    pub receipt: EntityId,
    pub plan: EntityId,
    pub state: RepoSecretPurgeState,
    pub refs: Vec<RepoSecretPurgeRefOutcome>,
    /// The keep-ref owners released.
    pub released: Vec<RepoSecretPurgeKeepRoot>,
    /// The purged blobs still in the store after collection.
    pub still_present: Vec<String>,
    pub outstanding: Vec<RepoSecretPurgeOutstanding>,
    pub executed_at: u64,
}

/// One plan and its receipt, once executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoSecretPurgeView {
    pub plan: RepoSecretPurgePlan,
    pub receipt: Option<RepoSecretPurgeReceipt>,
}
