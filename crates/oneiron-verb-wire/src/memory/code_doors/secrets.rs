//! Moved from `crates/oneiron/src/memory/code_doors/secrets.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::code_doors::*;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::critic_lens::LensCatalog;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Where a marked blob was seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeRepoSecretSeen {
    /// A pushed ref's move: the ref and the commit it moved to.
    RefMove { name: String, new_commit: String },
    /// The push's quarantine, with no proved ref.
    Quarantine,
    /// A translated sync copy edit landed the bytes on a marked source.
    SyncLanding,
}

/// One marked key, or one blob's opaque residue. No value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRepoSecretMark {
    pub mark: EntityId,
    /// The receive operation that marked it.
    pub operation: EntityId,
    /// The blob's Git OID.
    pub blob: String,
    /// The exact path, when the push named it.
    pub path: Option<String>,
    /// The detector's reason code, never an excerpt.
    pub kind: String,
    pub seen: CodeRepoSecretSeen,
    /// The custody record holding the key's value; absent for residue no
    /// span isolates, which is kept and marked whole.
    pub custody: Option<EntityId>,
    /// The handle the key stands as in a masked copy.
    pub handle: Option<String>,
    pub marked_at: u64,
}

/// One remediation linked to the repository: `offered` when a pushed
/// candidate carried marked files, `proposed` when a bundle was staged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRepoSecretRemediationLink {
    pub state: String,
    pub proposal: EntityId,
    pub commit: Option<String>,
    pub paths: Vec<String>,
    pub linked_at: u64,
}

/// A repository's marked keys and their remediations, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRepoSecretsView {
    pub repo: EntityId,
    pub marks: Vec<CodeRepoSecretMark>,
    pub remediations: Vec<CodeRepoSecretRemediationLink>,
}

/// Stages the remediation of one repository's current code. The engine
/// reads the current HEAD itself and attributes the bundle to this request
/// (`owner_request`): the caller names no session or provenance claim.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRepoSecretProposeRequest {
    /// An existing CODE_ARTIFACT naming a local repository.
    pub repo: EntityId,
    pub op_provenance: CodeOpProvenance,
    /// The owner's own review catalog for the bundle; omitted, the vault's
    /// review policy holds it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<LensCatalog>,
}

/// Where a remediation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeRepoSecretRemediationStatus {
    /// One bundle is staged and waits for its review.
    Proposed,
    /// Nothing could be staged; each marked key is an unresolved action.
    Unresolved,
    /// The base moved while the bundle was staged: nothing was written.
    Stale,
    /// No current file holds a marked key or a dotenv value.
    Clean,
}

/// One change the staged bundle makes. No value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum CodeRepoSecretRemediationAction {
    /// The marked literals of `path` now read these environment variables.
    ReplaceLiterals {
        path: String,
        env_names: Vec<String>,
    },
    /// A committed live dotenv file is removed.
    RemoveDotenv { path: String },
    /// An example file's marked values are blanked and these names added.
    WriteExample { path: String, names: Vec<String> },
    /// The ignore file gains these entries.
    IgnoreDotenv { entries: Vec<String> },
    /// The secret manifest maps these env names onto custody names.
    DeclareEnvNames { env_names: Vec<String> },
}

/// A key, or a file, the remediation leaves as it is, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRepoSecretUnresolved {
    pub path: String,
    /// The engine's reason code (`no_reference`, `container_member`, ...).
    pub reason: String,
    pub custody: Option<EntityId>,
}

/// What one remediation did. No value, span or excerpt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRepoSecretRemediation {
    pub repo: EntityId,
    pub status: CodeRepoSecretRemediationStatus,
    /// The HEAD it read.
    pub base_commit: String,
    /// The staged bundle (a `repo.proposed_diff` claim), when one is.
    pub proposal: Option<EntityId>,
    pub actions: Vec<CodeRepoSecretRemediationAction>,
    pub unresolved: Vec<CodeRepoSecretUnresolved>,
}
