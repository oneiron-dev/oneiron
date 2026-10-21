//! Account-local working views and immutable build results (ARCH-0050 / RC7).
use crate::EntityId;
use crate::code_view::VisibleFilePolicy;
use crate::memory::codebase_doors::RepoFileProjectionView;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeViewMaterializeRequest {
    pub repo: EntityId,
    /// A finalized CodeRevision with verified per-file tested frontiers.
    pub tested: EntityId,
    /// Expected account: the authenticated owner's PERSON id, not a grant.
    pub account: EntityId,
    pub policy: VisibleFilePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeViewRequest {
    pub view: EntityId,
    pub repo: EntityId,
    pub tested: EntityId,
    pub account: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeViewReadRequest {
    pub view: CodeViewRequest,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeViewFile {
    pub path: String,
    pub content_hash_blake3: String,
    /// The exact tested document identity and version vector, not a fabricated version ref.
    pub frontier: crate::code_document::CodeDocumentFrontier,
    pub text_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeWorkingView {
    pub view: EntityId,
    pub repo: EntityId,
    pub base: EntityId,
    pub account: EntityId,
    pub fork_hash: String,
    /// The immutable base file identities. Edits in this view do not change them.
    pub files: Vec<CodeViewFile>,
    pub receipt: EntityId,
    /// On the serving host only. It is not a client-side folder or authority.
    pub host_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeViewFileBytes {
    pub path: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
    /// How these bytes differ from the stored file a masked reader reads
    /// them for (FIX 7608): absent for the stored bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<RepoFileProjectionView>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeBuildClass {
    Build,
    Verify,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeSecretTaintRef {
    pub secret_ref: String,
    pub rotation_generation: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeBuildSpec {
    /// Native, owner-authorized build command. No shell or inherited environment is added.
    pub argv: Vec<String>,
    pub env_allowlist: BTreeMap<String, String>,
    /// Pin the toolchain and platform inputs here; undeclared outside state is not proved.
    pub platform: BTreeMap<String, String>,
    pub declared_outputs: Vec<String>,
    /// Declared consumption taint only. This call neither reveals nor injects a secret.
    pub secret_taint_refs: Vec<CodeSecretTaintRef>,
    pub class: CodeBuildClass,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeViewActionRequest {
    pub view: CodeViewRequest,
    pub spec: CodeBuildSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeActionDigest {
    /// SHA-256 of the engine's REAPI Action protobuf, in lower hex.
    pub hash: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeViewAction {
    pub action_digest: CodeActionDigest,
    /// Exact Command protobuf bytes and Directory digest for independent digest checks.
    pub command_bytes: Vec<u8>,
    pub input_root_digest: CodeActionDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeViewBuildRequest {
    pub view: CodeViewRequest,
    pub spec: CodeBuildSpec,
    /// Must still match the frozen current view before dispatch or reuse.
    pub action_digest: CodeActionDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeCacheReadRequest {
    pub account: EntityId,
    pub action_digest: CodeActionDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeBuildOutput {
    pub artifact_ref: String,
    pub output_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeBuildEntry {
    pub action_digest: CodeActionDigest,
    pub account: EntityId,
    pub exit_code: i32,
    pub outputs: BTreeMap<String, CodeBuildOutput>,
    pub stdout_ref: Option<String>,
    pub stderr_ref: Option<String>,
    pub secret_taint_refs: Vec<CodeSecretTaintRef>,
    pub reusable: bool,
    /// Original producer, including on a reuse. Never a caller-supplied receipt.
    pub receipt: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeCacheState {
    Hit,
    Miss,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeCacheOutcome {
    pub state: CodeCacheState,
    pub entry: Option<CodeBuildEntry>,
    /// Source build receipt on a hit; the transport also keeps this call's own receipt.
    pub receipt: Option<String>,
}

impl CodeBuildSpec {
    pub(crate) fn engine_taint_refs(&self) -> Vec<crate::secret_lease::SecretTaintRef> {
        self.secret_taint_refs
            .iter()
            .map(|taint| crate::secret_lease::SecretTaintRef {
                secret_ref: taint.secret_ref.clone(),
                generation: taint.rotation_generation,
            })
            .collect()
    }
}
