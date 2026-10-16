//! Typed inputs for the public memory verbs in the SDK inventory.
use crate::memory::{
    ClaimInput, Memory, MemoryError, MemoryResult, NeighborOpts, SafeDeleteReason,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitRequest {
    pub claims: Vec<ClaimInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimRefRequest {
    pub claim_ref: String,
}

/// Retraction by exact claim or by subject and predicate, never a hard delete.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ForgetRequest {
    Claim(ClaimRefRequest),
    Predicate(ForgetPredicateRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForgetPredicateRequest {
    pub subject_ref: String,
    pub predicate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SafeDeleteRequest {
    pub entity_ref: String,
    pub reason: SafeDeleteReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HydrateRequest {
    pub refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityRequest {
    pub entity_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryBm25Request {
    pub query: String,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NeighborsRequest {
    pub entity_ref: String,
    pub opts: NeighborOpts,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppendBlobVersionRequest {
    pub artifact_ref: String,
    /// RFC 4648 base64; the raw bytes still use the engine blob ceiling.
    pub content_base64: String,
    #[serde(default)]
    pub run_ref: Option<String>,
    pub occurred_at: u64,
    #[serde(default)]
    pub learned_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadBlobVersionRequest {
    pub artifact_ref: String,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateNoteRequest {
    pub kind: String,
    pub markdown: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateNoteFromEntityRequest {
    pub source_ref: String,
    pub kind: String,
}

pub(super) fn forget_claims(
    memory: &Memory<'_>,
    request: ForgetRequest,
) -> MemoryResult<Vec<crate::memory::CommitReceipt>> {
    let references = match request {
        ForgetRequest::Claim(request) => vec![request.claim_ref],
        ForgetRequest::Predicate(request) => {
            if request.predicate.trim().is_empty() {
                return Err(MemoryError::bad_request("forget requires a predicate"));
            }
            memory
                .claim_list(&crate::memory::ClaimListFilter {
                    subject_ref: Some(request.subject_ref),
                    predicate: Some(request.predicate),
                    lifecycle: Some("active".to_owned()),
                    limit: usize::MAX,
                })?
                .value
                .into_iter()
                .map(|claim| claim.claim_ref)
                .collect()
        }
    };
    references
        .iter()
        .map(|reference| memory.claim_retract(reference))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EditNoteRequest {
    pub note_ref: String,
    pub edit: crate::note::NoteProgramEdit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobContent {
    pub content_base64: String,
}

pub(super) fn append_blob(
    memory: &Memory<'_>,
    input: AppendBlobVersionRequest,
) -> MemoryResult<crate::memory::BlobVersionView> {
    use base64::Engine as _;
    if input.content_base64.len() > crate::memory::caps::MAX_BLOB_BASE64_LEN {
        return Err(MemoryError::bad_request(
            "blob base64 exceeds the content ceiling",
        ));
    }
    let content = base64::engine::general_purpose::STANDARD
        .decode(&input.content_base64)
        .map_err(|_| MemoryError::bad_request("invalid blob base64"))?;
    crate::memory::caps::check_blob_bytes(content.len())?;
    memory.append_blob_version(
        &input.artifact_ref,
        &content,
        input.run_ref.as_deref(),
        input.occurred_at,
        input.learned_at,
    )
}

pub(super) fn read_blob(
    memory: &Memory<'_>,
    input: ReadBlobVersionRequest,
) -> MemoryResult<Option<BlobContent>> {
    use base64::Engine as _;
    memory
        .read_blob_version(&input.artifact_ref, input.version)
        .map(|content| {
            content.map(|content| BlobContent {
                content_base64: base64::engine::general_purpose::STANDARD.encode(content),
            })
        })
}
