//! Typed inputs for the public memory verbs in the SDK inventory.
use crate::claim::{ScopedReadReceipt, ScopedReadResult};
use crate::memory::{
    ClaimInput, LexicalHit, Memory, MemoryError, MemoryResult, NeighborOpts, RecallResidence,
    SafeDeleteReason,
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

/// `vault.search.bm25`'s answer (FIX 3876): this device's own scoped hits
/// with their read's receipt, and on a device that syncs only what it
/// opened, what its home holds beside them. A server's door asks the home
/// under the call's own caller; an embedded handle never asks it, so its
/// answer there is local-only and incomplete. `None`: the device holds
/// every window it may read, or runs no sync.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bm25Search {
    /// Hits, in engine score order.
    pub value: Vec<LexicalHit>,
    /// The read's receipt.
    #[serde(rename = "narrowing")]
    pub receipt: ScopedReadReceipt,
    /// The home's references the page does not hold, apart from its hits;
    /// a hit's window opens it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residence: Option<RecallResidence>,
}

impl Bm25Search {
    /// `page`, this device's own, as the device answers it alone: whole,
    /// or local-only and incomplete on one that syncs only what it opened.
    #[must_use]
    pub fn local(vault: &crate::Vault, page: ScopedReadResult<Vec<LexicalHit>>) -> Self {
        #[cfg(feature = "sync")]
        let opened = matches!(
            vault.device_residence(),
            crate::sync::DeviceResidence::Opened { .. }
        );
        #[cfg(not(feature = "sync"))]
        let opened = {
            let _ = vault;
            false
        };
        Self {
            value: page.value,
            receipt: page.receipt,
            residence: opened.then(RecallResidence::local_only),
        }
    }
}

/// `vault.search.bm25` on a handle: its own BM25 page, as the device
/// answers it alone ([`Bm25Search::local`]).
pub fn search_bm25(memory: &Memory<'_>, input: QueryBm25Request) -> MemoryResult<Bm25Search> {
    let page = memory.query_bm25(&input.query, input.limit)?;
    Ok(Bm25Search::local(memory.vault(), page))
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

/// An opinion's subject or claim, named by short ref or 32-hex id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthorTakeTarget {
    /// Links the NOTE to a subject with `about`.
    Subject(String),
    /// Links the NOTE to a CLAIM with `claim_of`; the engine checks its type.
    Claim(String),
}

/// `vault.notes.author_take`: attribution comes only from the bound caller.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorTakeRequest {
    pub target: AuthorTakeTarget,
    pub markdown: String,
}

pub(super) fn author_take(
    memory: &Memory<'_>,
    input: AuthorTakeRequest,
) -> MemoryResult<crate::memory::EntityRefReceipt> {
    let resolve = |reference: &str| crate::memory::resolve_entity_ref(memory.vault(), reference);
    let target = match input.target {
        AuthorTakeTarget::Subject(reference) => {
            crate::note::TakeTarget::Subject(resolve(&reference)?)
        }
        AuthorTakeTarget::Claim(reference) => crate::note::TakeTarget::Claim(resolve(&reference)?),
    };
    memory.author_take(target, input.markdown)
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

/// `vault.consolidation.enqueue`'s input (OF-237): one Dreamer consolidation
/// attempt, as [`crate::memory::ConsolidationAttemptInput`] takes it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationEnqueueRequest {
    /// `micro`, `meso` or `macro`.
    pub scope: String,
    /// The attempt's opaque input.
    pub input: serde_json::Value,
    #[serde(default)]
    pub run_id: Option<String>,
    /// Advisory: coalesces onto an existing attempt, never a lock.
    #[serde(default)]
    pub dedupe_key: Option<String>,
    /// Unix seconds; omitted, now.
    #[serde(default)]
    pub now: Option<u64>,
}

/// `vault.consolidation.status`'s input: the job ref an enqueue returned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationStatusRequest {
    pub job_ref: String,
}

pub(super) fn enqueue_consolidation(
    memory: &Memory<'_>,
    input: ConsolidationEnqueueRequest,
) -> MemoryResult<crate::memory::DreamerAttemptRef> {
    memory.enqueue_consolidation(&crate::memory::ConsolidationAttemptInput {
        scope: input.scope,
        input: input.input,
        run_id: input.run_id,
        dedupe_key: input.dedupe_key,
        now: input.now,
    })
}

/// A status read is the bound actor's: its binding is proved before the
/// queue is read.
pub(super) fn dreamer_attempt_status(
    memory: &Memory<'_>,
    input: ConsolidationStatusRequest,
) -> MemoryResult<Option<crate::memory::DreamerAttemptView>> {
    crate::memory::verify_actor_binding(memory.vault(), memory.actor(), memory.actor_class())?;
    memory.dreamer_attempt_status(&input.job_ref)
}

/// A wake read is the bound actor's, as its status sibling is (DOOR-144 B):
/// its binding is proved before one page of the addressed attempt's or
/// pass's observation is read.
pub(super) fn dreamer_wake_status(
    memory: &Memory<'_>,
    input: crate::memory::ConsolidationWakeStatusRequest,
) -> MemoryResult<Option<crate::memory::DreamerWakeView>> {
    crate::memory::verify_actor_binding(memory.vault(), memory.actor(), memory.actor_class())?;
    memory.dreamer_wake_status(&input)
}

/// Each claim through its own gate, forced proposed: one landed receipt or
/// typed refusal per claim, never one all-or-nothing batch.
pub(super) fn seed_claims(
    memory: &Memory<'_>,
    input: CommitRequest,
) -> MemoryResult<Vec<crate::memory::CommitOutcome>> {
    memory.seed_claims(&input.claims)
}
