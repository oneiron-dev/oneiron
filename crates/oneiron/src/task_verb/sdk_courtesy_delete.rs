//! The inputs and answers of the owner's courtesy delete rows (OF-273,
//! ARCH-0043 #relationship-lifecycle): `vault.courtesy_delete.send`,
//! `.sent`, `.incoming` and `.answer`, each a host door over the engine
//! calls and owner proof `/v1/owner/courtesy-delete/*` takes. A server signs
//! an ask or an answer with its own authority key and delivers it through
//! its courtesy outbox; an embedded handle has neither, so it refuses
//! ([`courtesy_delete_host_only`]). A former peer's signed ask and answer
//! (`/v1/federation/courtesy-delete*`) are peer HTTP, never a verb.
use serde::{Deserialize, Serialize};

use crate::deletion::CooperativeDeletionDispositionKind;
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};

/// `vault.courtesy_delete.send`'s input: the ended pact, the worlds to ask
/// about, and the former peer's host.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CourtesyDeleteSendRequest {
    /// The ended pact, as 64 hex.
    pub pact: String,
    /// The worlds to ask about, as 32 hex; none asks about all the pact
    /// delivered.
    #[serde(default)]
    pub worlds: Vec<String>,
    /// Content up to this pact epoch; by default, the epoch the pact ended at.
    #[serde(default)]
    pub epoch_cutoff: Option<u64>,
    /// The former peer's host origin, `https://host[:port]`.
    pub peer: String,
    /// The ask already signed by the key the peer pinned, base64, when that
    /// key is not this host's. `worlds` and `epoch_cutoff` are then the ask's.
    #[serde(default)]
    pub signed: Option<String>,
}

/// One ask this vault sent, as its outbox holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CourtesyDeleteSent {
    /// The ask's request id, as 32 hex.
    pub request: String,
    /// The ended pact, as 64 hex.
    pub pact: String,
    pub recipient: String,
    /// Its delivery status.
    pub status: String,
    /// RFC 3339.
    pub created: String,
    /// RFC 3339.
    pub updated: String,
}

/// `vault.courtesy_delete.answer`'s input: the owner's choice on one ask a
/// former peer sent.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CourtesyDeleteAnswerRequest {
    /// The pact the ask came under, as 64 hex.
    pub pact: String,
    /// The ask's request id, as 32 hex.
    pub request: String,
    /// `delete`, `redact`, `restrict_pending_review`, `retain_under_basis`,
    /// `legal_hold` or `decline`.
    #[schemars(with = "String")]
    pub choice: CooperativeDeletionDispositionKind,
    /// A short snake_case reason code, for any choice but delete.
    #[serde(default)]
    pub reason_code: Option<String>,
    /// When a choice other than delete comes up for review, unix seconds.
    #[serde(default)]
    pub review_at: Option<u64>,
    /// Under a delete choice, the records to hard-delete, as 32 hex.
    #[serde(default)]
    pub delete: Vec<String>,
    /// Under a legal hold choice, the records to hold, as 32 hex.
    #[serde(default)]
    pub hold: Vec<String>,
    /// The requester's host origin, to send the answer back; without it the
    /// answer stays on this side.
    #[serde(default)]
    pub reply_to: Option<String>,
}

/// One world an incoming ask names, with its stale stamp when the pact's
/// end already stopped its refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CourtesyDeleteAskedWorld {
    pub world: String,
    pub stale: Option<String>,
    pub stale_epoch: Option<u64>,
}

/// The owner's recorded choice on an incoming ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CourtesyDeleteChoice {
    pub choice: CooperativeDeletionDispositionKind,
    pub reason_code: Option<String>,
    /// RFC 3339.
    pub review: Option<String>,
    pub deleted: Vec<String>,
    /// RFC 3339.
    pub recorded: String,
}

/// One ask a former peer sent, filed for the owner's review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CourtesyDeleteIncoming {
    pub request: String,
    pub pact: String,
    /// The pact's state in this vault's log, when it still has one.
    pub pact_status: Option<String>,
    pub requester: String,
    /// The worlds named; empty asks about everything the pact delivered.
    pub worlds: Vec<CourtesyDeleteAskedWorld>,
    pub epoch_cutoff: u64,
    /// RFC 3339.
    pub requested: String,
    /// RFC 3339.
    pub received: String,
    pub answer: Option<CourtesyDeleteChoice>,
    /// The answer's delivery status, once one is sent back.
    pub reply_status: Option<String>,
}

/// What an embedded handle answers for a courtesy delete row: the asks, the
/// answers and their outbox live with a server's own authority key and
/// delivery, and an embedded vault has neither.
pub fn courtesy_delete_host_only<T, I>(
    _memory: &Memory<'_>,
    verb: &str,
    _input: &I,
) -> MemoryResult<T> {
    Err(MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        format!(
            "{verb} runs on a server's own authority key and courtesy outbox; an embedded vault has neither"
        ),
        &["Call it through a remote client of a server that serves it."],
    ))
}
