//! Exact conversation sessions on a model worker (DESIGN-V2 §3.2, R2): what
//! a session is keyed by, the canonical checkpoint it keeps, the ops a host
//! sends its worker over the native channel, and why a session is dropped.
//!
//! A session keeps one canonical checkpoint: the stable prefix and the
//! selected log path, with no board attached, at a token frontier the worker
//! verified. A turn forks a working branch at that frontier, renders and
//! admits its whole board fresh, and discards the branch when it ends; the
//! working branch's state attended the board and is never promoted. Once the
//! reply is committed the host stages the successor (only the newly
//! committed canonical suffix is computed against the retained prefix),
//! rechecks what it was admitted under, and publishes it by compare-and-swap
//! on the checkpoint's token digest and HEAD. Nothing here is vault state:
//! a session lives in memory, is never persisted, and is never restored as
//! truth. A metadata match is never a KV hit: only the worker's verified
//! token frontier is.
use serde::{Deserialize, Serialize};

use super::CacheIdentity;
use super::segments::hex_bytes;
use oneiron_contracts::EntityId;

/// The hello capability that advertises session ops.
pub const SESSIONS_CAPABILITY: &str = "sessions";

/// The codec minor version that carries session ops (codec v1.1); a worker
/// that advertises a lower one gets none.
pub const SESSION_SCHEMA_MINOR: u64 = 1;

/// A session or branch handle's size: 128 bits, minted by the worker.
pub const SESSION_HANDLE_BYTES: usize = 16;

hex_bytes!(
    /// The vault a conversation lives in: its vault id.
    VaultRef,
    32
);
hex_bytes!(
    /// The read a canonical path was admitted under: its reader, where it
    /// sits, and its credential's ceilings, as the host digests them.
    ScopeDigest,
    32
);
hex_bytes!(
    /// Everything besides the token ids that shapes what a prefix computes:
    /// template arguments, tool definitions and any non-token input.
    ConditioningDigest,
    32
);
hex_bytes!(
    /// The worker's digest of a canonical path's token ids.
    TokenDigest,
    32
);
hex_bytes!(
    /// What a session handle is bound to: its key less the HEAD
    /// ([`SessionKey::binding`]). The worker refuses an op on a handle that
    /// names another.
    SessionBinding,
    32
);
hex_bytes!(
    /// A session's capability handle on one worker incarnation.
    SessionHandle,
    16
);
hex_bytes!(
    /// A working branch's handle inside a session.
    BranchHandle,
    16
);

/// The conversation a call's canonical path was read from, as the producer
/// read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConversationAnchor {
    pub vault: VaultRef,
    pub read_scope: ScopeDigest,
    pub conversation: EntityId,
    /// The selected path's tip: a DAG conversation's HEAD when it was read.
    pub head: Option<EntityId>,
    /// The fold epoch of the newest summary standing in the log; 0 when
    /// none does.
    pub fold_epoch: u64,
}

/// What a session is keyed by: the conversation and the read it was
/// admitted under, the model identity of the worker that keeps it, and the
/// non-token conditioning of its calls. Text-token equality alone never
/// claims a match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionKey {
    pub anchor: ConversationAnchor,
    pub identity: CacheIdentity,
    pub conditioning: ConditioningDigest,
}

impl SessionKey {
    /// The key less its HEAD: one session per binding, whose checkpoint
    /// advances with the HEAD.
    #[must_use]
    pub fn binding(&self) -> SessionBinding {
        let ConversationAnchor {
            vault,
            read_scope,
            conversation,
            head: _,
            fold_epoch,
        } = &self.anchor;
        let line = (
            vault,
            read_scope,
            conversation,
            fold_epoch,
            &self.identity,
            &self.conditioning,
        );
        SessionBinding(digest(b"oneiron.llm.session.binding.v1\0", &line))
    }
}

fn digest<T: Serialize>(domain: &[u8], value: &T) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&super::canonical_json_bytes(value).unwrap_or_default());
    *hasher.finalize().as_bytes()
}

/// A canonical checkpoint as the worker verified it: the token digest of
/// the canonical path, the HEAD it ends at, its frontier, and the checkpoint
/// it was staged on, so a chain names each predecessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalCheckpointRef {
    pub digest: TokenDigest,
    pub head: Option<EntityId>,
    pub frontier_tokens: u64,
    #[serde(default)]
    pub parent: Option<TokenDigest>,
}

impl CanonicalCheckpointRef {
    /// Whether `other` names the same checkpoint: its digest and HEAD.
    #[must_use]
    pub fn same_point(&self, other: &Self) -> bool {
        self.digest == other.digest && self.head == other.head
    }
}

/// The session ops, by their wire names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOp {
    Create,
    Append,
    Checkpoint,
    Fork,
    Generate,
    SuffixCommit,
    Restore,
    Drop,
}

impl SessionOp {
    pub const ALL: [Self; 8] = [
        Self::Create,
        Self::Append,
        Self::Checkpoint,
        Self::Fork,
        Self::Generate,
        Self::SuffixCommit,
        Self::Restore,
        Self::Drop,
    ];

    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Create => "session.create",
            Self::Append => "session.append",
            Self::Checkpoint => "session.checkpoint",
            Self::Fork => "session.fork",
            Self::Generate => "session.generate",
            Self::SuffixCommit => "session.suffix_commit",
            Self::Restore => "session.restore",
            Self::Drop => "session.drop",
        }
    }
}

/// A worker's `capabilities.sessions` in its hello.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SessionCapability {
    pub minor: u64,
    pub ops: Vec<String>,
}

impl SessionCapability {
    /// Whether the worker serves `op` at this codec minor.
    #[must_use]
    pub fn serves(&self, op: SessionOp) -> bool {
        self.minor >= SESSION_SCHEMA_MINOR && self.ops.iter().any(|name| name == op.wire_name())
    }
}

/// The session an op names, and what its handle must be bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionTarget {
    pub handle: SessionHandle,
    pub binding: SessionBinding,
}

/// What makes an op safe to retry: its id, which the worker answers again
/// with the same result instead of acting twice, and the session
/// generation the host expects, which every published checkpoint moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SessionOpStamp {
    pub op_id: u64,
    pub generation: u64,
}

/// `session.create`: a new session, not warm, bound to `binding` on the
/// incarnation the frame's epoch names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionCreate {
    pub binding: SessionBinding,
    pub op_id: u64,
}

/// `session.create`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SessionCreated {
    pub handle: SessionHandle,
    pub generation: u64,
}

/// `session.append`: stage the canonical path the frame's input region
/// carries (a `chat_json` conversation, no generation prompt) on the
/// session's checkpoint, render and jointly encode it, and verify the token
/// longest common prefix with that checkpoint. Nothing is computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionAppend {
    #[serde(flatten)]
    pub target: SessionTarget,
    #[serde(flatten)]
    pub stamp: SessionOpStamp,
    /// The checkpoint the host holds as published; `None` for a cold one.
    pub base: Option<CanonicalCheckpointRef>,
    /// The HEAD the staged path ends at.
    pub head: Option<EntityId>,
}

/// `session.append`'s answer: the staged path's length and how much of the
/// published checkpoint it keeps, both in tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct SessionAppended {
    pub staged_tokens: u64,
    pub lcp_tokens: u64,
}

/// `session.suffix_commit`: compute the staged path's suffix past the
/// verified prefix, prefill only, against the retained checkpoint. The
/// result is staged, never ready, until a `session.checkpoint` publishes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionSuffixCommit {
    #[serde(flatten)]
    pub target: SessionTarget,
    #[serde(flatten)]
    pub stamp: SessionOpStamp,
}

/// `session.suffix_commit`'s answer: the staged successor, which names its
/// base as its parent, and the tokens it computed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SessionSuffixStaged {
    pub staged: CanonicalCheckpointRef,
    pub computed_tokens: u64,
}

/// `session.checkpoint`: publish the staged successor `staged` as the
/// session's canonical checkpoint, atomically, or discard it (`publish`
/// false).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionCheckpoint {
    #[serde(flatten)]
    pub target: SessionTarget,
    #[serde(flatten)]
    pub stamp: SessionOpStamp,
    pub staged: TokenDigest,
    pub publish: bool,
}

/// What a session holds on the worker, as the worker measured it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub struct SessionResidency {
    /// Its checkpoint is resident and attachable now.
    pub resident: bool,
    /// The unique bytes its pages and state hold, charged once; `None`
    /// when the worker did not measure them.
    #[serde(default)]
    pub unique_bytes: Option<u64>,
}

/// `session.checkpoint`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SessionCheckpointed {
    pub ready: bool,
    #[serde(default)]
    pub checkpoint: Option<CanonicalCheckpointRef>,
    pub generation: u64,
    #[serde(default)]
    pub residency: SessionResidency,
}

/// `session.fork`: a working branch at the verified frontier of the full
/// turn the frame's input region carries, whose first `canonical_messages`
/// messages are its canonical path. The worker renders the turn with and
/// without its ephemeral tail, takes the verified token LCP with `expected`
/// (never a guessed message boundary), caps it before the first board
/// token, and rewinds to an earlier safe state when it must.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionFork {
    #[serde(flatten)]
    pub target: SessionTarget,
    #[serde(flatten)]
    pub stamp: SessionOpStamp,
    pub expected: Option<CanonicalCheckpointRef>,
    pub canonical_messages: u64,
}

/// `session.fork`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SessionForked {
    pub branch: BranchHandle,
    /// Where the branch attached: tokens reused from the checkpoint.
    pub frontier_tokens: u64,
    /// How much of the published checkpoint the turn's canonical path
    /// keeps; less than its frontier means the prefix changed.
    pub canonical_lcp_tokens: u64,
    #[serde(default)]
    pub residency: SessionResidency,
}

/// The `session` field of a `session.generate`, whose body is otherwise a
/// `generate`'s: the turn runs on `branch`, which ends with the call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionGenerate {
    #[serde(flatten)]
    pub target: SessionTarget,
    pub branch: BranchHandle,
    pub op_id: u64,
}

/// `session.restore`: confirm `checkpoint` resident and attachable,
/// bringing it back from the worker's host memory when it was moved there.
/// Sealed and on-disk snapshots are not R2's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionRestore {
    #[serde(flatten)]
    pub target: SessionTarget,
    #[serde(flatten)]
    pub stamp: SessionOpStamp,
    pub checkpoint: CanonicalCheckpointRef,
}

/// `session.restore`'s answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct SessionRestored {
    pub residency: SessionResidency,
}

/// `session.drop`: revoke the handle, cancel what depends on it, and answer
/// once every page and state slot it held is released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionDrop {
    #[serde(flatten)]
    pub target: SessionTarget,
    pub op_id: u64,
    pub reason: SessionInvalidation,
}

/// `session.drop`'s answer, sent only after the release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct SessionReleased {
    pub released: bool,
}

/// Why a session's state stops serving (DESIGN-V2 §3.2). With no precise
/// dependency map, any of these drops the whole session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionInvalidation {
    /// The canonical prefix's tokens changed before the frontier.
    PrefixTokens,
    /// The model, quant, adapter, tokenizer, template, attention, build or
    /// state format, or the calls' template arguments, changed.
    Identity,
    /// Another path of the conversation was selected.
    PathChanged,
    /// A fold rewrote the log before the frontier.
    FoldBeforeFrontier,
    /// The read or disclosure the path was admitted under changed.
    DisclosureOrScope,
    /// A source the path was read from was withdrawn or erased.
    SourceWithdrawn,
    /// The HEAD moved on under a staged successor.
    StaleHead,
    /// The worker's incarnation ended.
    WorkerEpoch,
    /// The worker or the host evicted it.
    Evicted,
    /// The worker no longer holds it resident.
    ResidencyLost,
}
