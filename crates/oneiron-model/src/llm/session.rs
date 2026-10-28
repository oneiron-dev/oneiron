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
//!
//! Codec v1.2 (R3) adds the snapshot ops: `session.export` copies a
//! published checkpoint out of the worker into a sealed region, and
//! `session.import` rebuilds one from such a region on a new, empty session,
//! staged until the host has rechecked what it was admitted under and
//! publishes it. The worker keeps no snapshot past its op's replay; what the
//! host keeps, and where, is the host's.
use serde::{Deserialize, Serialize};

use super::CacheIdentity;
use super::segments::hex_bytes;
use oneiron_contracts::EntityId;

/// The hello capability that advertises session ops.
pub const SESSIONS_CAPABILITY: &str = "sessions";

/// The codec minor version that carries session ops (codec v1.1); a worker
/// that advertises a lower one gets none.
pub const SESSION_SCHEMA_MINOR: u64 = 1;

/// The codec minor that carries the snapshot ops (codec v1.2): a worker
/// advertises it with `capabilities.sessions.snapshot`. It is asked only of
/// [`SessionOp::Export`] and [`SessionOp::Import`]; every other op still
/// needs [`SESSION_SCHEMA_MINOR`] alone.
pub const SNAPSHOT_SCHEMA_MINOR: u64 = 2;

/// The snapshot format both sides speak: `OIRS`, a u32 little-endian schema,
/// a u64 little-endian header length, the canonical JSON header, then the
/// tensor payload it describes.
pub const SNAPSHOT_SCHEMA: u64 = 1;

/// A snapshot region's encoding on the native channel.
pub const SNAPSHOT_ENCODING: &str = "snapshot_v1";

/// What names a snapshot region's bytes: their SHA-256.
pub const SNAPSHOT_HASH: &str = "sha256";

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
hex_bytes!(
    /// The SHA-256 of a snapshot region's bytes, as both sides take it:
    /// never a token digest.
    SnapshotDigest,
    32
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
    Export,
    Import,
}

impl SessionOp {
    pub const ALL: [Self; 10] = [
        Self::Create,
        Self::Append,
        Self::Checkpoint,
        Self::Fork,
        Self::Generate,
        Self::SuffixCommit,
        Self::Restore,
        Self::Drop,
        Self::Export,
        Self::Import,
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
            Self::Export => "session.export",
            Self::Import => "session.import",
        }
    }

    /// The codec minor that carries the op.
    #[must_use]
    pub const fn minor(self) -> u64 {
        match self {
            Self::Create
            | Self::Append
            | Self::Checkpoint
            | Self::Fork
            | Self::Generate
            | Self::SuffixCommit
            | Self::Restore
            | Self::Drop => SESSION_SCHEMA_MINOR,
            Self::Export | Self::Import => SNAPSHOT_SCHEMA_MINOR,
        }
    }
}

/// A worker's `capabilities.sessions` in its hello.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SessionCapability {
    pub minor: u64,
    pub ops: Vec<String>,
    /// What its snapshots are; only a minor-2 worker that exports or
    /// imports names it.
    #[serde(default)]
    pub snapshot: Option<SnapshotCapability>,
}

impl SessionCapability {
    /// Whether the worker serves `op` at the op's codec minor, and, for a
    /// snapshot op, writes and reads the snapshots this side does.
    #[must_use]
    pub fn serves(&self, op: SessionOp) -> bool {
        let minor = op.minor();
        let agreed = minor < SNAPSHOT_SCHEMA_MINOR
            || self
                .snapshot
                .as_ref()
                .is_some_and(SnapshotCapability::agrees);
        self.minor >= minor && agreed && self.ops.iter().any(|name| name == op.wire_name())
    }
}

/// A minor-2 worker's `capabilities.sessions.snapshot`: the snapshot schema,
/// region encoding and hash it speaks, and the recurrent state kinds it
/// captures and rebuilds exactly (`gdn`, `swa`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SnapshotCapability {
    pub schema: u64,
    pub encoding: String,
    pub hash: String,
    pub state_kinds: Vec<String>,
}

impl SnapshotCapability {
    /// Whether the worker's snapshots are the ones this side reads: the same
    /// schema, encoding and hash, and some state kind it rebuilds.
    #[must_use]
    pub fn agrees(&self) -> bool {
        self.schema == SNAPSHOT_SCHEMA
            && self.encoding == SNAPSHOT_ENCODING
            && self.hash == SNAPSHOT_HASH
            && !self.state_kinds.is_empty()
    }
}

/// A refused snapshot op that is a cache miss, not a fault: nothing ran, and
/// the host goes cold and recomputes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotMiss {
    /// The snapshot's schema, layout, state or model identity is not one
    /// this worker rebuilds exactly.
    Incompatible,
    /// The worker has no room for it beside what runs now.
    Busy,
}

impl SnapshotMiss {
    /// The refusal code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Incompatible => "snapshot_incompatible",
            Self::Busy => "snapshot_busy",
        }
    }

    /// The miss a refusal code names, if it names one.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        [Self::Incompatible, Self::Busy]
            .into_iter()
            .find(|miss| miss.code() == code)
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

/// A region's description on the native channel: one whole region, the
/// first descriptor of the frame that carries it, in `encoding`.
/// `buffer_id` names it on its connection: the request id of that frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionDescriptor {
    pub buffer_id: u64,
    pub fd_index: u64,
    pub offset: u64,
    pub length: u64,
    pub encoding: String,
}

/// `session.export`: copy the session's published checkpoint, `checkpoint`
/// exactly (its digest, HEAD, frontier and parent), into a snapshot in a
/// sealed region whose descriptor rides on the answer's frame. The
/// checkpoint stays published and resident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionExport {
    #[serde(flatten)]
    pub target: SessionTarget,
    #[serde(flatten)]
    pub stamp: SessionOpStamp,
    pub checkpoint: CanonicalCheckpointRef,
}

/// `session.export`'s answer: the checkpoint it copied, the snapshot's
/// length and SHA-256, and the region that holds it (`output.length` is the
/// snapshot's length). A retry of the op gets the same bytes again.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SessionExported {
    pub checkpoint: CanonicalCheckpointRef,
    pub snapshot_bytes: u64,
    pub snapshot_sha256: SnapshotDigest,
    pub output: RegionDescriptor,
    #[serde(default)]
    pub residency: SessionResidency,
}

/// `session.import`: rebuild `checkpoint` from the snapshot the frame's
/// input region carries (`snapshot_bytes` long, named by `snapshot_sha256`)
/// on a session that holds nothing yet, and stage it as that session's
/// successor. It is never ready until a `session.checkpoint` publishes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionImport {
    #[serde(flatten)]
    pub target: SessionTarget,
    #[serde(flatten)]
    pub stamp: SessionOpStamp,
    pub checkpoint: CanonicalCheckpointRef,
    pub snapshot_bytes: u64,
    pub snapshot_sha256: SnapshotDigest,
}

/// `session.import`'s answer: the staged checkpoint, and the bytes it read
/// with their SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SessionImported {
    pub staged: CanonicalCheckpointRef,
    pub imported_bytes: u64,
    pub snapshot_sha256: SnapshotDigest,
    #[serde(default)]
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
