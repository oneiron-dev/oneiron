//! The protocol's messages.
//!
//! Every message is MessagePack with named fields, in the protocol's own
//! codec ([`crate::codec`]). A receiver ignores a field it does not know and
//! refuses a message type it does not know. A new message type or field is
//! a minor bump; a changed meaning is a major bump.
//!
//! 2.0 is a major bump: a message is one or more frames
//! ([`crate::send_frame`]), so no reply, report, answer or descriptor set
//! is held to one frame's length or descriptor count; a value nests to any
//! depth; and a descriptor slot indexes the whole message's descriptors.
//! Inside a call the organ may `ask` the engine, and the engine sends an
//! `answer`. A 1.x peer fails the handshake.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;

pub use crate::value::{Integer, Value};

/// The protocol version this crate speaks.
pub const PROTOCOL: ProtocolVersion = ProtocolVersion { major: 2, minor: 0 };

/// The bytes one ask's value takes, encoded, past which the engine's
/// `[limits]` row asks (`organ_ask_value_bytes`). A larger value is sent and
/// read whole, across as many frames as it takes.
pub const ASK_VALUE_MAX: usize = 64 * 1024;

/// An input or output at or under this size rides inside the frame. A larger
/// one crosses as a read-only region handle.
pub const INLINE_MAX_BYTES: usize = 64 * 1024;

/// The most file descriptors one frame carries: pacing, not a limit. A
/// message with more sends the rest on its next frames, at most this many
/// on each.
pub const MAX_FDS_PER_FRAME: usize = 16;

/// The longest frame both sides send until the handshake sets one. A
/// longer message takes more frames.
pub const DEFAULT_FRAME_LIMIT: u32 = 64 * 1024 * 1024;

/// The largest `hello` or `hello_ack` either side reads, its frames together
/// (FIX 7648). It binds only that first exchange, before a session exists:
/// an allowed pre-session bound, never one on an established call, reply,
/// ask or answer, which take as many frames as they need. The
/// shipped organs' `hello_ack`s are under 1 KiB; this leaves wide room for
/// an organ that offers many verbs.
pub const INITIAL_HANDSHAKE_FRAME_BYTES: u32 = 1024 * 1024;

/// A protocol version. The major must match; both sides speak the lower minor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    /// What a session speaks when this side meets `other`: one major, the
    /// lower minor. `None` when the majors differ.
    #[must_use]
    pub fn session(self, other: Self) -> Option<Self> {
        (self.major == other.major).then(|| Self {
            major: self.major,
            minor: self.minor.min(other.minor),
        })
    }
}

/// A 32-byte blake3 digest, encoded as MessagePack bin.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// The blake3 digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        blake3::Hash::from_bytes(self.0).to_hex().to_string()
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", self.to_hex())
    }
}

impl Serialize for Hash32 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HashVisitor;
        impl Visitor<'_> for HashVisitor {
            type Value = Hash32;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("32 bytes")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Hash32, E> {
                <[u8; 32]>::try_from(v)
                    .map(Hash32)
                    .map_err(|_| E::invalid_length(v.len(), &self))
            }
        }
        deserializer.deserialize_bytes(HashVisitor)
    }
}

/// Who an organ is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganIdentity {
    pub name: String,
    pub version: String,
}

/// One verb an organ offers, at one args schema, over the body kinds it reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerbSpec {
    pub name: String,
    pub schema: u32,
    pub kinds: Vec<String>,
}

/// What the engine grants the organ process, sent in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Calls the organ may run at once.
    pub threads: u16,
    /// The organ's memory grant; the host also sets it as a kernel limit.
    pub memory_bytes: u64,
    /// The largest frame the engine sends.
    pub max_call_frame: u32,
    /// The largest frame the engine accepts.
    pub max_reply_frame: u32,
}

/// Engine to organ.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToOrgan {
    Hello(Hello),
    Call(Call),
    Cancel {
        id: u64,
        reason: CancelReason,
    },
    Shutdown,
    /// The answer to one of the organ's asks.
    Answer(AskAnswer),
}

/// Organ to engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FromOrgan {
    HelloAck(HelloAck),
    Reply(Reply),
    /// Inside a call, the organ asks the engine for something.
    Ask(Ask),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol: ProtocolVersion,
    pub engine: String,
    /// The organ name the engine installed; a different name is refused.
    pub organ: String,
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    pub protocol: ProtocolVersion,
    pub organ: OrganIdentity,
    pub verbs: Vec<VerbSpec>,
}

/// A typed body: the engine's own model of one artifact kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypedBody {
    pub kind: String,
    pub schema: u32,
    pub value: Value,
}

/// One edit op or query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Call {
    pub id: u64,
    pub verb: String,
    pub schema: u32,
    pub args: Value,
    pub body: Option<TypedBody>,
    pub inputs: Vec<Input>,
    pub deadline_ms: u32,
}

/// Bytes the engine hands the organ for one call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    pub media_type: String,
    pub len: u64,
    pub content_hash: Hash32,
    pub data: Payload,
}

/// Where the bytes are: inside the message, or behind the message's
/// descriptor at this slot (a read-only region, valid for the call only). A
/// slot counts every descriptor the message's frames carried, in order.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    Inline(ByteBuf),
    Slot(u64),
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline(bytes) => write!(f, "Inline({} bytes)", bytes.len()),
            Self::Slot(slot) => write!(f, "Slot({slot})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    Deadline,
    Revoked,
    Caller,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    pub id: u64,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Proposal(Proposal),
    Error(OrganError),
}

/// What an organ proposes. The engine lands it, or not; the organ never
/// writes the vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub body: Option<TypedBody>,
    pub outputs: Vec<Output>,
    /// A verb-specific result, such as what `inspect` found.
    pub report: Value,
    pub notes: Notes,
}

/// A file the organ made. The engine hashes and sizes it itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub name: String,
    pub media_type: String,
    pub data: Payload,
}

/// The organ's own word on a call. The engine bounds it and keeps it as a
/// note beside the facts it computed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Notes {
    pub touched: Vec<Locator>,
    pub warnings: Vec<String>,
    pub losses: Vec<Loss>,
}

/// Something an op could not keep, said plainly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Loss {
    pub code: String,
    pub detail: String,
}

/// The unit an anchor, an arg or a note points at. The engine adds the
/// artifact and version; the organ never names them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Locator {
    /// A half-open pixel rectangle, top-left origin, after orientation.
    Pixel {
        layer: Option<String>,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
    },
    Object {
        id: String,
    },
    CellRange {
        sheet: String,
        a1: String,
    },
    Span {
        path: Vec<u32>,
        start: u32,
        end: u32,
    },
    SlideShape {
        slide: u32,
        shape: String,
    },
    Opaque {
        kind: String,
        value: Value,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {detail}")]
pub struct OrganError {
    pub code: ErrorCode,
    pub detail: String,
    pub retryable: bool,
}

impl OrganError {
    #[must_use]
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        let retryable = matches!(code, ErrorCode::Budget | ErrorCode::StaleBase);
        Self {
            code,
            detail: detail.into(),
            retryable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    UnknownVerb,
    SchemaMismatch,
    Unsupported,
    TooLarge,
    Budget,
    Cancelled,
    Revoked,
    DeadlineExceeded,
    StaleBase,
    Internal,
}

/// One ask, inside the call it names. At most one per call is in
/// flight: the organ waits for its answer, or the call's cancel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ask {
    /// The id of the call this ask belongs to.
    pub call: u64,
    /// This call's asks in order: 1, 2, 3.
    pub id: u32,
    pub verb: String,
    /// Past [`ASK_VALUE_MAX`] bytes, encoded, the engine's row asks.
    pub value: Value,
}

/// The engine's answer to one ask. It names both the call and the
/// ask, so a late answer never reads as the answer to a later ask.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AskAnswer {
    pub call: u64,
    pub id: u32,
    pub outcome: AskOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AskOutcome {
    Answered {
        value: Value,
        /// Bytes beside the value: inline, or a region the engine sealed,
        /// valid for the call only.
        data: Option<AskData>,
    },
    Refused(AskRefusal),
}

/// Bytes an answer carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskData {
    pub len: u64,
    pub content_hash: Hash32,
    pub data: Payload,
}

/// Why an ask got no answer. These codes are the ask's own: they never
/// appear as an organ error code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {detail}")]
pub struct AskRefusal {
    pub code: AskCode,
    pub detail: String,
    pub retryable: bool,
}

impl AskRefusal {
    #[must_use]
    pub fn new(code: AskCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            retryable: false,
        }
    }

    /// A refusal that may go another way if asked again.
    #[must_use]
    pub fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AskCode {
    /// The grant does not name this verb or target, or the caller supplied
    /// no handler for it.
    NotGranted,
    /// This call's asks, or its answer bytes, are spent.
    Budget,
    /// A fetched body a handler could not carry. The engine refuses no ask
    /// for its value's or its answer's size (Rule 5).
    TooLarge,
    /// The handler refused the value.
    BadRequest,
    /// The handler could not answer.
    Failed,
    /// Local to the organ: outside a served call there is no engine to
    /// ask, so nothing was sent.
    Unsupported,
    /// Local to the organ: the call was cancelled while the ask waited.
    Cancelled,
}

/// The granted fetch: any organ may be granted it. The engine checks the
/// target against the grant's allowlist and fetches it itself.
pub const ASK_NET_FETCH: &str = "net.fetch";

/// The value of a `net.fetch` ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchAsk {
    /// A label for the receipt, at most 32 bytes.
    pub purpose: String,
    pub method: FetchMethod,
    pub url: String,
    pub content_type: Option<String>,
    pub body: Option<ByteBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchMethod {
    Get,
    Post,
}

/// The value of a `net.fetch` answer; the body rides as the answer's data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchAnswer {
    pub status: u16,
    pub content_type: Option<String>,
    /// Where the body came from, after any redirects.
    pub final_url: String,
}
