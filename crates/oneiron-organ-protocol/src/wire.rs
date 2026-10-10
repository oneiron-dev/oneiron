//! The protocol's messages.
//!
//! Every message is MessagePack with named fields. A receiver ignores a field
//! it does not know and refuses a message type it does not know. A new
//! message type or field is a minor bump; a changed meaning is a major bump.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;

/// The protocol version this crate speaks.
pub const PROTOCOL: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

/// An input or output at or under this size rides inside the frame. A larger
/// one crosses as a read-only region handle.
pub const INLINE_MAX_BYTES: usize = 64 * 1024;

/// The most file descriptors one frame may carry.
pub const MAX_FDS_PER_FRAME: usize = 16;

/// The frame limit both sides use until the handshake sets one.
pub const DEFAULT_FRAME_LIMIT: u32 = 64 * 1024 * 1024;

/// A protocol version. The major must match; both sides speak the lower minor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
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
    Cancel { id: u64, reason: CancelReason },
    Shutdown,
}

/// Organ to engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FromOrgan {
    HelloAck(HelloAck),
    Reply(Reply),
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
    pub value: rmpv::Value,
}

/// One edit op or query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Call {
    pub id: u64,
    pub verb: String,
    pub schema: u32,
    pub args: rmpv::Value,
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

/// Where the bytes are: inside the frame, or behind the frame's descriptor
/// at this slot (a read-only region, valid for the call only).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    Inline(ByteBuf),
    Slot(u16),
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
    pub report: rmpv::Value,
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
        value: rmpv::Value,
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
