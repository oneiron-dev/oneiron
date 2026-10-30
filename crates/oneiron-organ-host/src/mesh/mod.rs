//! Organ calls between the owner's nodes (OF-575, owner ruling MESH).
//!
//! A host that cannot start an organ (a phone, a browser) sends the call to
//! another node of the owner's over ALPN `oneiron/organ/1`, and that node's
//! host runs it as its own. Descriptors and shared regions cannot cross
//! machines, so every input, output and answer crosses as bytes: inline when
//! small, else staged in pieces under the transport's 1 MiB message cap and
//! named by blake3. The serving node spills what it stages to disk, however
//! much (FIX 6193). The serving host hashes what it got again, so its receipt
//! holds what it saw; the asking node checks each output against that
//! receipt. The organ's asks come back to the asking node, whose handlers
//! (and keys) answer them; a granted `net.fetch` runs where the organ runs.
//!
//! Every stream carries one message each way. The asking node opens streams
//! for `offers`, `put`, `get` and `call`; while a call runs, the serving node
//! opens one stream per ask.

mod client;
#[cfg(unix)]
mod serve;
#[cfg(unix)]
mod staging;

use oneiron_mesh_transport::{MeshConnection, MeshError};
use oneiron_organ_protocol::{AskRefusal, ByteBuf, Hash32, OrganError, TypedBody};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::receipt::{AskReceipt, CallReceipt, FetchTarget, SignedReceipt};
use crate::spec::CallClass;

pub(crate) use client::{PeerError, call_on, offers};
#[cfg(unix)]
pub use serve::OrganService;

/// The mesh ALPN organ calls ride. A node serves it only to the owner's
/// machines its vault grants it to.
pub const ORGAN_ALPN: &[u8] = b"oneiron/organ/1";

/// Payload bytes in one staged piece, under the transport's 1 MiB message.
const PIECE: usize = (1 << 20) - 4096;
/// Bytes at or under this ride inside the message that names them.
const INLINE: usize = 64 * 1024;

/// One organ a node offers, with the verbs its install grant names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    pub organ: String,
    pub verbs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Request {
    /// What the node offers.
    Offers,
    /// One piece of bytes a later message names by hash.
    Put {
        hash: Hash32,
        total: u64,
        offset: u64,
        bytes: ByteBuf,
    },
    /// One piece of bytes a reply named by hash.
    Get { hash: Hash32, offset: u64 },
    /// One call: the bytes of a [`PeerCall`].
    Call { call: Carried },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reply {
    Offers(Vec<Offer>),
    Put,
    Piece(ByteBuf),
    /// The bytes of a [`PeerResult`].
    Call(Carried),
    Refused(String),
}

/// Bytes, inline or staged by hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Carried {
    Inline(ByteBuf),
    Staged { hash: Hash32, len: u64 },
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PeerCall {
    pub organ: String,
    pub verb: String,
    pub schema: u32,
    pub args: rmpv::Value,
    pub body: Option<TypedBody>,
    pub class: CallClass,
    pub deadline_ms: u64,
    pub grant: String,
    /// Vault inputs first, then lent bytes, as the local host orders them.
    pub inputs: Vec<PeerInput>,
    /// The ask verbs the asking node has handlers for.
    pub answers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PeerInput {
    /// The artifact (hex) and version the asking node read, if any.
    pub read: Option<(String, u64)>,
    pub media_type: String,
    pub bytes: Carried,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PeerResult {
    Done(PeerOutcome),
    Failed(PeerFailure),
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PeerOutcome {
    pub body: Option<TypedBody>,
    pub report: rmpv::Value,
    pub receipt: CallReceipt,
    pub outputs: Vec<PeerOutput>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PeerOutput {
    pub name: String,
    pub media_type: String,
    pub content_hash: Hash32,
    pub bytes: Carried,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PeerFailure {
    pub kind: FailureKind,
    pub detail: String,
    pub organ: Option<OrganError>,
    /// The receipt line of every ask the call made before it failed.
    pub asks: Vec<AskReceipt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FailureKind {
    /// The node cannot run this call now: not installed, unavailable,
    /// backing off, over its budget. Another node may.
    Absent,
    /// The organ ran and answered with an error.
    Organ,
    Deadline,
    Revoked,
    Failed,
}

/// An organ's ask, sent back to the node whose handlers answer it.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PeerAsk {
    pub organ: String,
    pub verb: String,
    pub value: rmpv::Value,
    pub call_verb: String,
    pub grant: String,
    pub deadline_ms: u64,
    pub max_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PeerAnswer {
    pub answered: Result<PeerAnswered, AskRefusal>,
    /// What the handler's key signed, for the serving host's receipt.
    pub signed: Option<SignedReceipt>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PeerAnswered {
    pub value: rmpv::Value,
    pub data: Option<Carried>,
    pub fetch: Option<FetchTarget>,
}

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, MeshError> {
    rmp_serde::to_vec_named(value).map_err(|err| MeshError::Io(format!("organ mesh encode: {err}")))
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MeshError> {
    rmp_serde::from_slice(bytes).map_err(|err| MeshError::Io(format!("organ mesh decode: {err}")))
}

/// One message out on a fresh stream, one back.
pub(crate) async fn exchange(
    conn: &dyn MeshConnection,
    request: &Request,
) -> Result<Reply, MeshError> {
    let mut stream = conn.open_stream().await?;
    stream.send(&encode(request)?).await?;
    decode(&stream.recv().await?)
}
