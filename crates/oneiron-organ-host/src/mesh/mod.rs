//! Organ calls between the owner's nodes (OF-575, owner ruling MESH).
//!
//! A host that cannot start an organ (a phone, a browser) sends the call to
//! another node of the owner's over ALPN `oneiron/organ/1`, and that node's
//! host runs it as its own. Descriptors and shared regions cannot cross
//! machines, so every input, output and answer crosses as bytes: inline when
//! small, else staged in pieces under the transport's 1 MiB message cap and
//! named by blake3. The serving host hashes what it got again, so its receipt
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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

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
/// The most bytes one connection may stage, either way.
const STAGED_MAX: u64 = 1 << 30;

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

/// Bytes a connection staged, each way.
#[derive(Debug, Default)]
pub(crate) struct Staging {
    /// Pieces the peer put, by hash, in order.
    incoming: Mutex<HashMap<Hash32, Vec<u8>>>,
    /// Bytes this side named in a reply, for the peer to get.
    outgoing: Mutex<HashMap<Hash32, Arc<Vec<u8>>>>,
}

impl Staging {
    fn staged(&self) -> u64 {
        let incoming: u64 = lock(&self.incoming).values().map(|b| b.len() as u64).sum();
        let outgoing: u64 = lock(&self.outgoing).values().map(|b| b.len() as u64).sum();
        incoming + outgoing
    }

    /// Takes one piece the peer put. Pieces of one hash come in order.
    pub(crate) fn put(
        &self,
        hash: Hash32,
        total: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), String> {
        if total > STAGED_MAX || self.staged().saturating_add(bytes.len() as u64) > STAGED_MAX {
            return Err("over what one connection may stage".into());
        }
        let mut incoming = lock(&self.incoming);
        let held = incoming.entry(hash).or_default();
        if held.len() as u64 == total && offset == 0 {
            // Already whole: the same bytes, put again.
            return Ok(());
        }
        if held.len() as u64 != offset || offset.saturating_add(bytes.len() as u64) > total {
            return Err("a staged piece out of order".into());
        }
        held.extend_from_slice(bytes);
        Ok(())
    }

    /// The bytes `carried` names: inline, or put whole and matching its hash.
    pub(crate) fn take(&self, carried: &Carried) -> Result<Vec<u8>, String> {
        match carried {
            Carried::Inline(bytes) => Ok(bytes.to_vec()),
            Carried::Staged { hash, len } => {
                let incoming = lock(&self.incoming);
                let bytes = incoming
                    .get(hash)
                    .filter(|bytes| bytes.len() as u64 == *len)
                    .ok_or("staged bytes missing or incomplete")?;
                if Hash32::of(bytes) != *hash {
                    return Err("staged bytes do not match their hash".into());
                }
                Ok(bytes.clone())
            }
        }
    }

    /// Names bytes for a reply: inline when small, else kept for the peer
    /// to get in pieces.
    pub(crate) fn offer(&self, bytes: Vec<u8>) -> Carried {
        if bytes.len() <= INLINE {
            return Carried::Inline(ByteBuf::from(bytes));
        }
        let hash = Hash32::of(&bytes);
        let len = bytes.len() as u64;
        lock(&self.outgoing).insert(hash, Arc::new(bytes));
        Carried::Staged { hash, len }
    }

    /// One piece of bytes this side offered.
    pub(crate) fn piece(&self, hash: Hash32, offset: u64) -> Result<ByteBuf, String> {
        let bytes = lock(&self.outgoing)
            .get(&hash)
            .cloned()
            .ok_or("no such staged bytes")?;
        let start = usize::try_from(offset)
            .ok()
            .filter(|start| *start < bytes.len())
            .ok_or("a piece past the end")?;
        let end = start.saturating_add(PIECE).min(bytes.len());
        Ok(ByteBuf::from(bytes[start..end].to_vec()))
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
