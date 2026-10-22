//! Models on the owner's other nodes (OF-575, owner ruling MESH: "a phone
//! uses the MacBook's model"). [`MeshLlmTransport`] is an
//! [`OwnServerTransport`](crate::OwnServerTransport) over ALPN
//! `oneiron/llm/1`: a call goes to the first of the owner's nodes that takes
//! it, and with none reachable it waits, saying why ([`MeshLlmTransport::waiting`]),
//! until one does or the caller drops it. It never fails for want of a node.
//! [`LlmMeshService`] serves the ALPN on the node that has the model, under
//! that node's own admission ([`LlmMeshHandler`]).
//!
//! Every stream carries one message each way, under the transport's 1 MiB
//! cap. Bodies over that cross in pieces named by blake3. A stream's events
//! come back as the asking node pulls them, in batches, and go on to the
//! caller as it reads them ([`pump`]). A message of 16 KiB or more crosses
//! in the /ws codec frame, zstd, when that is smaller. What either side
//! holds for its calls is booked on its host's [`StagingBudget`]
//! ([`staging`]).

mod catalog;
mod client;
mod pump;
mod serve;
mod staging;

use std::sync::{Mutex, MutexGuard, PoisonError};

use oneiron::sync::transport::{TAG_CODEC, WireCodecs, decode_codec_frame, encode_codec_frame};
use oneiron_mesh_transport::{MeshConnection, MeshError};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use catalog::{COST_DECLARED, CatalogRefresh, MESH_PEER, advertises};
pub use client::{LlmNodes, MeshLlmTransport, MeshPeerProof, MeshPeerTransport, VaultLlmNodes};
pub use serve::{LlmMeshHandler, LlmMeshService};
pub use staging::{DEFAULT_STAGING_BYTES, StagingBudget};

/// The mesh ALPN model calls ride.
pub const LLM_ALPN: &[u8] = b"oneiron/llm/1";

/// Payload bytes in one piece, under the transport's 1 MiB message.
const PIECE: usize = (1 << 20) - 4096;
/// Bodies at or under this ride inside the message that names them.
const INLINE: usize = 256 * 1024;
/// The transport's message cap, which a codec frame also decodes to at most.
const MESSAGE_MAX: usize = 1 << 20;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Request {
    /// One piece of a body a later message names by hash.
    Put {
        hash: [u8; 32],
        total: u64,
        offset: u64,
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    /// One piece of a body a reply named by hash.
    Get { hash: [u8; 32], offset: u64 },
    /// One generate: the request as JSON.
    Generate { request: Carried },
    /// Starts one stream: the request as JSON.
    Stream { request: Carried },
    /// The stream's next events, waiting briefly for at least one.
    Next { stream: u64 },
    /// The asking side let the stream go.
    Cancel { stream: u64 },
    /// The models this node offers the owner's other nodes.
    Catalog,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Reply {
    Put,
    Piece(#[serde(with = "serde_bytes")] Vec<u8>),
    /// The response as JSON, or the call's error.
    Generated(Result<Carried, oneiron::LlmError>),
    Started(Result<u64, oneiron::LlmError>),
    /// Events as JSON lines, in order; `end` when the stream is over.
    Events {
        events: Carried,
        end: bool,
    },
    Cancelled,
    /// The offered models' catalog entries as JSON.
    Catalog(Carried),
    /// The node does not take this request; another may.
    Refused(String),
}

/// A body, inline or staged by hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Carried {
    Inline(#[serde(with = "serde_bytes")] Vec<u8>),
    Staged { hash: [u8; 32], len: u64 },
}

/// One stream batch: each event as JSON text, or the error that ended it.
#[derive(Debug, Serialize, Deserialize)]
struct Batch {
    events: Vec<Result<String, oneiron::LlmError>>,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, MeshError> {
    rmp_serde::to_vec_named(value).map_err(|err| MeshError::Io(format!("llm mesh encode: {err}")))
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MeshError> {
    rmp_serde::from_slice(bytes).map_err(|err| MeshError::Io(format!("llm mesh decode: {err}")))
}

/// One message as it crosses (ARCH-0081 §7): its MessagePack bytes, in the
/// /ws codec frame when that is smaller. MessagePack never starts with the
/// frame's tag, so a plain message needs no mark.
fn seal<T: Serialize>(message: &T) -> Result<Vec<u8>, MeshError> {
    let bytes = encode(message)?;
    Ok(encode_codec_frame(&bytes, WireCodecs::OURS).unwrap_or(bytes))
}

/// One message as it arrived, a codec frame decoded to at most
/// [`MESSAGE_MAX`] first.
fn unseal<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MeshError> {
    if bytes.first() != Some(&TAG_CODEC) {
        return decode(bytes);
    }
    let inner = decode_codec_frame(bytes, MESSAGE_MAX)
        .map_err(|err| MeshError::Io(format!("llm mesh codec: {err}")))?;
    decode(&inner)
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// One message out on a fresh stream, one back.
async fn exchange(conn: &dyn MeshConnection, request: &Request) -> Result<Reply, MeshError> {
    let mut stream = conn.open_stream().await?;
    stream.send(&seal(request)?).await?;
    unseal(&stream.recv().await?)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Stages a body on the serving node, unless it rides inline.
async fn put(conn: &dyn MeshConnection, bytes: Vec<u8>) -> Result<Carried, MeshError> {
    if bytes.len() <= INLINE {
        return Ok(Carried::Inline(bytes));
    }
    let named = hash(&bytes);
    let total = bytes.len() as u64;
    for (n, piece) in bytes.chunks(PIECE).enumerate() {
        let request = Request::Put {
            hash: named,
            total,
            offset: (n * PIECE) as u64,
            bytes: piece.to_vec(),
        };
        match exchange(conn, &request).await? {
            Reply::Put => {}
            other => return Err(unexpected(&other)),
        }
    }
    Ok(Carried::Staged {
        hash: named,
        len: total,
    })
}

/// A body a reply named, got in pieces when staged, checked against its
/// hash, and booked on `budget` until its holder lets it go (FIX 8619): its
/// whole room before its first piece, waiting its turn, however long it is.
async fn take(
    conn: &dyn MeshConnection,
    carried: Carried,
    budget: &StagingBudget,
) -> Result<staging::BookedBody, MeshError> {
    let (named, len) = match carried {
        Carried::Inline(bytes) => return Ok(staging::BookedBody::charged(budget, bytes)),
        Carried::Staged { hash, len } => (hash, len),
    };
    let want = usize::try_from(len)
        .map_err(|_| MeshError::Io("staged body too long for this node".into()))?;
    let mut body = staging::BookedBody::room(budget, want, 0)
        .await
        .map_err(MeshError::Io)?;
    let bytes = &mut body.bytes;
    while bytes.len() < want {
        let request = Request::Get {
            hash: named,
            offset: bytes.len() as u64,
        };
        match exchange(conn, &request).await? {
            Reply::Piece(piece) if !piece.is_empty() && bytes.len() + piece.len() <= want => {
                bytes.extend_from_slice(&piece);
            }
            other => return Err(unexpected(&other)),
        }
    }
    if hash(&body.bytes) != named {
        return Err(MeshError::Io("staged body does not match its hash".into()));
    }
    Ok(body)
}

fn unexpected(reply: &Reply) -> MeshError {
    match reply {
        Reply::Refused(why) => MeshError::Io(format!("refused: {why}")),
        _ => MeshError::Io("an unexpected reply".into()),
    }
}
