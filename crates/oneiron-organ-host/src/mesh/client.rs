//! The asking side of a mesh organ call: stage the inputs, send the call,
//! answer the organ's asks while it runs, take the outputs back.

use std::collections::HashSet;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron_mesh_transport::{MeshConnection, MeshError, MeshStream};
use oneiron_organ_protocol::{AskCode, AskRefusal, ByteBuf, Hash32};

use super::{
    Carried, FailureKind, INLINE, Offer, PIECE, PeerAnswer, PeerAnswered, PeerAsk, PeerCall,
    PeerInput, PeerOutcome, PeerResult, Reply, Request, decode, encode, exchange,
};
use crate::error::HostError;
use crate::handlers::{Answered, AskHandlers, AskRequest, HandlerScope};
use crate::outcome::{OrganOutcome, OrganOutput, OutputBytes};
use crate::spec::{FetchGrant, LentInput, OrganCall, OrganInput};

/// Why a node did not return an outcome.
#[derive(Debug)]
pub(crate) enum PeerError {
    /// The node cannot serve the call now, or could not be reached; another
    /// node may.
    Absent(String),
    /// The call ran there and failed.
    Failed(HostError),
}

fn absent(err: MeshError) -> PeerError {
    PeerError::Absent(err.to_string())
}

fn unexpected(reply: &Reply) -> MeshError {
    match reply {
        Reply::Refused(why) => MeshError::Io(format!("refused: {why}")),
        _ => MeshError::Io("an unexpected reply".into()),
    }
}

/// What the node offers.
pub(crate) async fn offers(conn: &dyn MeshConnection) -> Result<Vec<Offer>, MeshError> {
    match exchange(conn, &Request::Offers).await? {
        Reply::Offers(offers) => Ok(offers),
        other => Err(unexpected(&other)),
    }
}

/// Stages bytes on the serving node, unless they ride inline.
async fn put(
    conn: &dyn MeshConnection,
    bytes: &[u8],
    sent: &mut HashSet<Hash32>,
) -> Result<Carried, MeshError> {
    if bytes.len() <= INLINE {
        return Ok(Carried::Inline(ByteBuf::from(bytes.to_vec())));
    }
    let hash = Hash32::of(bytes);
    let total = bytes.len() as u64;
    if sent.insert(hash) {
        for (n, piece) in bytes.chunks(PIECE).enumerate() {
            let request = Request::Put {
                hash,
                total,
                offset: (n * PIECE) as u64,
                bytes: ByteBuf::from(piece.to_vec()),
            };
            match exchange(conn, &request).await? {
                Reply::Put => {}
                other => return Err(unexpected(&other)),
            }
        }
    }
    Ok(Carried::Staged { hash, len: total })
}

/// The bytes a reply named, got in pieces when staged, checked against
/// their hash.
async fn take(conn: &dyn MeshConnection, carried: Carried) -> Result<Vec<u8>, MeshError> {
    let (hash, len) = match carried {
        Carried::Inline(bytes) => return Ok(bytes.into_vec()),
        Carried::Staged { hash, len } => (hash, len),
    };
    let want = usize::try_from(len).map_err(|_| MeshError::Io("staged bytes too long".into()))?;
    let mut bytes = Vec::with_capacity(want);
    while bytes.len() < want {
        let request = Request::Get {
            hash,
            offset: bytes.len() as u64,
        };
        match exchange(conn, &request).await? {
            Reply::Piece(piece) if !piece.is_empty() && bytes.len() + piece.len() <= want => {
                bytes.extend_from_slice(&piece);
            }
            other => return Err(unexpected(&other)),
        }
    }
    if Hash32::of(&bytes) != hash {
        return Err(MeshError::Io("staged bytes do not match their hash".into()));
    }
    Ok(bytes)
}

/// Runs `call` on the node behind `conn`. `inputs` are the bytes this node
/// read or was lent, vault inputs first, each with the version it read.
/// The organ's asks are answered here by `asks`, and every ask's receipt
/// line lands in `asks` as a local call's would.
pub(crate) async fn call_on(
    conn: &dyn MeshConnection,
    machine: EntityId,
    call: &OrganCall,
    inputs: &[(Option<OrganInput>, LentInput)],
    asks: &AskHandlers<'_>,
) -> Result<OrganOutcome, PeerError> {
    let mut sent = HashSet::new();
    let mut wire = Vec::with_capacity(inputs.len());
    for (read, input) in inputs {
        wire.push(PeerInput {
            read: read.map(|read| (read.artifact.to_hex(), read.version)),
            media_type: input.media_type.clone(),
            bytes: put(conn, &input.bytes, &mut sent).await.map_err(absent)?,
        });
    }
    let peer = PeerCall {
        organ: call.organ.clone(),
        verb: call.verb.clone(),
        schema: call.schema,
        args: call.args.clone(),
        body: call.body.clone(),
        class: call.class,
        deadline_ms: u64::try_from(call.deadline.as_millis()).unwrap_or(u64::MAX),
        grant: call.grant.clone(),
        inputs: wire,
        answers: asks.verbs(),
    };
    let encoded = encode(&peer).map_err(absent)?;
    let carried = if encoded.len() <= INLINE {
        Carried::Inline(ByteBuf::from(encoded))
    } else {
        put(conn, &encoded, &mut sent).await.map_err(absent)?
    };
    let mut stream = conn.open_stream().await.map_err(absent)?;
    stream
        .send(&encode(&Request::Call { call: carried }).map_err(absent)?)
        .await
        .map_err(absent)?;
    let reply = {
        let mut reply = stream.recv();
        loop {
            tokio::select! {
                got = &mut reply => break got,
                incoming = conn.accept_stream() => match incoming {
                    // An ask this side failed to answer leaves the organ
                    // a refusal from its own host; the call goes on.
                    Ok(ask) => drop(answer(conn, ask, asks, &mut sent).await),
                    Err(err) => break Err(err),
                },
            }
        }
    };
    let result = match decode::<Reply>(&reply.map_err(absent)?).map_err(absent)? {
        Reply::Call(carried) => {
            decode::<PeerResult>(&take(conn, carried).await.map_err(absent)?).map_err(absent)?
        }
        other => return Err(absent(unexpected(&other))),
    };
    match result {
        PeerResult::Done(outcome) => {
            keep_lines(asks, &outcome.receipt.asks);
            received(conn, outcome).await
        }
        PeerResult::Failed(failure) => {
            keep_lines(asks, &failure.asks);
            Err(match failure.kind {
                FailureKind::Absent => PeerError::Absent(failure.detail),
                FailureKind::Organ => PeerError::Failed(match failure.organ {
                    Some(error) => HostError::Organ(error),
                    None => HostError::Remote {
                        machine: machine.to_hex(),
                        detail: failure.detail,
                    },
                }),
                FailureKind::Deadline => PeerError::Failed(HostError::DeadlineExceeded),
                FailureKind::Revoked => PeerError::Failed(HostError::Revoked),
                FailureKind::Failed => PeerError::Failed(HostError::Remote {
                    machine: machine.to_hex(),
                    detail: failure.detail,
                }),
            })
        }
    }
}

/// The serving host's ask lines, kept as a local call keeps its own.
fn keep_lines(asks: &AskHandlers<'_>, lines: &[crate::receipt::AskReceipt]) {
    asks.asked
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .extend(lines.iter().cloned());
}

/// Takes the outputs back and checks each against the serving host's
/// receipt: the bytes that came are the bytes it hashed.
async fn received(
    conn: &dyn MeshConnection,
    outcome: PeerOutcome,
) -> Result<OrganOutcome, PeerError> {
    let PeerOutcome {
        body,
        report,
        receipt,
        outputs: wire,
    } = outcome;
    if wire.len() != receipt.outputs.len() {
        return Err(PeerError::Failed(HostError::ReplyInvalid(
            "the node's outputs do not match its receipt".into(),
        )));
    }
    let mut outputs = Vec::with_capacity(wire.len());
    for (output, line) in wire.into_iter().zip(&receipt.outputs) {
        let bytes = take(conn, output.bytes).await.map_err(absent)?;
        let content_hash = Hash32::of(&bytes);
        if content_hash != output.content_hash
            || content_hash != line.content_hash
            || output.name != line.name
            || output.media_type != line.media_type
        {
            return Err(PeerError::Failed(HostError::ReplyInvalid(
                "an output from the node is not the one its receipt names".into(),
            )));
        }
        outputs.push(OrganOutput {
            name: output.name,
            media_type: output.media_type,
            content_hash,
            bytes: OutputBytes::Inline(bytes),
            _kept: None,
        });
    }
    Ok(OrganOutcome {
        body,
        outputs,
        report,
        receipt,
    })
}

/// Answers one ask the serving node sent back, through this side's
/// handler for its verb.
async fn answer(
    conn: &dyn MeshConnection,
    mut stream: Box<dyn MeshStream>,
    asks: &AskHandlers<'_>,
    sent: &mut HashSet<Hash32>,
) -> Result<(), MeshError> {
    let ask: PeerAsk = decode(&stream.recv().await?)?;
    let (answered, signed) = run_handler(&ask, asks);
    let answered = match answered {
        Ok(Answered { value, data, fetch }) => Ok(PeerAnswered {
            value,
            data: match data {
                Some(bytes) => Some(put(conn, &bytes, sent).await?),
                None => None,
            },
            fetch,
        }),
        Err(refusal) => Err(refusal),
    };
    stream
        .send(&encode(&PeerAnswer { answered, signed })?)
        .await
}

fn run_handler(
    ask: &PeerAsk,
    asks: &AskHandlers<'_>,
) -> (
    Result<Answered, AskRefusal>,
    Option<crate::receipt::SignedReceipt>,
) {
    let Some(handler) = asks.get(&ask.verb) else {
        let refusal = AskRefusal::new(
            AskCode::NotGranted,
            "the asking node has no handler for this ask",
        );
        return (Err(refusal), None);
    };
    let signing = Mutex::new(None);
    // A fetch runs where the organ runs, under that install's allowlist.
    let fetch = FetchGrant::default();
    let request = AskRequest {
        verb: &ask.verb,
        value: &ask.value,
        organ: &ask.organ,
        call_verb: &ask.call_verb,
        grant: &ask.grant,
        // At most the wire's u32 milliseconds, as a local call's deadline.
        deadline: Instant::now() + Duration::from_millis(ask.deadline_ms.min(u64::from(u32::MAX))),
        max_bytes: ask.max_bytes,
        fetch: &fetch,
        signing: &signing,
    };
    let answered = {
        let _scope = HandlerScope::enter();
        handler.answer(&request)
    };
    let signed = signing.into_inner().unwrap_or_else(PoisonError::into_inner);
    (answered, signed)
}
