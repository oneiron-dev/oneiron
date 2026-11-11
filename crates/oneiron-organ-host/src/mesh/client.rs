//! The asking side of a mesh organ call: stage the inputs, send the call,
//! answer the organ's asks while it runs, take the outputs back. The bytes
//! this node takes back, the reply and each output, lease this machine's
//! memory floor before they are allocated, and an output keeps its lease
//! while it lives (FIX 6196). What it sends leases the floor while it
//! crosses: a handler's answer until it is sent, each staged piece while
//! its exchange runs (FIX 10577). The organ's own memory stays its host's:
//! `memory.grow` is never answered here.

use std::collections::HashSet;
use std::io;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron_mesh_transport::{MeshConnection, MeshError, MeshStream};
use oneiron_organ_protocol::{ASK_MEMORY_GROW, AskCode, AskRefusal, ByteBuf, Hash32};

use super::{
    Carried, FailureKind, INLINE, Offer, PIECE, PeerAnswer, PeerAnswered, PeerAsk, PeerCall,
    PeerInput, PeerOutcome, PeerResult, Reply, Request, decode, encode, exchange,
};
use crate::budget::Stop;
use crate::clock::Clock;
use crate::error::HostError;
use crate::handlers::{Answered, AskHandlers, AskRequest, HandlerScope};
use crate::outcome::{Leased, OrganOutcome, OrganOutput, OutputBytes};
use crate::resource_memory::{FloorRefusal, SharedFloor};
use crate::shutdown;
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

/// Stages bytes on the serving node, unless they ride inline. Each piece
/// leases `here` for its copy and its encoded message while it crosses.
async fn put(
    conn: &dyn MeshConnection,
    bytes: &[u8],
    sent: &mut HashSet<Hash32>,
    here: Here<'_>,
) -> Result<Carried, MeshError> {
    if bytes.len() <= INLINE {
        return Ok(Carried::Inline(ByteBuf::from(bytes.to_vec())));
    }
    let hash = Hash32::of(bytes);
    let total = bytes.len() as u64;
    if sent.insert(hash) {
        for (n, piece) in bytes.chunks(PIECE).enumerate() {
            let _held = here.hold_sent((piece.len() as u64).saturating_mul(2))?;
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

/// This node's memory floor for the bytes a call takes back or sends, and
/// the call's deadline, which a wait for it keeps.
#[derive(Clone, Copy)]
struct Here<'a> {
    floor: Option<&'a SharedFloor>,
    deadline: Instant,
}

impl Here<'_> {
    /// A lease of this machine's memory for staged bytes about to be taken
    /// back, before they are allocated; none for bytes that rode inline, or
    /// with no floor here.
    fn hold(self, carried: &Carried) -> Result<Option<Leased>, PeerError> {
        let Carried::Staged { len, .. } = carried else {
            return Ok(None);
        };
        self.lease(*len).map_err(PeerError::Failed)
    }

    /// A lease of this machine's memory for `len` bytes this node sends,
    /// held until they are sent; none with no floor here. A refusal ends
    /// the send as the mesh's own error.
    fn hold_sent(self, len: u64) -> Result<Option<Leased>, MeshError> {
        self.lease(len)
            .map_err(|err| MeshError::Io(format!("organ mesh send: {err}")))
    }

    /// A lease of `len` bytes of this machine's memory, within the call's
    /// deadline; none with no floor here.
    fn lease(self, len: u64) -> Result<Option<Leased>, HostError> {
        let Some(floor) = self.floor else {
            return Ok(None);
        };
        let held = floor
            .0
            .lease(len, self.deadline, &|| false)
            .map_err(refused_here)?;
        Ok(Some(Leased::new(held)))
    }
}

/// This node's floor's refusal, as the call's error.
fn refused_here(refused: FloorRefusal) -> HostError {
    match refused {
        FloorRefusal::Floor { needed, available } => HostError::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!("this node's memory floor: {needed} bytes needed, {available} available"),
        )),
        FloorRefusal::Deadline => HostError::DeadlineExceeded,
    }
}

/// The bytes a reply named, got in pieces when staged, checked against
/// their hash.
async fn take(conn: &dyn MeshConnection, carried: Carried) -> Result<Vec<u8>, MeshError> {
    let (hash, len) = match carried {
        Carried::Inline(bytes) => return Ok(bytes.into_vec()),
        Carried::Staged { hash, len } => (hash, len),
    };
    let want = usize::try_from(len)
        .ok()
        .filter(|len| *len <= isize::MAX as usize)
        .ok_or_else(|| MeshError::Io("staged bytes too long".into()))?;
    let mut bytes = Vec::new();
    while bytes.len() < want {
        let request = Request::Get {
            hash,
            offset: bytes.len() as u64,
        };
        match exchange(conn, &request).await? {
            Reply::Piece(piece) if !piece.is_empty() && piece.len() <= want - bytes.len() => {
                bytes.try_reserve_exact(piece.len()).map_err(|error| {
                    MeshError::Io(format!("staged bytes allocation failed: {error}"))
                })?;
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
/// line lands in `asks` as a local call's would. What comes back leases
/// `floor`, this machine's, before it is allocated, and what goes out
/// leases it while it crosses. Under a mesh stop's cancel the call is
/// dropped there once the cancel comes, and it says
/// [`HostError::Interrupted`] (FIX 4756).
pub(crate) async fn call_on(
    conn: &dyn MeshConnection,
    machine: EntityId,
    call: &OrganCall,
    inputs: &[(Option<OrganInput>, LentInput)],
    asks: &AskHandlers<'_>,
    floor: Option<&SharedFloor>,
) -> Result<OrganOutcome, PeerError> {
    let longest = Duration::from_millis(u64::from(u32::MAX));
    let here = Here {
        floor,
        deadline: Instant::now() + call.deadline.min(longest),
    };
    // Read on the blocking thread the router drives this call from.
    let cancel = shutdown::current();
    let mut sent = HashSet::new();
    let mut wire = Vec::with_capacity(inputs.len());
    for (read, input) in inputs {
        wire.push(PeerInput {
            read: read.map(|read| (read.artifact.to_hex(), read.version)),
            media_type: input.media_type.clone(),
            bytes: put(conn, &input.bytes, &mut sent, here)
                .await
                .map_err(absent)?,
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
        put(conn, &encoded, &mut sent, here).await.map_err(absent)?
    };
    let mut stream = conn.open_stream().await.map_err(absent)?;
    stream
        .send(&encode(&Request::Call { call: carried }).map_err(absent)?)
        .await
        .map_err(absent)?;
    let mut receipts = AttemptReceipts {
        asked: &asks.asked,
        lines: Vec::new(),
    };
    let reply = {
        let mut reply = stream.recv();
        loop {
            tokio::select! {
                got = &mut reply => break got,
                () = shutdown::cancelled(cancel.as_ref()) => {
                    return Err(PeerError::Failed(HostError::Interrupted));
                }
                incoming = conn.accept_stream() => match incoming {
                    // An ask this side failed to answer leaves the organ
                    // a refusal from its own host; the call goes on.
                    Ok(ask) => drop(answer(conn, ask, asks, &mut sent, here, &mut receipts.lines).await),
                    Err(err) => break Err(err),
                },
            }
        }
    };
    let result = match decode::<Reply>(&reply.map_err(absent)?).map_err(absent)? {
        Reply::Call(carried) => {
            let _held = here.hold(&carried)?;
            decode::<PeerResult>(&take(conn, carried).await.map_err(absent)?).map_err(absent)?
        }
        other => return Err(absent(unexpected(&other))),
    };
    match result {
        PeerResult::Done(mut outcome) => {
            receipts.reconcile(std::mem::take(&mut outcome.receipt.asks));
            outcome.receipt.asks = receipts.lines.clone();
            received(conn, outcome, here).await
        }
        PeerResult::Failed(failure) => {
            receipts.reconcile(failure.asks);
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

/// This one mesh attempt's receipt, retained before each callback and
/// published on every exit, just as `CallAsks` publishes its local lines.
/// Router retries each own a fresh instance; ids are never merged globally.
struct AttemptReceipts<'a> {
    asked: &'a Mutex<Vec<crate::receipt::AskReceipt>>,
    lines: Vec<crate::receipt::AskReceipt>,
}

impl AttemptReceipts<'_> {
    /// The serving host records what the organ was lent, in call order.
    /// Keep those facts, adding this node's own signing fact when present.
    fn reconcile(&mut self, mut peer: Vec<crate::receipt::AskReceipt>) {
        let local_unique: Vec<_> = self
            .lines
            .iter()
            .map(|local| {
                self.lines
                    .iter()
                    .filter(|other| same_ask(local, other))
                    .count()
                    == 1
            })
            .collect();
        let mut used = vec![false; peer.len()];
        let mut unmatched = Vec::new();
        for (local, unique) in self.lines.drain(..).zip(local_unique) {
            // A signing fact already recorded by the serving host proves
            // this occurrence, even when an earlier refusal has the same id.
            let proven = local.signed.as_ref().and_then(|signed| {
                peer.iter().enumerate().position(|(index, line)| {
                    !used[index] && same_ask(&local, line) && line.signed.as_ref() == Some(signed)
                })
            });
            let matched = proven.or_else(|| {
                if !unique || peer.iter().filter(|line| same_ask(&local, line)).count() != 1 {
                    return None;
                }
                peer.iter().enumerate().position(|(index, line)| {
                    !used[index]
                        && same_ask(&local, line)
                        && (local.signed.is_none() || line.signed.is_none())
                })
            });
            if let Some(index) = matched {
                used[index] = true;
                if local.signed.is_some() {
                    peer[index].signed = local.signed;
                }
            } else {
                // Duplicate identities without a signing proof do not name
                // an occurrence. Keep the local evidence separate instead.
                unmatched.push(local);
            }
        }
        if !unmatched.is_empty() {
            peer.extend(unmatched);
            // Only this attempt's one serving call is here. Stable sorting
            // retains peer and local occurrence order for repeated ids.
            peer.sort_by_key(|line| line.id);
        }
        self.lines = peer;
    }
}

fn same_ask(left: &crate::receipt::AskReceipt, right: &crate::receipt::AskReceipt) -> bool {
    left.id == right.id && left.verb == right.verb && left.value_digest == right.value_digest
}

impl Drop for AttemptReceipts<'_> {
    fn drop(&mut self) {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .append(&mut self.lines);
    }
}

/// Takes the outputs back and checks each against the serving host's
/// receipt: the bytes that came are the bytes it hashed.
async fn received(
    conn: &dyn MeshConnection,
    outcome: PeerOutcome,
    here: Here<'_>,
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
        let leased = here.hold(&output.bytes)?;
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
            _leased: leased,
        });
    }
    Ok(OrganOutcome {
        body,
        outputs,
        report,
        receipt,
        _frame: None,
    })
}

/// Answers one ask the serving node sent back, through this side's
/// handler for its verb. The answer, value and data, leases `here` until
/// it is sent; a refusal there leaves the organ its own host's refusal.
async fn answer(
    conn: &dyn MeshConnection,
    mut stream: Box<dyn MeshStream>,
    asks: &AskHandlers<'_>,
    sent: &mut HashSet<Hash32>,
    here: Here<'_>,
    lines: &mut Vec<crate::receipt::AskReceipt>,
) -> Result<(), MeshError> {
    let ask: PeerAsk = decode(&stream.recv().await?)?;
    let (answered, signed, slot) = run_handler(&ask, asks, lines);
    let _held = match &answered {
        Ok(Answered { value, data, .. }) => {
            let value_len = oneiron_organ_protocol::encoded_len(value).unwrap_or(0);
            let data_len = data.as_ref().map_or(0, |bytes| bytes.len() as u64);
            here.hold_sent(value_len.saturating_add(data_len))?
        }
        Err(_) => None,
    };
    let answered = match answered {
        Ok(Answered { value, data, fetch }) => Ok(PeerAnswered {
            value,
            data: match data {
                Some(bytes) => Some(put(conn, &bytes, sent, here).await?),
                None => None,
            },
            fetch,
        }),
        Err(refusal) => Err(refusal),
    };
    let encoded = encode(&PeerAnswer { answered, signed })?;
    // Sending may partially succeed even on an error. Only the serving
    // host's final receipt can confirm what the organ received.
    lines[slot].unanswered = Some(crate::receipt::Unanswered::Unknown);
    stream.send(&encoded).await
}

fn run_handler(
    ask: &PeerAsk,
    asks: &AskHandlers<'_>,
    lines: &mut Vec<crate::receipt::AskReceipt>,
) -> (
    Result<Answered, AskRefusal>,
    Option<crate::receipt::SignedReceipt>,
    usize,
) {
    let slot = lines.len();
    lines.push(crate::receipt::AskReceipt {
        id: ask.id,
        verb: ask.verb.clone(),
        value_digest: crate::receipt::digest(&ask.value),
        refused: None,
        answer_len: 0,
        answer_digest: None,
        data_hash: None,
        data_len: 0,
        fetch: None,
        handler_us: 0,
        unanswered: Some(crate::receipt::Unanswered::NotSent),
        signed: None,
    });
    let Some(handler) = asks.get(&ask.verb) else {
        let refusal = AskRefusal::new(
            AskCode::NotGranted,
            "the asking node has no handler for this ask",
        );
        lines[slot].refused = Some(refusal.code);
        return (Err(refusal), None, slot);
    };
    // The organ's memory is its own host's to reserve, where the organ runs
    // (FIX 7654): this node holds neither its room nor its machine, so a
    // memory ask sent here is refused, never granted.
    if ask.verb == ASK_MEMORY_GROW {
        let refusal = AskRefusal::new(
            AskCode::NotGranted,
            "memory is reserved where the organ runs, never on the asking node",
        );
        lines[slot].refused = Some(refusal.code);
        return (Err(refusal), None, slot);
    }
    let signing = Mutex::new(None);
    // A fetch runs where the organ runs, under that install's allowlist.
    let fetch = FetchGrant::default();
    // At most the wire's u32 milliseconds, as a local call's deadline. This
    // node holds no room for the call, so no wait for room moves it.
    let deadline = Instant::now() + Duration::from_millis(ask.deadline_ms.min(u64::from(u32::MAX)));
    let request = AskRequest {
        verb: &ask.verb,
        value: &ask.value,
        organ: &ask.organ,
        call_verb: &ask.call_verb,
        grant: &ask.grant,
        call: ask.call,
        id: ask.id,
        deadline,
        clock: Clock::fixed(deadline),
        max_bytes: ask.max_bytes,
        fetch: &fetch,
        signing: &signing,
        // The organ's host holds the call's room; this node holds none.
        room: None,
        revoked: Stop::NEVER,
    };
    let mut recording = RecordingAsk {
        line: &mut lines[slot],
        signing: &signing,
        started: Instant::now(),
    };
    let answered = {
        let _scope = HandlerScope::enter();
        handler.answer(&request)
    };
    recording.finish(&answered);
    drop(recording);
    let signed = lines[slot].signed.clone();
    (answered, signed, slot)
}

/// The running callback's exact line and signing mutex. Both normal
/// return and unwind retain its prehash before any async send can fail.
struct RecordingAsk<'a> {
    line: &'a mut crate::receipt::AskReceipt,
    signing: &'a Mutex<Option<crate::receipt::SignedReceipt>>,
    started: Instant,
}

impl RecordingAsk<'_> {
    fn finish(&mut self, answered: &Result<Answered, AskRefusal>) {
        match answered {
            Ok(Answered { value, data, fetch }) => {
                self.line.fetch = fetch.clone();
                let value_len = oneiron_organ_protocol::encoded_len(value).unwrap_or(0);
                let data_len = data.as_ref().map_or(0, |bytes| bytes.len() as u64);
                self.line.answer_len = value_len.saturating_add(data_len);
                self.line.answer_digest = Some(crate::receipt::digest(value));
                if let Some(bytes) = data {
                    self.line.data_hash = Some(Hash32::of(bytes));
                    self.line.data_len = data_len;
                }
            }
            Err(refusal) => self.line.refused = Some(refusal.code),
        }
    }
}

impl Drop for RecordingAsk<'_> {
    fn drop(&mut self) {
        self.line.signed = self
            .signing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.line.handler_us =
            u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
    }
}
