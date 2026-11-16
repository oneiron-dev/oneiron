//! The core queue's duplex wire to the VoxCPM2 worker: one versioned
//! WebSocket per queue, `GET /v1/voice` on the worker's loopback listener,
//! the bearer credential checked before the upgrade answers. Text frames are
//! one JSON object each with a `type` string; a binary frame follows only
//! the frame that announces it, with exactly the announced byte count. The
//! worker answers `ready` once after the upgrade; the queue sends `start`
//! lazily inside the first render of a generation, then one `text` frame per
//! render, and reads that render's `audio` frames until its `usage`. Frames
//! of another generation, and every `done`, are skipped; an `error` for the
//! render's generation fails it. After an I/O or protocol error the socket
//! is dropped and every later render on the queue fails; there is no
//! reconnect.
//!
//! Each render is one `ai.speech` call on the host's [`WireSeat`]: admitted
//! on its own permit before the reference leaves for the worker, and settled
//! on the characters it spoke. The writer thread owns the socket, so queuing
//! work never does I/O.

use super::GenerationEpoch;
use super::voxcpm2::{
    PcmSpool, RenderTarget, VoiceServingPolicyReceipt, VoxCpm2Audio, VoxCpm2Operation,
    VoxCpm2PcmBody, VoxCpm2Queue, VoxCpm2Work, WarmTarget,
};
use crate::llm::ModelLocality;
use crate::llm::media::{AiOperation, MediaPart, MediaUsage, MediaVoice};
use crate::llm::run_admission::{WireCallError, WireSeat};
use crate::voice_identity::ref_bank::{VoiceRefFence, VoiceRegisterClip};
use crate::{Vault, error::Result};
use oneiron_records::voice_cascade::voxcpm2::invalid;
use serde_json::{Value, json};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{
    Arc,
    mpsc::{self, Receiver, Sender, TryRecvError},
};
use std::{thread, time::Duration};
use tokio_tungstenite::tungstenite::client::client_with_config;
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{ClientRequestBuilder, Message, WebSocket};

/// The wire version this queue speaks: the `version` a `ready` frame carries.
pub const OUR_VOICE_VERSION: u64 = 1;
/// The worker path this queue upgrades: `GET /v1/voice` on loopback.
pub const OUR_VOICE_PATH: &str = "/v1/voice";
/// The largest audio binary frame the worker sends: a render's PCM arrives
/// split into frames of at most this many bytes, each with its own header.
pub const AUDIO_FRAME_MAX_BYTES: usize = 65_536;

/// One client frame: the queue's half of the wire. A generation rides as its
/// epoch's integer ([`GenerationEpoch::value`]).
#[derive(Debug, Clone)]
pub enum VoiceClientFrame {
    Start {
        generation: u64,
        target: Value,
        transcript_bytes: u64,
        reference_bytes: u64,
    },
    Text {
        generation: u64,
        text: String,
    },
    Flush {
        generation: u64,
    },
    End {
        generation: u64,
    },
    Cancel {
        generation: u64,
    },
}

impl VoiceClientFrame {
    /// The frame's JSON text: one object with its `type` string.
    #[must_use]
    pub fn to_json(&self) -> String {
        match self {
            Self::Start {
                generation,
                target,
                transcript_bytes,
                reference_bytes,
            } => json!({
                "type": "start",
                "generation": generation,
                "target": target,
                "transcript_bytes": transcript_bytes,
                "reference_bytes": reference_bytes,
            })
            .to_string(),
            Self::Text { generation, text } => json!({
                "type": "text",
                "generation": generation,
                "text": text,
            })
            .to_string(),
            Self::Flush { generation } => json!({
                "type": "flush",
                "generation": generation,
            })
            .to_string(),
            Self::End { generation } => json!({
                "type": "end",
                "generation": generation,
            })
            .to_string(),
            Self::Cancel { generation } => json!({
                "type": "cancel",
                "generation": generation,
            })
            .to_string(),
        }
    }
}

/// One server frame: the worker's half of the wire, parsed from JSON text.
#[derive(Debug, Clone)]
pub enum VoiceServerFrame {
    Ready {
        target: Value,
        capabilities: Value,
    },
    /// The whole `started` object, so its pins compare as the render reply
    /// header's did; its `generation` is read back out of `meta`.
    Started {
        meta: Value,
    },
    Audio {
        generation: u64,
        chunk_index: u64,
        bytes: u64,
    },
    Usage {
        generation: u64,
        characters: u64,
        audio_ms: u64,
    },
    Done {
        generation: u64,
    },
    Error {
        generation: Option<u64>,
        code: String,
    },
}

impl VoiceServerFrame {
    /// Parses one text frame's JSON. An unknown type, a missing field, or a
    /// `ready` whose version is not [`OUR_VOICE_VERSION`] refuses.
    pub fn parse(text: &str) -> Result<Self> {
        let frame: Value =
            serde_json::from_str(text).map_err(|_| invalid("invalid voice frame"))?;
        let frame_type = frame
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("invalid voice frame"))?;
        match frame_type {
            "ready" => {
                let version = field_u64(&frame, "version")?;
                if version != OUR_VOICE_VERSION {
                    return Err(invalid("unsupported voice version"));
                }
                Ok(Self::Ready {
                    target: field(&frame, "target")?,
                    capabilities: field(&frame, "capabilities")?,
                })
            }
            "started" => {
                let _ = field_u64(&frame, "generation")?;
                Ok(Self::Started { meta: frame })
            }
            "audio" => Ok(Self::Audio {
                generation: field_u64(&frame, "generation")?,
                chunk_index: field_u64(&frame, "chunk_index")?,
                bytes: field_u64(&frame, "bytes")?,
            }),
            "usage" => Ok(Self::Usage {
                generation: field_u64(&frame, "generation")?,
                characters: field_u64(&frame, "characters")?,
                audio_ms: field_u64(&frame, "audio_ms")?,
            }),
            "done" => Ok(Self::Done {
                generation: field_u64(&frame, "generation")?,
            }),
            "error" => Ok(Self::Error {
                generation: frame.get("generation").and_then(Value::as_u64),
                code: frame
                    .get("code")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("invalid voice frame"))?
                    .to_owned(),
            }),
            _ => Err(invalid("unknown voice frame type")),
        }
    }
}

/// One required object field, cloned out.
fn field(frame: &Value, name: &str) -> Result<Value> {
    frame
        .get(name)
        .cloned()
        .ok_or_else(|| invalid("invalid voice frame"))
}

/// One required unsigned integer field.
fn field_u64(frame: &Value, name: &str) -> Result<u64> {
    frame
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("invalid voice frame"))
}

pub enum VoxCpm2Event {
    Audio {
        generation: GenerationEpoch,
        submission: u64,
        chunk_index: u64,
        target: Box<RenderTarget>,
        body: Arc<VoxCpm2PcmBody>,
    },
    Failed {
        generation: GenerationEpoch,
        submission: u64,
    },
}
impl VoxCpm2Event {
    pub fn audio(&self) -> Option<VoxCpm2Audio<'_>> {
        if let Self::Audio {
            generation,
            submission,
            chunk_index,
            target,
            body,
        } = self
        {
            Some(VoxCpm2Audio {
                generation: *generation,
                submission: *submission,
                chunk_index: *chunk_index,
                target: *target.clone(),
                channels: 1,
                body,
            })
        } else {
            None
        }
    }
}

/// Single worker owns the request-scoped WAV. Connect outside a cascade lock.
/// Only the loopback worker is accepted: a remote host needs a separately
/// secured tunnel/proxy, never a public raw reference-upload endpoint.
pub struct OurVoiceQueue {
    sender: Sender<VoxCpm2Work>,
    responses: Receiver<VoxCpm2Event>,
    warm: WarmTarget,
    /// The vault's serving policy the worker was set up under, kept whole
    /// (FIX 8772): whether the shipped defaults stood in rides with it.
    serving_policy: VoiceServingPolicyReceipt,
}

impl OurVoiceQueue {
    /// Connects to the worker at `base_url`; each render it sends is a call
    /// on `seat`, the host's rung for the worker. The reference clip is the
    /// person's raw voice, so a third party's rung refuses.
    pub fn connect(
        vault: Arc<Vault>,
        base_url: &str,
        bearer: &str,
        seat: WireSeat,
    ) -> Result<Self> {
        if seat.locality() == ModelLocality::ThirdParty {
            return Err(invalid("a voice reference never goes to a third party"));
        }
        if bearer.len() < 32
            || bearer.len() > 512
            || !bearer.is_ascii()
            || bearer.bytes().any(|b| b.is_ascii_control())
        {
            return Err(invalid("invalid worker credential"));
        }
        let port = loopback_worker_port(base_url)?;
        let serving_policy = vault.voice_serving_policy(None)?;
        let vault_limits = serving_policy.limits;
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let deadline = Duration::from_millis(vault_limits.http_deadline_ms);
        // A plain loopback socket, so no environment proxy can apply.
        let stream = TcpStream::connect_timeout(&address, deadline)
            .map_err(|_| invalid("worker is not ready"))?;
        stream
            .set_read_timeout(Some(deadline))
            .map_err(|_| invalid("worker is not ready"))?;
        stream
            .set_write_timeout(Some(deadline))
            .map_err(|_| invalid("worker is not ready"))?;
        let bound = usize::try_from(vault_limits.max_header_bytes)
            .unwrap_or(usize::MAX)
            .max(AUDIO_FRAME_MAX_BYTES);
        let config = WebSocketConfig::default()
            .max_message_size(Some(bound))
            .max_frame_size(Some(bound));
        let uri: Uri = format!("ws://127.0.0.1:{port}{OUR_VOICE_PATH}")
            .parse()
            .map_err(|_| invalid("worker is not ready"))?;
        let request =
            ClientRequestBuilder::new(uri).with_header("Authorization", format!("Bearer {bearer}"));
        let (mut socket, _) = client_with_config(request, stream, Some(config))
            .map_err(|_| invalid("worker is not ready"))?;
        let target = loop {
            match socket.read().map_err(|_| invalid("worker is not ready"))? {
                Message::Text(text) => {
                    match VoiceServerFrame::parse(text.as_str())
                        .map_err(|_| invalid("worker is not ready"))?
                    {
                        VoiceServerFrame::Ready { target, .. } => break target,
                        _ => return Err(invalid("worker is not ready")),
                    }
                }
                Message::Ping(_) | Message::Pong(_) => continue,
                _ => return Err(invalid("worker is not ready")),
            }
        };
        let (warm, _) =
            WarmTarget::from_ready(target).map_err(|_| invalid("worker is not ready"))?;
        warm.validate()?;
        if !vault_limits.within(warm.limits) {
            return Err(invalid("worker policy narrower than vault limits"));
        }
        let (sender, work) = mpsc::channel();
        let (results, responses) = mpsc::channel();
        thread::Builder::new()
            .name("voxcpm2-voice".into())
            .spawn(move || {
                run_worker(vault, &seat, socket, work, results);
            })
            .map_err(|_| invalid("worker thread unavailable"))?;
        Ok(Self {
            sender,
            responses,
            warm,
            serving_policy,
        })
    }

    /// The vault serving policy this worker was set up under, and whether
    /// the shipped defaults stood in for an absent row.
    #[must_use]
    pub fn serving_policy(&self) -> VoiceServingPolicyReceipt {
        self.serving_policy
    }

    pub fn try_recv(&self) -> Result<Option<VoxCpm2Event>> {
        match self.responses.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(invalid("worker disconnected")),
        }
    }
}
impl VoxCpm2Queue for OurVoiceQueue {
    fn warm_target(&self) -> Result<WarmTarget> {
        Ok(self.warm.clone())
    }
    fn try_submit(&mut self, work: VoxCpm2Work) -> Result<()> {
        self.sender
            .send(work)
            .map_err(|_| invalid("worker disconnected"))
    }
}

/// The loopback port of a worker base URL: exactly
/// `http://127.0.0.1:<port>/`, the shape the old URL check admitted, without
/// the HTTP stack. The two refusals stay the old ones: a non-URL is not a
/// worker URL, and a URL for anywhere else is not the loopback worker.
fn loopback_worker_port(base_url: &str) -> Result<u16> {
    let after_scheme = match base_url.split_once("://") {
        Some((scheme, after)) if scheme.eq_ignore_ascii_case("http") => after,
        Some(_) => return Err(invalid("worker must be loopback HTTP with a port")),
        None => return Err(invalid("invalid worker URL")),
    };
    let after_host = after_scheme
        .strip_prefix("127.0.0.1:")
        .ok_or_else(|| invalid("worker must be loopback HTTP with a port"))?;
    let digits = after_host.bytes().take_while(u8::is_ascii_digit).count();
    let (port, path) = after_host.split_at(digits);
    if !matches!(path, "/" | "") {
        return Err(invalid("worker must be loopback HTTP with a port"));
    }
    if port.is_empty() {
        return Err(invalid("worker must be loopback HTTP with a port"));
    }
    port.parse().map_err(|_| invalid("invalid worker URL"))
}

/// One frame down the socket; a failure drops it, failing every render.
fn send_message(socket: &mut Option<WebSocket<TcpStream>>, message: Message) -> Result<()> {
    let Some(raw) = socket.as_mut() else {
        return Err(invalid("worker render failed"));
    };
    if raw.send(message).is_err() {
        *socket = None;
        return Err(invalid("worker render failed"));
    }
    Ok(())
}

/// One message off the socket; a failure drops it, failing every render.
fn read_message(socket: &mut Option<WebSocket<TcpStream>>) -> Result<Message> {
    let Some(raw) = socket.as_mut() else {
        return Err(invalid("worker render failed"));
    };
    match raw.read() {
        Ok(message) => Ok(message),
        Err(_) => {
            *socket = None;
            Err(invalid("worker render failed"))
        }
    }
}

/// The binary frame an `audio` header announced: exactly its byte count, or
/// the render fails and the socket drops.
fn read_binary(socket: &mut Option<WebSocket<TcpStream>>, announced: u64) -> Result<Vec<u8>> {
    loop {
        match read_message(socket)? {
            Message::Binary(bytes) => {
                if bytes.len() as u64 != announced {
                    *socket = None;
                    return Err(invalid("invalid worker metadata"));
                }
                return Ok(bytes.to_vec());
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            _ => {
                *socket = None;
                return Err(invalid("invalid worker metadata"));
            }
        }
    }
}

/// The `started` answer to a generation's `start`: its pins must match the
/// render's target, as the render reply header's did. Another generation's
/// frames, and every `done`, are skipped; its `error` refuses the start.
fn await_started(
    socket: &mut Option<WebSocket<TcpStream>>,
    target: &RenderTarget,
    generation: u64,
) -> Result<()> {
    loop {
        match read_message(socket)? {
            Message::Text(text) => {
                let frame = VoiceServerFrame::parse(text.as_str()).map_err(|_| {
                    *socket = None;
                    invalid("invalid worker metadata")
                })?;
                match frame {
                    VoiceServerFrame::Started { meta } => {
                        if meta.get("generation").and_then(Value::as_u64) != Some(generation) {
                            continue;
                        }
                        if meta["target"] != target_json(target)
                            || meta["sample_rate"].as_u64()
                                != Some(u64::from(target.warm.sample_rate))
                            || meta["channels"].as_u64() != Some(1)
                        {
                            return Err(invalid("worker target mismatch"));
                        }
                        return Ok(());
                    }
                    VoiceServerFrame::Error {
                        generation: failed, ..
                    } if failed == Some(generation) || failed.is_none() => {
                        return Err(invalid("worker render failed"));
                    }
                    VoiceServerFrame::Audio {
                        generation: other,
                        bytes: announced,
                        ..
                    } if other != generation => {
                        read_binary(socket, announced)?;
                    }
                    VoiceServerFrame::Usage {
                        generation: other, ..
                    } if other != generation => {
                        continue;
                    }
                    VoiceServerFrame::Done { .. } | VoiceServerFrame::Error { .. } => continue,
                    _ => {
                        *socket = None;
                        return Err(invalid("invalid worker metadata"));
                    }
                }
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            _ => {
                *socket = None;
                return Err(invalid("worker render failed"));
            }
        }
    }
}

/// One render's reply: every `audio` binary frame of its generation streams
/// into one spool, until its `usage`. Skipped as in [`await_started`].
fn read_audio_reply(
    socket: &mut Option<WebSocket<TcpStream>>,
    vault: &Vault,
    generation: u64,
) -> Result<VoxCpm2PcmBody> {
    // Rule 5: a render's audio is taken whole, however long it speaks. It
    // streams into a spool, in memory up to the result-body inline bound
    // and spilled past it, never into one growing buffer.
    let mut spool = PcmSpool::new(vault)?;
    loop {
        match read_message(socket)? {
            Message::Text(text) => {
                let frame = VoiceServerFrame::parse(text.as_str()).map_err(|_| {
                    *socket = None;
                    invalid("invalid worker metadata")
                })?;
                match frame {
                    VoiceServerFrame::Audio {
                        generation: other,
                        bytes: announced,
                        ..
                    } => {
                        let chunk = read_binary(socket, announced)?;
                        if other == generation {
                            spool.write(&chunk)?;
                        }
                    }
                    VoiceServerFrame::Usage {
                        generation: other, ..
                    } => {
                        if other != generation {
                            continue;
                        }
                        break;
                    }
                    VoiceServerFrame::Done { .. } => continue,
                    VoiceServerFrame::Error {
                        generation: failed, ..
                    } => {
                        if failed == Some(generation) || failed.is_none() {
                            return Err(invalid("worker render failed"));
                        }
                    }
                    _ => {
                        *socket = None;
                        return Err(invalid("invalid worker metadata"));
                    }
                }
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            _ => {
                *socket = None;
                return Err(invalid("worker render failed"));
            }
        }
    }
    let body = spool.finish(vault)?;
    if body.is_empty() {
        return Err(invalid("invalid worker metadata"));
    }
    Ok(body)
}

/// One render on the socket: the generation's `start` goes lazily inside its
/// first render's admitted send, then this render's `text`, and its `audio`
/// frames spool until its `usage`.
fn render_on_wire(
    vault: &Vault,
    socket: &mut Option<WebSocket<TcpStream>>,
    started_on_wire: &mut Option<u64>,
    target: &RenderTarget,
    reference: &VoiceRegisterClip,
    text: &str,
    generation: u64,
) -> Result<VoxCpm2PcmBody> {
    if socket.is_none() {
        return Err(invalid("worker render failed"));
    }
    if let Some(raw) = socket.as_mut() {
        let deadline = Duration::from_millis(target.limits.http_deadline_ms);
        if raw.get_mut().set_read_timeout(Some(deadline)).is_err()
            || raw.get_mut().set_write_timeout(Some(deadline)).is_err()
        {
            *socket = None;
            return Err(invalid("worker render failed"));
        }
    }
    // The generation's `start` goes only with its first render on the wire.
    let start_json = (*started_on_wire != Some(generation)).then(|| {
        VoiceClientFrame::Start {
            generation,
            target: target_json(target),
            transcript_bytes: reference.transcript.len() as u64,
            reference_bytes: reference.audio.len() as u64,
        }
        .to_json()
    });
    let text_json = VoiceClientFrame::Text {
        generation,
        text: text.to_owned(),
    }
    .to_json();
    // Oversize metadata is refused before a byte leaves, as today; the
    // reference clip itself still goes whole, however long (Rule 5).
    let bound = target.limits.max_header_bytes;
    if text_json.len() as u64 > bound
        || start_json.as_ref().is_some_and(|start| {
            start.len() as u64 > bound || reference.transcript.len() as u64 > bound
        })
    {
        return Err(invalid("request metadata exceeds serving policy"));
    }
    if let Some(start_json) = start_json {
        send_message(socket, Message::text(start_json))?;
        send_message(socket, Message::from(reference.transcript.as_bytes()))?;
        send_message(socket, Message::from(reference.audio.as_slice()))?;
        *started_on_wire = Some(generation);
        await_started(socket, target, generation)?;
    }
    send_message(socket, Message::text(text_json))?;
    read_audio_reply(socket, vault, generation)
}

/// The bank's revision of the identity's refs a render is fenced at, in hex.
fn reference_revision(fence: &VoiceRefFence) -> String {
    fence
        .incarnation
        .iter()
        .flatten()
        .chain(&fence.ref_digest)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn target_json(target: &RenderTarget) -> Value {
    let fence = &target.fence;
    let revision = reference_revision(fence);
    json!({"voice_id": target.voice_id, "owner": fence.owner.to_hex(),
        "register": target.register, "reference_revision": revision,
        "limits": target.limits,
        "warm": {"model": target.warm.model, "checkpoint": target.warm.checkpoint,
            "boot_id": target.warm.boot_id, "sample_rate": target.warm.sample_rate,
            "limits": target.warm.limits}})
}

/// One render as one call on `seat`: its permit starts before `send`'s
/// request leaves, and an answer settles on the characters it spoke, with
/// the render's inference receipt (FIX 8314).
fn admitted_render(
    seat: &WireSeat,
    target: &RenderTarget,
    reference: &VoiceRegisterClip,
    text: &str,
    send: impl FnOnce() -> Result<VoxCpm2PcmBody>,
) -> Result<VoxCpm2PcmBody> {
    let request = seat.request(
        AiOperation::Speech,
        vec![MediaPart::Text {
            text: text.to_owned(),
        }],
        Some(MediaVoice::Reference {
            voice_id: target.voice_id.clone(),
            owner: target.fence.owner.to_hex(),
            register: reference.register.clone(),
            revision: reference_revision(&target.fence),
            media_type: reference.media_type.clone(),
            audio: reference.audio.clone(),
            transcript: reference.transcript.clone(),
        }),
    );
    let receipt = target.warm.render_receipt(&request.model);
    seat.call(&request, send, |_| {
        let mut usage = MediaUsage {
            characters: u64::try_from(text.chars().count()).unwrap_or(u64::MAX),
            ..MediaUsage::default()
        };
        usage.put_inference_calls(&[receipt]);
        usage
    })
    .map_err(|error| match error {
        WireCallError::Refused(_) => invalid("run admission refused the render"),
        WireCallError::Failed(error) => error,
    })
}

fn run_worker(
    vault: Arc<Vault>,
    seat: &WireSeat,
    socket: WebSocket<TcpStream>,
    work: Receiver<VoxCpm2Work>,
    results: Sender<VoxCpm2Event>,
) {
    let mut active: Option<(GenerationEpoch, RenderTarget)> = None;
    let mut chunk_index = 0;
    let mut socket = Some(socket);
    let mut started_on_wire: Option<u64> = None;
    while let Ok(item) = work.recv() {
        match item.operation {
            VoxCpm2Operation::Start { target } => {
                // A new target sends its own reference: the held one ends first.
                if let Some(held) = started_on_wire.take() {
                    let end = VoiceClientFrame::End { generation: held };
                    let _ = send_message(&mut socket, Message::text(end.to_json()));
                }
                active = Some((item.generation, *target));
                chunk_index = 0;
            }
            VoxCpm2Operation::Cancel => {
                if started_on_wire == Some(item.generation.value()) {
                    started_on_wire = None;
                    let cancel = VoiceClientFrame::Cancel {
                        generation: item.generation.value(),
                    };
                    let _ = send_message(&mut socket, Message::text(cancel.to_json()));
                }
                active = None;
            }
            VoxCpm2Operation::Render { text } => {
                let event = match active.as_ref() {
                    Some((epoch, target)) if *epoch == item.generation => {
                        match target.with_current(&vault, |reference| {
                            admitted_render(seat, target, reference, &text, || {
                                render_on_wire(
                                    &vault,
                                    &mut socket,
                                    &mut started_on_wire,
                                    target,
                                    reference,
                                    &text,
                                    item.generation.value(),
                                )
                            })
                        }) {
                            Ok(body) => {
                                let event = VoxCpm2Event::Audio {
                                    generation: item.generation,
                                    submission: item.sequence,
                                    chunk_index,
                                    target: Box::new(target.clone()),
                                    body: Arc::new(body),
                                };
                                chunk_index += 1;
                                event
                            }
                            Err(_) => {
                                active = None;
                                VoxCpm2Event::Failed {
                                    generation: item.generation,
                                    submission: item.sequence,
                                }
                            }
                        }
                    }
                    _ => VoxCpm2Event::Failed {
                        generation: item.generation,
                        submission: item.sequence,
                    },
                };
                // A stopped session (its queue dropped) must not hold this worker.
                if results.send(event).is_err() {
                    active = None;
                }
            }
        }
    }
    if let Some(held) = started_on_wire.take() {
        let end = VoiceClientFrame::End { generation: held };
        let _ = send_message(&mut socket, Message::text(end.to_json()));
    }
    let _ = send_message(&mut socket, Message::Close(None));
}
