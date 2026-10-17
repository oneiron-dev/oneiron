//! Soniox's real-time speech-to-text socket (OF-410): a live
//! `[models.media.transcribe]` rung. The voice cascade hears the owner on it
//! as they speak ([`ModelRuntime::open_voice_asr`]); a buffered
//! `ai.transcribe` call refuses on it.
//!
//! The key is read from the provider's `key_env` when the rung is built and
//! rides each WebSocket upgrade as a bearer, marked sensitive, and nowhere
//! else: not the opening config, not the media door, not a receipt.
//!
//! One socket carries one segment of the call, on a stream lease of its own
//! of at most [`oneiron::voice_cascade::media::MAX_STREAM_AUDIO_MS`], admitted before the socket opens. At
//! that bound the segment ends (an empty binary frame) and drains until
//! `finished`, and the next opens on a fresh lease. The words the old one
//! made final carry over to the utterance still open, never as an owner's
//! Final; only the owner's cut, answered by `<fin>`, finalizes one.
//!
//! A socket that drops (it fails or closes before its `finished`, or Soniox
//! reports a request timeout or a failure of its own) is reconnected once:
//! the next segment opens on a fresh lease, the dropped one's final words
//! carried, and what it had not sent yet goes to the next. A cut it sent
//! whose `<fin>` never came is answered with the words carried. Audio it
//! sent that Soniox had not made final is lost. A second drop before the
//! next socket says anything fails the hearing.
use std::collections::{BTreeMap, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{Sink, Stream};
use oneiron::llm::media::{AiOperation, MediaBackend, MediaFuture, MediaRequest, MediaResponse};
use oneiron::voice_cascade::media::{LeasedAsrStream, MediaVoiceRoute};
use oneiron::voice_cascade::soniox::{SonioxAsrClient, SonioxTransport, SonioxUpdate};
use oneiron::voice_cascade::{AsrEvent, AsrEventKind, AsrStream, AsrToken};
use oneiron::{BudgetLease, FatalLlmError};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue, header::AUTHORIZATION};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::ModelRuntime;
use super::catalog::engine_model_id;
use crate::config::models::{LiveAsrOptions, ModelsConfig, ProviderConfig};

/// The most bytes a live hearing queues: frames waiting for the socket, and
/// audio waiting for a segment to open. Past it the socket is not keeping
/// up, and the hearing fails.
const QUEUE_LIMIT_BYTES: usize = 4 * 1024 * 1024;
/// A segment that has sent nothing for this long sends a keepalive, so a
/// silence gap does not end it.
const KEEPALIVE_AFTER: Duration = Duration::from_secs(5);
/// Soniox error codes a fresh socket may clear: a request timeout and the
/// server's own failures. Any other error fails the hearing.
const RETRIABLE_ERROR_CODES: [u64; 5] = [408, 500, 502, 503, 504];
/// The control frame that asks Soniox to finalize every word so far.
const FINALIZE: &str = r#"{"type":"finalize"}"#;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type Opening = Pin<Box<dyn Future<Output = oneiron::Result<Segment>> + Send>>;

fn invalid(message: &str) -> oneiron::Error {
    oneiron::Error::InvalidConfig(format!("soniox: {message}"))
}

/// One live rung: where its socket opens, its key, and what it listens for.
pub(crate) struct SonioxRung {
    url: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    model: String,
    language_hints: Vec<String>,
    /// How long the upgrade may take.
    timeout: Duration,
}

impl SonioxRung {
    /// A configured `key_env` that is unset or empty is a refusal here, so
    /// the rung drops out of its ladder rather than open unauthenticated.
    fn new(
        provider: &ProviderConfig,
        model: &str,
        options: &LiveAsrOptions,
    ) -> anyhow::Result<Self> {
        let mut headers = Vec::new();
        for (name, value) in &provider.headers {
            headers.push((
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            ));
        }
        headers.push((AUTHORIZATION, bearer(provider)?));
        Ok(Self {
            url: provider.base_url.clone(),
            headers,
            model: model.to_owned(),
            language_hints: options.language_hints.clone(),
            timeout: Duration::from_secs(provider.timeout_secs.min(30)),
        })
    }

    /// The socket's first frame: what it hears, and how.
    fn config(&self, sample_rate: u32, channels: u16) -> String {
        serde_json::json!({
            "model": self.model,
            "audio_format": "pcm_s16le",
            "sample_rate": sample_rate,
            "num_channels": channels,
            "enable_endpoint_detection": true,
            "language_hints": self.language_hints,
        })
        .to_string()
    }
}

fn bearer(provider: &ProviderConfig) -> anyhow::Result<HeaderValue> {
    let env = provider
        .key_env
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("a soniox provider takes its key from key_env"))?;
    let key = std::env::var(env)
        .ok()
        .filter(|key| !key.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{env} is not set"))?;
    let mut value = HeaderValue::from_str(&format!("Bearer {}", key.trim()))
        .map_err(|_| anyhow::anyhow!("{env} is not a header value"))?;
    value.set_sensitive(true);
    Ok(value)
}

/// Each soniox rung of the transcribe seat, by its engine id. A rung whose
/// key is missing serves no live hearing.
pub(super) fn live_rungs(config: &ModelsConfig) -> BTreeMap<String, Arc<SonioxRung>> {
    let mut rungs = BTreeMap::new();
    let Some(seat) = config.media.seats.get(&AiOperation::Transcribe) else {
        return rungs;
    };
    for (model, options) in &seat.live_asr {
        let provider = &config.providers[&model.provider];
        let Ok(id) = engine_model_id(model, provider) else {
            continue;
        };
        match SonioxRung::new(provider, &model.model, options) {
            Ok(rung) => {
                rungs.insert(id.as_str().to_owned(), Arc::new(rung));
            }
            Err(error) => {
                tracing::warn!(provider = %model.provider, %error, "live transcribe rung unavailable");
            }
        }
    }
    rungs
}

/// A soniox rung's media client. It hears live only, so a buffered call
/// refuses; nothing falls back to another wire.
struct LiveOnly;

impl MediaBackend for LiveOnly {
    fn run<'a>(
        &'a self,
        _request: MediaRequest,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(async { Err(FatalLlmError::InvalidRequest.into()) })
    }
}

/// The media client of a soniox provider: one that refuses buffered calls,
/// once its key is there.
pub(super) fn live_backend(provider: &ProviderConfig) -> anyhow::Result<Arc<dyn MediaBackend>> {
    bearer(provider)?;
    Ok(Arc::new(LiveOnly))
}

/// The Soniox client's transport: frames queue here, in order, and the
/// live hearing sends them as the socket takes them.
#[derive(Default)]
struct Outbox {
    frames: VecDeque<Message>,
    bytes: usize,
}

impl Outbox {
    fn push(&mut self, frame: Message) -> oneiron::Result<()> {
        let bytes = self.bytes.saturating_add(frame.len());
        if bytes > QUEUE_LIMIT_BYTES {
            return Err(invalid("the socket is not keeping up"));
        }
        self.bytes = bytes;
        self.frames.push_back(frame);
        Ok(())
    }

    fn pop(&mut self) -> Option<Message> {
        let frame = self.frames.pop_front()?;
        self.bytes -= frame.len();
        Some(frame)
    }
}

impl SonioxTransport for Outbox {
    fn submit_audio(&mut self, bytes: &[u8]) -> oneiron::Result<()> {
        self.push(Message::binary(bytes.to_vec()))
    }

    fn submit_finalize(&mut self) -> oneiron::Result<()> {
        self.push(Message::text(FINALIZE))
    }

    fn submit_end(&mut self) -> oneiron::Result<()> {
        self.push(Message::binary(Vec::new()))
    }
}

/// One socket and the lease its audio is metered on.
struct Segment {
    stream: LeasedAsrStream<SonioxAsrClient<Outbox>>,
    socket: Socket,
    /// Its end is queued: it is read on until `finished`.
    ending: bool,
}

impl Segment {
    /// Admitted first, so a refused stream opens no socket; its config is
    /// the first frame queued.
    async fn open(
        rung: Arc<SonioxRung>,
        door: Arc<ModelRuntime>,
        route: MediaVoiceRoute,
        sample_rate: u32,
        channels: u16,
    ) -> oneiron::Result<Self> {
        let mut outbox = Outbox::default();
        outbox.push(Message::text(rung.config(sample_rate, channels)))?;
        let stream = LeasedAsrStream::open(
            &*door,
            &route,
            sample_rate,
            channels,
            SonioxAsrClient::new(outbox),
        )
        .await?;
        let mut request = rung
            .url
            .as_str()
            .into_client_request()
            .map_err(|_| invalid("base_url is not a socket request"))?;
        for (name, value) in &rung.headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        let (socket, _) =
            tokio::time::timeout(rung.timeout, tokio_tungstenite::connect_async(request))
                .await
                .map_err(|_| invalid("the socket did not open in time"))?
                .map_err(|error| invalid(&format!("the socket did not open: {error}")))?;
        Ok(Self {
            stream,
            socket,
            ending: false,
        })
    }

    /// Sends what the outbox holds, as far as the socket takes it now.
    /// Each frame leaves the outbox only once the socket has room for it,
    /// so a poll dropped part-way loses none. Whether any frame went out.
    fn send(&mut self, cx: &mut Context<'_>) -> oneiron::Result<bool> {
        let mut sent = false;
        loop {
            if self.stream.inner_mut().transport().frames.is_empty() {
                break;
            }
            match Pin::new(&mut self.socket).poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Err(socket_error(&error)),
                Poll::Pending => break,
            }
            let Some(frame) = self.stream.inner_mut().transport_mut().pop() else {
                break;
            };
            Pin::new(&mut self.socket)
                .start_send(frame)
                .map_err(|error| socket_error(&error))?;
            sent = true;
        }
        // Also carries the pong a ping is answered with.
        if let Poll::Ready(Err(error)) = Pin::new(&mut self.socket).poll_flush(cx) {
            return Err(socket_error(&error));
        }
        Ok(sent)
    }

    /// The socket's next frame, once what is queued went out as far as the
    /// socket takes it, with a keepalive after [`KEEPALIVE_AFTER`] quiet. A
    /// frame that does not parse is an error, not a drop.
    fn poll_heard(
        &mut self,
        quiet: &mut Pin<Box<tokio::time::Sleep>>,
        cx: &mut Context<'_>,
    ) -> Poll<oneiron::Result<Heard>> {
        loop {
            match self.send(cx) {
                Ok(true) => quiet
                    .as_mut()
                    .reset(tokio::time::Instant::now() + KEEPALIVE_AFTER),
                Ok(false) => {}
                Err(error) => return Poll::Ready(Ok(Heard::Dropped(error))),
            }
            if !self.ending && quiet.as_mut().poll(cx).is_ready() {
                self.stream
                    .inner_mut()
                    .transport_mut()
                    .push(Message::text(r#"{"type":"keepalive"}"#))?;
                quiet
                    .as_mut()
                    .reset(tokio::time::Instant::now() + KEEPALIVE_AFTER);
                continue;
            }
            let text = match Pin::new(&mut self.socket).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(Message::Text(text)))) => text,
                // The pong a ping asks for goes out with the next send.
                Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)))) => {
                    continue;
                }
                Poll::Ready(None | Some(Ok(Message::Binary(_) | Message::Close(_)))) => {
                    return Poll::Ready(Ok(Heard::Dropped(invalid("the socket closed early"))));
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Ok(Heard::Dropped(socket_error(&error))));
                }
            };
            let frame: serde_json::Value =
                serde_json::from_str(text.as_str()).map_err(|_| invalid("a frame is not JSON"))?;
            return Poll::Ready(Ok(match retriable_error(&frame) {
                Some(error) => Heard::Dropped(error),
                None => Heard::Frame(frame),
            }));
        }
    }
}

/// What a segment's socket said next.
enum Heard {
    Frame(serde_json::Value),
    /// The socket failed or closed before its `finished`, or Soniox sent an
    /// error a fresh socket may clear.
    Dropped(oneiron::Error),
}

/// A Soniox error a fresh socket may clear, as the hearing's failure.
fn retriable_error(frame: &serde_json::Value) -> Option<oneiron::Error> {
    let code = frame.get("error_code")?.as_u64()?;
    RETRIABLE_ERROR_CODES.contains(&code).then(|| {
        let message = frame
            .get("error_message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unnamed");
        invalid(&format!("provider error: {code}: {message}"))
    })
}

fn socket_error(error: &tokio_tungstenite::tungstenite::Error) -> oneiron::Error {
    invalid(&format!("socket: {error}"))
}

/// What waits for the next segment, in the order the owner said it.
enum Held {
    Audio(Vec<u8>),
    Cut,
}

/// One call's live hearing: a segment after another on the route's rung,
/// each on a lease of its own. It is polled beside the call's connection
/// ([`Self::next`]), never detached and never under the session lock, and
/// dropping it closes the socket and cancels the lease.
pub(crate) struct SonioxLive {
    rung: Arc<SonioxRung>,
    door: Arc<ModelRuntime>,
    route: MediaVoiceRoute,
    sample_rate: u32,
    channels: u16,
    segment: Option<Segment>,
    opening: Option<Opening>,
    held: VecDeque<Held>,
    held_bytes: usize,
    /// Final words a rolled-over segment heard for the utterance still open.
    carried: Vec<AsrToken>,
    /// The owner's audio ended: no segment opens after this one.
    ending: bool,
    /// The hearing's `Closed` went out.
    closed: bool,
    /// A dropped socket was reconnected after, and the next has said
    /// nothing yet: another drop fails the hearing.
    reconnected: bool,
    /// Fires once a segment has sent nothing for [`KEEPALIVE_AFTER`].
    quiet: Pin<Box<tokio::time::Sleep>>,
}

impl ModelRuntime {
    /// The live hearing for `route`, when its rung hears live (a soniox
    /// rung); `None` when it transcribes buffered cuts. Nothing is admitted
    /// or connected here: the first segment opens, on its own lease, as the
    /// hearing is first polled.
    pub(crate) fn open_voice_asr(
        self: &Arc<Self>,
        route: &MediaVoiceRoute,
        sample_rate: u32,
        channels: u16,
    ) -> oneiron::Result<Option<SonioxLive>> {
        let Some(rung) = self.media.live_rung(route.model.as_str()) else {
            return Ok(None);
        };
        route.stream_request(sample_rate, channels)?;
        let mut live = SonioxLive {
            rung,
            door: Arc::clone(self),
            route: route.clone(),
            sample_rate,
            channels,
            segment: None,
            opening: None,
            held: VecDeque::new(),
            held_bytes: 0,
            carried: Vec::new(),
            ending: false,
            closed: false,
            reconnected: false,
            quiet: Box::pin(tokio::time::sleep(KEEPALIVE_AFTER)),
        };
        live.opening = Some(live.open());
        Ok(Some(live))
    }
}

impl SonioxLive {
    fn open(&self) -> Opening {
        Box::pin(Segment::open(
            Arc::clone(&self.rung),
            Arc::clone(&self.door),
            self.route.clone(),
            self.sample_rate,
            self.channels,
        ))
    }

    /// The segment audio and cuts go to now: open, and not ending.
    fn live_segment(&mut self) -> Option<&mut Segment> {
        if !self.held.is_empty() {
            return None;
        }
        self.segment.as_mut().filter(|segment| !segment.ending)
    }

    fn hold(&mut self, held: Held) -> oneiron::Result<()> {
        if let Held::Audio(pcm) = &held {
            let bytes = self.held_bytes.saturating_add(pcm.len());
            if bytes > QUEUE_LIMIT_BYTES {
                return Err(invalid("a segment did not open in time"));
            }
            self.held_bytes = bytes;
        }
        self.held.push_back(held);
        Ok(())
    }

    /// The owner's microphone audio. Audio that would pass the segment's
    /// bound ends it, and waits for the next.
    pub(crate) fn accept_audio(&mut self, pcm: &[u8]) -> oneiron::Result<()> {
        if self.ending {
            return Err(invalid("audio after the hearing ended"));
        }
        let per_second = u64::from(self.sample_rate) * u64::from(self.channels) * 2;
        let ms = (pcm.len() as u64)
            .saturating_mul(1_000)
            .div_ceil(per_second);
        if let Some(segment) = self.live_segment() {
            // One more millisecond for the lease's rounding up.
            if ms.saturating_add(1) < segment.stream.remaining_ms() {
                return segment.stream.accept_audio(pcm);
            }
            segment.stream.inner_mut().end()?;
            segment.ending = true;
        }
        self.hold(Held::Audio(pcm.to_vec()))
    }

    /// The owner's cut: Soniox finalizes every word before it, and its
    /// `<fin>` comes back from [`Self::next`] as one Final and then
    /// [`SonioxUpdate::Finalized`].
    pub(crate) fn cut(&mut self) -> oneiron::Result<()> {
        if self.ending {
            return Err(invalid("cut after the hearing ended"));
        }
        match self.live_segment() {
            Some(segment) => segment.stream.inner_mut().finalize(),
            None => self.hold(Held::Cut),
        }
    }

    /// The owner's audio ended: the segment drains until `finished` and its
    /// lease settles; words no cut finalized are not handed back.
    pub(crate) fn end(&mut self) -> oneiron::Result<()> {
        if self.ending {
            return Ok(());
        }
        self.ending = true;
        self.held.clear();
        self.held_bytes = 0;
        // A segment still opening is dropped, and its lease cancelled.
        self.opening = None;
        match &mut self.segment {
            Some(segment) if !segment.ending => {
                segment.ending = true;
                segment.stream.inner_mut().end()
            }
            _ => Ok(()),
        }
    }

    /// The hearing's next updates, in Soniox's order, with the words a
    /// rolled-over segment carried put before the next ones. A provider
    /// error, a socket that fails or closes early, or a frame that does not
    /// parse, is an error. Once the last segment settles this yields
    /// [`AsrEventKind::Closed`], and then nothing more.
    pub(crate) async fn next(&mut self) -> oneiron::Result<Vec<SonioxUpdate>> {
        poll_fn(|cx| self.poll_updates(cx)).await
    }

    fn poll_updates(&mut self, cx: &mut Context<'_>) -> Poll<oneiron::Result<Vec<SonioxUpdate>>> {
        loop {
            if let Some(opening) = &mut self.opening {
                let segment = match opening.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        self.opening = None;
                        result
                    }
                };
                self.segment = Some(segment?);
                self.release()?;
            }
            let Some(segment) = &mut self.segment else {
                if self.ending {
                    if self.closed {
                        return Poll::Pending;
                    }
                    self.closed = true;
                    return Poll::Ready(Ok(vec![SonioxUpdate::Asr(asr_event(
                        AsrEventKind::Closed,
                        Vec::new(),
                    ))]));
                }
                self.opening = Some(self.open());
                continue;
            };
            let frame = match segment.poll_heard(&mut self.quiet, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(Heard::Frame(frame))) => frame,
                Poll::Ready(Ok(Heard::Dropped(error))) => {
                    let updates = self.reconnect(error)?;
                    if updates.is_empty() {
                        continue;
                    }
                    return Poll::Ready(Ok(updates));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            };
            self.reconnected = false;
            let updates = segment.stream.inner_mut().receive(&frame)?;
            let updates = self.carry(updates)?;
            if !updates.is_empty() {
                return Poll::Ready(Ok(updates));
            }
        }
    }

    /// A dropped socket, once in a row and while the owner still speaks.
    /// Its lease settles the audio it admitted. Its final words are carried,
    /// and what it had not sent waits for the next segment, ahead of what
    /// already waited. Each cut it sent whose `<fin>` never came is answered
    /// here, with the words carried so far. The next segment opens on the
    /// next poll.
    fn reconnect(&mut self, error: oneiron::Error) -> oneiron::Result<Vec<SonioxUpdate>> {
        if self.ending || self.reconnected {
            return Err(error);
        }
        let mut segment = self.segment.take().ok_or_else(|| invalid("no segment"))?;
        tracing::warn!(%error, "live transcribe socket dropped; reconnecting once");
        self.reconnected = true;
        segment.stream.cancel()?;
        let client = segment.stream.inner_mut();
        let (words, finalizing) = client.dropped();
        let mut unsent = VecDeque::new();
        let mut unsent_bytes = 0_usize;
        let mut unsent_cuts = 0_usize;
        while let Some(frame) = client.transport_mut().pop() {
            match frame {
                Message::Binary(pcm) if !pcm.is_empty() => {
                    unsent_bytes = unsent_bytes.saturating_add(pcm.len());
                    unsent.push_back(Held::Audio(pcm.to_vec()));
                }
                Message::Text(text) if text.as_str() == FINALIZE => {
                    unsent_cuts += 1;
                    unsent.push_back(Held::Cut);
                }
                // Its config, a keepalive, its end.
                _ => {}
            }
        }
        self.held_bytes = self.held_bytes.saturating_add(unsent_bytes);
        if self.held_bytes > QUEUE_LIMIT_BYTES {
            return Err(invalid("the socket is not keeping up"));
        }
        unsent.append(&mut self.held);
        self.held = unsent;
        self.carried.extend(words);
        let unanswered = finalizing.saturating_sub(unsent_cuts);
        if unanswered > 0 {
            return self.carry(vec![SonioxUpdate::Finalized; unanswered]);
        }
        Ok(if self.carried.is_empty() {
            Vec::new()
        } else {
            vec![SonioxUpdate::Asr(asr_event(
                AsrEventKind::Partial,
                self.carried.clone(),
            ))]
        })
    }

    /// What waited for this segment goes to it, in order.
    fn release(&mut self) -> oneiron::Result<()> {
        let segment = self.segment.as_mut().ok_or_else(|| invalid("no segment"))?;
        while let Some(held) = self.held.pop_front() {
            match held {
                Held::Audio(pcm) => {
                    self.held_bytes = self.held_bytes.saturating_sub(pcm.len());
                    segment.stream.accept_audio(&pcm)?;
                }
                Held::Cut => segment.stream.inner_mut().finalize()?,
            }
        }
        Ok(())
    }

    /// One frame's updates as the hearing hands them on: the carried words
    /// lead the next hypothesis and the next Final. A segment's `finished`
    /// settles its lease, and either rolls over (its last words carried,
    /// never an owner's Final) or, once the owner's audio ended, closes the
    /// hearing.
    fn carry(&mut self, updates: Vec<SonioxUpdate>) -> oneiron::Result<Vec<SonioxUpdate>> {
        let mut out = Vec::with_capacity(updates.len());
        let mut updates = updates.into_iter().peekable();
        while let Some(update) = updates.next() {
            let event = match update {
                SonioxUpdate::Finalized => {
                    if !self.carried.is_empty() {
                        out.push(SonioxUpdate::Asr(asr_event(
                            AsrEventKind::Final,
                            std::mem::take(&mut self.carried),
                        )));
                    }
                    out.push(SonioxUpdate::Finalized);
                    continue;
                }
                SonioxUpdate::Asr(event) => event,
            };
            match event.kind {
                AsrEventKind::Error => {
                    return Err(invalid(&format!(
                        "provider error: {}",
                        event.error.as_deref().unwrap_or("unnamed")
                    )));
                }
                // The owner's cut: `<fin>` follows its words.
                AsrEventKind::Final if matches!(updates.peek(), Some(SonioxUpdate::Finalized)) => {
                    let mut tokens = std::mem::take(&mut self.carried);
                    tokens.extend(event.tokens);
                    out.push(SonioxUpdate::Asr(asr_event(AsrEventKind::Final, tokens)));
                }
                // A segment's `finished`: words no cut finalized.
                AsrEventKind::Final => {
                    if !self.ending {
                        self.carried.extend(event.tokens);
                        out.push(SonioxUpdate::Asr(asr_event(
                            AsrEventKind::Partial,
                            self.carried.clone(),
                        )));
                    }
                }
                AsrEventKind::Partial if !self.carried.is_empty() => {
                    let mut tokens = self.carried.clone();
                    tokens.extend(event.tokens);
                    out.push(SonioxUpdate::Asr(asr_event(AsrEventKind::Partial, tokens)));
                }
                AsrEventKind::Closed => {
                    let mut segment = self
                        .segment
                        .take()
                        .filter(|segment| segment.ending)
                        .ok_or_else(|| invalid("the stream finished unasked"))?;
                    // Its lease settles; the hearing's own `Closed`, once
                    // the owner's audio ended, follows on the next poll.
                    segment.stream.end()?;
                    if self.ending {
                        self.carried.clear();
                    }
                }
                _ => out.push(SonioxUpdate::Asr(event)),
            }
        }
        Ok(out)
    }
}

fn asr_event(kind: AsrEventKind, tokens: Vec<AsrToken>) -> AsrEvent {
    AsrEvent {
        kind,
        text: tokens.iter().map(|token| token.text.as_str()).collect(),
        tokens,
        provider_latency_ms: None,
        endpoint_delay_ms: None,
        error: None,
    }
}
