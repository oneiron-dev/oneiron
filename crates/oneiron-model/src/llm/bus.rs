//! Ephemeral one-producer fanout. The durable sink accepts terminals, never deltas.
use super::{
    ContentPart, FinishReason, LlmMessage, LlmMessageRole, LlmResponse, LlmResult, LlmStream,
    LlmStreamEvent, LlmUsage, ReplyAssertions,
};
use futures_core::Stream;
use std::{
    collections::{BTreeMap, VecDeque},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
};

pub trait TerminalSink: Send {
    fn record(&mut self, terminal: &LlmResponse) -> LlmResult<()>;
}
#[derive(Default)]
struct SubscriberState {
    queue: VecDeque<LlmStreamEvent>,
    closed: bool,
    waker: Option<Waker>,
}
pub struct StreamSubscription {
    state: Arc<Mutex<SubscriberState>>,
}
impl Stream for StreamSubscription {
    type Item = LlmStreamEvent;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut state = self.state.lock().expect("subscriber lock");
        if let Some(event) = state.queue.pop_front() {
            return Poll::Ready(Some(event));
        }
        if state.closed {
            return Poll::Ready(None);
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Not Clone: only this owner can publish. Late subscribers replay the transient
/// history while this producer lives; no event history is stored in the vault.
pub struct LlmEventBus {
    subscribers: Vec<Weak<Mutex<SubscriberState>>>,
    history: Vec<LlmStreamEvent>,
    /// Every part the stream started, in `order`, the order it started in
    /// (FIX 8625): text and reasoning as they stand, a tool call, tool result
    /// or image once it ends, `None` while it has not.
    parts: BTreeMap<String, Option<ContentPart>>,
    order: Vec<String>,
    closed: bool,
    sink: Box<dyn TerminalSink>,
}
impl LlmEventBus {
    pub fn new(sink: Box<dyn TerminalSink>) -> Self {
        Self {
            subscribers: Vec::new(),
            history: Vec::new(),
            parts: BTreeMap::new(),
            order: Vec::new(),
            closed: false,
            sink,
        }
    }
    pub fn subscribe(&mut self) -> StreamSubscription {
        let state = Arc::new(Mutex::new(SubscriberState {
            queue: self.history.clone().into(),
            closed: self.closed,
            waker: None,
        }));
        self.subscribers.push(Arc::downgrade(&state));
        StreamSubscription { state }
    }
    pub fn publish(&mut self, event: LlmStreamEvent) -> LlmResult<()> {
        if self.closed {
            return Err(super::FatalLlmError::InvalidRequest.into());
        }
        self.observe(&event);
        let terminal = match &event {
            LlmStreamEvent::Done {
                message,
                usage,
                finish_reason,
                reply_assertions,
            } => Some(LlmResponse {
                message: message.clone(),
                usage: usage.clone(),
                finish_reason: finish_reason.clone(),
                reply_assertions: reply_assertions.clone(),
            }),
            _ => None,
        };
        if let Some(terminal) = terminal {
            // A failed write leaves the bus open for explicit retry or abort.
            self.sink.record(&terminal)?;
            self.closed = true;
        }
        self.history.push(event.clone());
        self.subscribers.retain(|weak| {
            let Some(state) = weak.upgrade() else {
                return false;
            };
            let waker = {
                let mut state = state.lock().expect("subscriber lock");
                state.queue.push_back(event.clone());
                state.closed = self.closed;
                state.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
            true
        });
        Ok(())
    }
    /// A host supplies actual usage on cancellation. The reply keeps every
    /// part in the order it started; incomplete tools are omitted. A
    /// cancellation asserts no record (FIX 3416).
    pub fn abort(&mut self, usage: LlmUsage) -> LlmResult<()> {
        if self.closed {
            return Ok(());
        }
        self.publish(LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: self
                    .order
                    .iter()
                    .filter_map(|id| self.parts.get(id)?.clone())
                    .collect(),
            },
            usage,
            finish_reason: FinishReason::Cancelled,
            reply_assertions: ReplyAssertions::default(),
        })
    }
    pub async fn drive(&mut self, mut stream: LlmStream<'_>) -> LlmResult<()> {
        while let Some(event) = std::future::poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await
        {
            match event {
                Ok(event) => self.publish(event)?,
                Err(error) => {
                    self.close_without_terminal();
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    /// Drive the raw producer and session-local subscriber stages together. The
    /// host supplies a clock and a timer stream (including ticks during silence).
    /// Raw listeners still receive exact events; only a committed Done reaches
    /// stages. On source/stage failure subscribers close without a fake terminal.
    pub async fn drive_with<T, E>(
        &mut self,
        mut stream: LlmStream<'_>,
        mut ticks: T,
        mut now_ms: impl FnMut() -> u64,
        mut on_input: impl FnMut(Option<&LlmStreamEvent>, u64) -> Result<(), E>,
    ) -> Result<(), E>
    where
        T: Stream<Item = u64> + Unpin,
        E: From<super::LlmError>,
    {
        let mut ticks_open = true;
        loop {
            let item = std::future::poll_fn(|cx| {
                match Pin::new(&mut stream).poll_next(cx) {
                    Poll::Ready(Some(event)) => return Poll::Ready(Some(Err(event))),
                    Poll::Ready(None) => return Poll::Ready(None),
                    Poll::Pending => {}
                }
                if ticks_open {
                    match Pin::new(&mut ticks).poll_next(cx) {
                        Poll::Ready(Some(tick)) => return Poll::Ready(Some(Ok(tick))),
                        Poll::Ready(None) => ticks_open = false,
                        Poll::Pending => {}
                    }
                }
                Poll::Pending
            })
            .await;
            match item {
                Some(Ok(tick)) => {
                    if let Err(error) = on_input(None, tick) {
                        self.close_without_terminal();
                        return Err(error);
                    }
                }
                Some(Err(Ok(event))) => {
                    let terminal = matches!(event, LlmStreamEvent::Done { .. });
                    if let Err(error) = self.publish(event.clone()) {
                        self.close_without_terminal();
                        return Err(error.into());
                    }
                    if let Err(error) = on_input(Some(&event), now_ms()) {
                        self.close_without_terminal();
                        return Err(error);
                    }
                    if terminal {
                        return Ok(());
                    }
                }
                Some(Err(Err(error))) => {
                    self.close_without_terminal();
                    return Err(error.into());
                }
                None => return Ok(()),
            }
        }
    }

    /// Closes every subscriber without a terminal event, as a failed drive does. Public so
    /// `oneiron`'s voice cascade (its one caller outside this module) can abandon a stream.
    pub fn close_without_terminal(&mut self) {
        self.closed = true;
        for weak in &self.subscribers {
            if let Some(state) = weak.upgrade() {
                let waker = {
                    let mut state = state.lock().expect("subscriber lock");
                    state.closed = true;
                    state.waker.take()
                };
                if let Some(waker) = waker {
                    waker.wake();
                }
            }
        }
    }
    fn observe(&mut self, event: &LlmStreamEvent) {
        match event {
            LlmStreamEvent::TextStart { part_id } => self.insert(
                part_id,
                ContentPart::Text {
                    text: String::new(),
                },
            ),
            LlmStreamEvent::ReasoningStart { part_id, signature } => self.insert(
                part_id,
                ContentPart::Reasoning {
                    text: String::new(),
                    signature: signature.clone(),
                },
            ),
            LlmStreamEvent::TextDelta { part_id, text }
            | LlmStreamEvent::ReasoningDelta { part_id, text } => {
                if let Some(
                    ContentPart::Text { text: value } | ContentPart::Reasoning { text: value, .. },
                ) = self.parts.get_mut(part_id).and_then(Option::as_mut)
                {
                    value.push_str(text);
                }
            }
            LlmStreamEvent::ToolCallStart { part_id, .. }
            | LlmStreamEvent::ToolResultStart { part_id, .. }
            | LlmStreamEvent::ImageStart { part_id, .. } => {
                self.reserve_part(part_id);
            }
            LlmStreamEvent::ToolCallEnd {
                part_id,
                call_id,
                name,
                input,
            } => self.insert(
                part_id,
                ContentPart::ToolCall {
                    call_id: call_id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                },
            ),
            LlmStreamEvent::ToolResultEnd {
                part_id,
                call_id,
                output,
                is_error,
            } => self.insert(
                part_id,
                ContentPart::ToolResult {
                    call_id: call_id.clone(),
                    output: output.clone(),
                    is_error: *is_error,
                },
            ),
            LlmStreamEvent::ImageEnd {
                part_id,
                media_type,
                image,
            } => self.insert(
                part_id,
                ContentPart::Image {
                    media_type: media_type.clone(),
                    image: image.clone(),
                },
            ),
            _ => {}
        }
    }
    fn insert(&mut self, id: &str, content: ContentPart) {
        *self.reserve_part(id) = Some(content);
    }
    /// `id`'s slot, its place in `order` taken the first time the stream
    /// names it, so content that fills it later keeps that place.
    fn reserve_part(&mut self, id: &str) -> &mut Option<ContentPart> {
        if !self.parts.contains_key(id) {
            self.order.push(id.into());
        }
        self.parts.entry(id.into()).or_default()
    }
}
impl Drop for LlmEventBus {
    fn drop(&mut self) {
        if self.abort(LlmUsage::zero()).is_err() {
            // A sink failure must not strand subscribers after the producer dies.
            // EOF is not a successful Done and no uncommitted terminal is replayed.
            self.close_without_terminal();
        }
    }
}
