//! Ephemeral one-producer fanout. The durable sink accepts terminals, never deltas.
use super::{
    ContentPart, FinishReason, LlmMessage, LlmMessageRole, LlmResponse, LlmResult, LlmStream,
    LlmStreamEvent, LlmUsage,
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
    parts: BTreeMap<String, ContentPart>,
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
            } => Some(LlmResponse {
                message: message.clone(),
                usage: usage.clone(),
                finish_reason: finish_reason.clone(),
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
    /// A host supplies actual usage on cancellation; incomplete tools are omitted.
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
                    .filter_map(|id| self.parts.get(id).cloned())
                    .collect(),
            },
            usage,
            finish_reason: FinishReason::Cancelled,
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
    fn close_without_terminal(&mut self) {
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
                ) = self.parts.get_mut(part_id)
                {
                    value.push_str(text);
                }
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
        if !self.parts.contains_key(id) {
            self.order.push(id.into());
        }
        self.parts.insert(id.into(), content);
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
