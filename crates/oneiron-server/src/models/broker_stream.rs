//! A brokered streamed reply read as the HTTP transport reads its own
//! (`http.rs` `next_sse`), so the OpenAI and Anthropic frame readers take
//! either.
//!
//! The broker strips every form of the key from the bytes as they pass, a
//! form split across two reads included (`oneiron-broker` `strip.rs`). A
//! form split across two events is not one it reads as a form, and needs
//! none: the model never sees the key, so the only echoes of it are the
//! provider's own texts (an error naming the key it was sent), which come
//! whole in one event.
use std::collections::{BTreeMap, VecDeque};

use oneiron::{BudgetLease, LlmResult};
use oneiron_broker::{BrokerStream, DispatchError, Failure, StreamPart};
use serde_json::Value as JsonValue;
use zeroize::Zeroizing;

use super::http::{HttpFailure, HttpReleaseError, JsonReply, SseItem};
use super::sse::{EventTooLarge, SseDecoder, SseEvent};

/// A brokered streamed reply as server-sent-event items, as the HTTP
/// transport reads its own: a non-2xx status arrives as one error body (null
/// when the body breaks off), a 2xx one as its events in order. Every body
/// read goes through the released reply's incremental reader.
pub(super) fn sse_items<'a>(
    reply: BrokerStream,
    status: u16,
    headers: Vec<(String, String)>,
    lease: Option<&'a BudgetLease>,
) -> impl futures_util::Stream<Item = Result<SseItem, HttpReleaseError>> + Send + 'a {
    let initial = if (200..300).contains(&status) {
        Items::Live {
            reply,
            decoder: SseDecoder::default(),
            ready: VecDeque::new(),
            lease,
        }
    } else {
        Items::Error {
            reply,
            status,
            headers,
            body: Zeroizing::new(Vec::new()),
            lease,
        }
    };
    futures_util::stream::unfold(initial, next_item)
}

/// The per-send release check for a brokered streamed reply's reads: the
/// lease's release, then one more physical attempt. The broker asks it only
/// before a physical send; the body phase never asks, but the released reply
/// must be read through its incremental reader.
pub(super) fn physical_send(lease: Option<&BudgetLease>) -> LlmResult<()> {
    if let Some(lease) = lease {
        lease.check_dispatch_release()?;
        lease.begin_physical_attempt();
    }
    Ok(())
}

/// The incremental read of a brokered streamed reply.
enum Items<'a> {
    /// A non-2xx reply's body, gathered whole for its one error item.
    Error {
        reply: BrokerStream,
        status: u16,
        headers: Vec<(String, String)>,
        body: Zeroizing<Vec<u8>>,
        lease: Option<&'a BudgetLease>,
    },
    /// A 2xx reply's events, decoded as they arrive, one per poll.
    Live {
        reply: BrokerStream,
        decoder: SseDecoder,
        ready: VecDeque<SseEvent>,
        lease: Option<&'a BudgetLease>,
    },
    /// The trailing events after the reply ended, then the end.
    Tail { ready: VecDeque<SseEvent> },
    /// The read ended.
    Done,
}

/// The next item of a brokered streamed reply's read.
async fn next_item<'a>(state: Items<'a>) -> Option<(Result<SseItem, HttpReleaseError>, Items<'a>)> {
    match state {
        Items::Done => None,
        Items::Tail { mut ready } => {
            let event = ready.pop_front()?;
            Some((Ok(SseItem::Event(event)), Items::Tail { ready }))
        }
        Items::Error {
            mut reply,
            status,
            headers,
            mut body,
            lease,
        } => loop {
            let parsed = match reply.next_released(&|| physical_send(lease)).await {
                Ok(StreamPart::Chunk(chunk)) => {
                    body.extend_from_slice(&chunk);
                    continue;
                }
                Ok(StreamPart::End) => {
                    serde_json::from_slice::<JsonValue>(&body).unwrap_or(JsonValue::Null)
                }
                // As on HTTP, a status whose body breaks off is classified
                // by its status alone.
                Ok(StreamPart::Cut(_)) | Err(DispatchError::Broker(_)) => JsonValue::Null,
                Err(DispatchError::Release(error)) => {
                    return Some((Err(HttpReleaseError::Release(error)), Items::Done));
                }
            };
            let headers: BTreeMap<String, String> = headers
                .into_iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value))
                .collect();
            let answer = JsonReply {
                status,
                headers,
                body: parsed,
            };
            return Some((Ok(SseItem::Status(answer)), Items::Done));
        },
        Items::Live {
            mut reply,
            mut decoder,
            mut ready,
            lease,
        } => loop {
            if let Some(event) = ready.pop_front() {
                return Some((
                    Ok(SseItem::Event(event)),
                    Items::Live {
                        reply,
                        decoder,
                        ready,
                        lease,
                    },
                ));
            }
            match reply.next_released(&|| physical_send(lease)).await {
                Ok(StreamPart::Chunk(chunk)) => match decoder.push(&chunk) {
                    Ok(events) => ready.extend(events),
                    Err(EventTooLarge) => {
                        return Some((
                            Err(HttpReleaseError::Transport(HttpFailure::EventTooLarge)),
                            Items::Done,
                        ));
                    }
                },
                Ok(StreamPart::End) => {
                    ready.extend(decoder.finish());
                    let event = ready.pop_front()?;
                    return Some((Ok(SseItem::Event(event)), Items::Tail { ready }));
                }
                Ok(StreamPart::Cut(reason)) => {
                    return Some((Err(cut_error(reason)), Items::Done));
                }
                Err(DispatchError::Release(error)) => {
                    return Some((Err(HttpReleaseError::Release(error)), Items::Done));
                }
                Err(DispatchError::Broker(_)) => {
                    return Some((
                        Err(HttpReleaseError::Transport(HttpFailure::StreamCut)),
                        Items::Done,
                    ));
                }
            }
        },
    }
}

/// The transport error a broker cut is.
fn cut_error(reason: Failure) -> HttpReleaseError {
    match reason {
        Failure::Timeout => HttpReleaseError::Transport(HttpFailure::Timeout),
        Failure::Send => HttpReleaseError::Transport(HttpFailure::StreamCut),
        Failure::ReplyTooLarge => HttpReleaseError::Transport(HttpFailure::BodyTooLarge),
        Failure::ReplyEncoded | Failure::Redirect | Failure::ReplyHoldsKey => {
            HttpReleaseError::Transport(HttpFailure::Malformed)
        }
    }
}
