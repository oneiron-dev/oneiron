use super::*;
use crate::llm::{
    ContentPart, FinishReason, LlmEventBus, LlmMessage, LlmMessageRole, LlmResponse, LlmResult,
    LlmStream, LlmStreamEvent, LlmUsage, TerminalSink, VoiceChunkPolicy,
};
use futures_core::Stream;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

struct Sink(Arc<Mutex<Vec<LlmResponse>>>);
impl TerminalSink for Sink {
    fn record(&mut self, response: &LlmResponse) -> LlmResult<()> {
        self.0.lock().unwrap().push(response.clone());
        Ok(())
    }
}
struct Source {
    events: Vec<LlmStreamEvent>,
    position: Arc<AtomicUsize>,
    time: Arc<AtomicU64>,
}
impl Stream for Source {
    type Item = LlmResult<LlmStreamEvent>;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let index = self.position.load(Ordering::SeqCst);
        if (index == 3 && self.time.load(Ordering::SeqCst) < 150)
            || (index == 4 && self.time.load(Ordering::SeqCst) < 1_000)
        {
            return Poll::Pending;
        }
        self.position.store(index + 1, Ordering::SeqCst);
        Poll::Ready(self.events.get(index).cloned().map(Ok))
    }
}
struct Ticks {
    position: Arc<AtomicUsize>,
    time: Arc<AtomicU64>,
}
impl Stream for Ticks {
    type Item = u64;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let index = self.position.load(Ordering::SeqCst);
        let now = self.time.load(Ordering::SeqCst);
        let tick = if index >= 3 && now < 150 {
            150
        } else if index >= 4 && now < 1_000 {
            1_000
        } else {
            return Poll::Pending;
        };
        self.time.store(tick, Ordering::SeqCst);
        Poll::Ready(Some(tick))
    }
}
#[derive(Default)]
struct Output(Vec<TtsCommand>);
impl TtsSeamClient for Output {
    fn submit(&mut self, command: TtsCommand) -> Result<()> {
        self.0.push(command);
        Ok(())
    }
}
fn drain(sub: &mut crate::llm::StreamSubscription) -> Vec<LlmStreamEvent> {
    let mut events = Vec::new();
    while let Poll::Ready(Some(event)) =
        Pin::new(&mut *sub).poll_next(&mut Context::from_waker(Waker::noop()))
    {
        events.push(event);
    }
    events
}

#[test]
fn live_stream_fans_out_raw_deltas_and_timed_voice_chunks_without_durable_progress() {
    let generation = GenerationEpoch {
        session: uuid::Uuid::new_v4(),
        value: 1,
    };
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let mut bus = LlmEventBus::new(Box::new(Sink(ledger.clone())));
    let mut raw = bus.subscribe();
    let delta = |text: &str| LlmStreamEvent::TextDelta {
        part_id: "t".into(),
        text: text.into(),
    };
    let events = vec![
        LlmStreamEvent::TextStart {
            part_id: "t".into(),
        },
        delta("Hello. one two three four five six "),
        delta("tail"),
        delta("x"),
        LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: "Hello. one two three four five six tailx".into(),
                }],
            },
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Stop,
        },
    ];
    let position = Arc::new(AtomicUsize::new(0));
    let time = Arc::new(AtomicU64::new(0));
    let source = LlmStream::new(Source {
        events: events.clone(),
        position: position.clone(),
        time: time.clone(),
    });
    let ticks = Ticks {
        position,
        time: time.clone(),
    };
    let mut output = Output::default();
    let mut reports = Vec::new();
    {
        let mut work = std::pin::pin!(drive_voice_stream(
            &mut bus,
            source,
            ticks,
            || time.load(Ordering::SeqCst),
            VoiceStreamConfig {
                generation,
                policy: VoiceChunkPolicy::default()
            },
            &mut output,
            |p| reports.push(p)
        ));
        assert!(matches!(
            work.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
    }
    assert_eq!(drain(&mut raw), events);
    assert_eq!(ledger.lock().unwrap().len(), 1);
    assert_eq!(reports.len(), 2);
    assert_eq!(
        reports[0].text_bytes,
        "Hello. one two three four five six tailx".len()
    );
    assert!(!reports[0].terminal);
    assert!(reports[1].terminal);
    let texts: Vec<_> = output
        .0
        .iter()
        .filter_map(|command| {
            if let TtsCommand::Text { text, .. } = command {
                Some(text.as_str())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        texts,
        ["Hello.", " one two three four five six ", "tail", "x"]
    );
    assert!(matches!(output.0.first(), Some(TtsCommand::Start { .. })));
    assert!(matches!(output.0.last(), Some(TtsCommand::End { .. })));
}

#[test]
fn resident_voice_cadence_is_session_local() {
    let delta = |text: &str| LlmStreamEvent::TextDelta {
        part_id: "t".into(),
        text: text.into(),
    };
    let policy = VoiceChunkPolicy {
        punctuation: "!".into(),
        min_words: 2,
        max_wait_ms: 75,
    };
    let mut chunker = crate::llm::VoiceChunker::with_policy(policy).unwrap();
    assert!(chunker.observe(&delta("one."), 0).is_empty());
    assert_eq!(chunker.observe(&delta(" two "), 1), ["one. two "]);
    assert!(chunker.observe(&delta("later"), 2).is_empty());
    assert_eq!(chunker.tick(76), None);
    assert_eq!(chunker.tick(77).as_deref(), Some("later"));
    assert!(
        crate::llm::VoiceChunker::with_policy(VoiceChunkPolicy {
            max_wait_ms: 0,
            ..Default::default()
        })
        .is_none()
    );
}

#[test]
fn cancelled_terminal_does_not_speak_buffered_tail() {
    let generation = GenerationEpoch {
        session: uuid::Uuid::new_v4(),
        value: 1,
    };
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let mut bus = LlmEventBus::new(Box::new(Sink(ledger.clone())));
    let mut raw = bus.subscribe();
    let events = vec![
        LlmStreamEvent::TextStart {
            part_id: "t".into(),
        },
        LlmStreamEvent::TextDelta {
            part_id: "t".into(),
            text: "unsaid".into(),
        },
        LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: "unsaid".into(),
                }],
            },
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Cancelled,
        },
    ];
    let source = LlmStream::new(Source {
        events: events.clone(),
        position: Arc::new(AtomicUsize::new(0)),
        time: Arc::new(AtomicU64::new(0)),
    });
    let mut output = Output::default();
    {
        let mut work = std::pin::pin!(drive_voice_stream(
            &mut bus,
            source,
            Ticks {
                position: Arc::new(AtomicUsize::new(0)),
                time: Arc::new(AtomicU64::new(0))
            },
            || 0,
            VoiceStreamConfig {
                generation,
                policy: VoiceChunkPolicy::default()
            },
            &mut output,
            |_| {},
        ));
        assert!(matches!(
            work.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
    }
    assert_eq!(drain(&mut raw), events);
    assert_eq!(ledger.lock().unwrap().len(), 1);
    assert_eq!(
        output.0,
        [
            TtsCommand::Start { generation },
            TtsCommand::Cancel { generation }
        ]
    );
}
