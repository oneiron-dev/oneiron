use super::*;
use futures_core::Stream;
use std::future::Future;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
struct Sink(Arc<Mutex<Vec<LlmResponse>>>);
impl TerminalSink for Sink {
    fn record(&mut self, r: &LlmResponse) -> LlmResult<()> {
        self.0.lock().unwrap().push(r.clone());
        Ok(())
    }
}
struct FakeStream(std::collections::VecDeque<LlmStreamEvent>);
impl Stream for FakeStream {
    type Item = LlmResult<LlmStreamEvent>;
    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.pop_front().map(Ok))
    }
}

fn drain(sub: &mut StreamSubscription) -> Vec<LlmStreamEvent> {
    let mut cx = Context::from_waker(Waker::noop());
    let mut events = Vec::new();
    while let Poll::Ready(Some(e)) = Pin::new(&mut *sub).poll_next(&mut cx) {
        events.push(e);
    }
    events
}
#[test]
fn three_subscribers_keep_full_sequence_and_only_terminal_is_durable() {
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let mut bus = LlmEventBus::new(Box::new(Sink(ledger.clone())));
    let mut subscribers: Vec<_> = (0..3).map(|_| bus.subscribe()).collect();
    let events = vec![
        LlmStreamEvent::TextStart {
            part_id: "a".into(),
        },
        LlmStreamEvent::TextDelta {
            part_id: "a".into(),
            text: "hi".into(),
        },
        LlmStreamEvent::TextEnd {
            part_id: "a".into(),
        },
        LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text { text: "hi".into() }],
            },
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Stop,
        },
    ];
    let source = LlmStream::new(FakeStream(events.clone().into()));
    {
        let mut drive = std::pin::pin!(bus.drive(source));
        assert!(matches!(
            drive.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
    }
    for sub in &mut subscribers {
        assert_eq!(drain(sub), events);
    }
    assert_eq!(ledger.lock().unwrap().len(), 1);
    assert_eq!(drain(&mut bus.subscribe()), events);
}
#[test]
fn abort_and_drop_fan_out_partial_done_once() {
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let mut bus = LlmEventBus::new(Box::new(Sink(ledger.clone())));
    let mut subscribers: Vec<_> = (0..3).map(|_| bus.subscribe()).collect();
    bus.publish(LlmStreamEvent::TextStart {
        part_id: "t".into(),
    })
    .unwrap();
    bus.publish(LlmStreamEvent::TextDelta {
        part_id: "t".into(),
        text: "part".into(),
    })
    .unwrap();
    bus.abort(LlmUsage::zero()).unwrap();
    drop(bus);
    for sub in &mut subscribers {
        let e = drain(sub);
        assert_eq!(e.len(), 3);
        assert!(
            matches!(e.last().unwrap(), LlmStreamEvent::Done { message, finish_reason: FinishReason::Cancelled, .. } if message.content == vec![ContentPart::Text { text: "part".into() }])
        );
    }
    assert_eq!(ledger.lock().unwrap().len(), 1);
}
#[test]
fn chunking_and_progress_do_not_change_full_grain_events() {
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let mut bus = LlmEventBus::new(Box::new(Sink(ledger.clone())));
    let mut raw = bus.subscribe();
    let mut voice = bus.subscribe();
    let mut progress_feed = bus.subscribe();
    let mut chunker = VoiceChunker::default();
    let mut progress = ProgressSubscriber::default();
    let delta = |s: &str| LlmStreamEvent::TextDelta {
        part_id: "t".into(),
        text: s.into(),
    };
    let events = vec![
        LlmStreamEvent::TextStart {
            part_id: "t".into(),
        },
        delta("Hello. one two three four five six "),
        delta("tail"),
        delta("x"),
        delta("y"),
        delta("z"),
    ];
    let times = [0, 0, 10, 999, 1000, 1001];
    for event in &events {
        bus.publish(event.clone()).unwrap();
    }
    let mut chunks = Vec::new();
    for (event, time) in drain(&mut voice).iter().zip(times) {
        if time == 999 {
            assert_eq!(chunker.tick(159), None);
            assert_eq!(chunker.tick(160), Some("tail".into()));
        }
        chunks.extend(chunker.observe(event, time));
    }
    assert_eq!(chunks, vec!["Hello.", " one two three four five six "]);
    let reports: Vec<_> = drain(&mut progress_feed)
        .iter()
        .zip(times)
        .filter_map(|(event, time)| progress.observe(event, time))
        .collect();
    assert_eq!(reports.len(), 1);
    assert_eq!(drain(&mut raw), events);
    assert!(ledger.lock().unwrap().is_empty());
    bus.publish(LlmStreamEvent::TextEnd {
        part_id: "t".into(),
    })
    .unwrap();
    let done = LlmStreamEvent::Done {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: "Hello. one two three four five six tailxyz".into(),
            }],
        },
        usage: LlmUsage::zero(),
        finish_reason: FinishReason::Stop,
    };
    assert_eq!(chunker.observe(&done, 1002), vec!["xyz"]);
    assert!(progress.observe(&done, 1002).unwrap().terminal);
    bus.publish(done.clone()).unwrap();
    for sub in [&mut raw, &mut voice, &mut progress_feed] {
        assert_eq!(drain(sub).last(), Some(&done));
    }
    assert_eq!(ledger.lock().unwrap().len(), 1);
}

#[test]
fn failed_terminal_write_is_not_published_and_can_be_retried() {
    struct FailOnce(bool);
    impl TerminalSink for FailOnce {
        fn record(&mut self, _: &LlmResponse) -> LlmResult<()> {
            if std::mem::replace(&mut self.0, false) {
                Err(RetryableLlmError::ServerError.into())
            } else {
                Ok(())
            }
        }
    }
    let mut bus = LlmEventBus::new(Box::new(FailOnce(true)));
    let mut sub = bus.subscribe();
    let terminal = LlmStreamEvent::Done {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![],
        },
        usage: LlmUsage::zero(),
        finish_reason: FinishReason::Stop,
    };
    assert!(bus.publish(terminal.clone()).is_err());
    assert!(drain(&mut sub).is_empty());
    let mut late = bus.subscribe();
    assert!(drain(&mut late).is_empty());
    bus.publish(terminal.clone()).unwrap();
    assert_eq!(drain(&mut sub), vec![terminal.clone()]);
    assert_eq!(drain(&mut late), vec![terminal]);
}

#[test]
fn failed_sink_on_drop_closes_subscribers_without_false_done() {
    struct Fail;
    impl TerminalSink for Fail {
        fn record(&mut self, _: &LlmResponse) -> LlmResult<()> {
            Err(RetryableLlmError::ServerError.into())
        }
    }
    let mut bus = LlmEventBus::new(Box::new(Fail));
    let mut subscriber = bus.subscribe();
    drop(bus);
    assert!(matches!(
        Pin::new(&mut subscriber).poll_next(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(None)
    ));
}
