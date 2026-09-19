use super::*;
use futures_core::Stream;
use std::future::Future;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
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

struct Noop;
impl Wake for Noop {
    fn wake(self: Arc<Self>) {}
}
fn drain(sub: &mut StreamSubscription) -> Vec<LlmStreamEvent> {
    let w = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&w);
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
    let mut chunker = VoiceChunker::default();
    let mut progress = ProgressSubscriber::default();
    let delta = |s: &str| LlmStreamEvent::TextDelta {
        part_id: "t".into(),
        text: s.into(),
    };
    let original = delta("Hello. one two three four five six ");
    assert_eq!(
        chunker.observe(&original, 0),
        vec!["Hello.", " one two three four five six "]
    );
    assert_eq!(original, delta("Hello. one two three four five six "));
    assert!(chunker.observe(&delta("tail"), 10).is_empty());
    assert_eq!(chunker.tick(159), None);
    assert_eq!(chunker.tick(160), Some("tail".into()));
    assert!(progress.observe(&original, 0).is_none());
    assert!(progress.observe(&delta("x"), 999).is_none());
    assert!(progress.observe(&delta("y"), 1000).is_some());
    assert!(progress.observe(&delta("z"), 1001).is_none());
}
