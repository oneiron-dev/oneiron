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

#[test]
fn source_failure_closes_subscribers_without_durable_cancellation() {
    struct Source(std::collections::VecDeque<LlmResult<LlmStreamEvent>>);
    impl Stream for Source {
        type Item = LlmResult<LlmStreamEvent>;
        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }
    for failure in [None, Some(LlmError::from(FatalLlmError::Auth))] {
        let ledger = Arc::new(Mutex::new(Vec::new()));
        let mut bus = LlmEventBus::new(Box::new(Sink(ledger.clone())));
        let mut subscriber = bus.subscribe();
        let event = LlmStreamEvent::TextStart {
            part_id: "partial".into(),
        };
        let mut events = std::collections::VecDeque::from([Ok(event.clone())]);
        if let Some(error) = failure.clone() {
            events.push_back(Err(error));
        }
        let source = LlmStream::new(Source(events));
        {
            let mut drive = std::pin::pin!(bus.drive(source));
            let Poll::Ready(Err(error)) =
                drive.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("source failure must reach driver");
            };
            assert_eq!(
                error,
                failure.unwrap_or_else(|| RetryableLlmError::StreamCut.into())
            );
        }
        let mut late = bus.subscribe();
        // An explicit abort after a failure must not rewrite it as cancellation.
        bus.abort(LlmUsage::zero()).unwrap();
        drop(bus);
        for sub in [&mut subscriber, &mut late] {
            assert_eq!(drain(sub), vec![event.clone()]);
            assert!(matches!(
                Pin::new(sub).poll_next(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(None)
            ));
        }
        assert!(ledger.lock().unwrap().is_empty());
    }
}
