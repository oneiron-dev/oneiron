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
            |command| output.submit(command),
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
            |command| output.submit(command),
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

#[test]
fn initial_model_silence_emits_zero_byte_progress_without_writes() {
    struct SilentSource(Arc<AtomicU64>);
    impl Stream for SilentSource {
        type Item = LlmResult<LlmStreamEvent>;
        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.0.load(Ordering::SeqCst) < 2_100 {
                return Poll::Pending;
            }
            Poll::Ready(Some(Ok(LlmStreamEvent::Done {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
            })))
        }
    }
    struct SilenceTicks {
        index: u64,
        clock: Arc<AtomicU64>,
    }
    impl Stream for SilenceTicks {
        type Item = u64;
        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.index >= 2 {
                return Poll::Pending;
            }
            self.index += 1;
            let now = self.index * 1_000;
            self.clock.store(now, Ordering::SeqCst);
            Poll::Ready(Some(now))
        }
    }
    let generation = GenerationEpoch {
        session: uuid::Uuid::new_v4(),
        value: 1,
    };
    let clock = Arc::new(AtomicU64::new(0));
    let reports = Arc::new(Mutex::new(Vec::new()));
    let observed = reports.clone();
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let mut bus = LlmEventBus::new(Box::new(Sink(ledger.clone())));
    let mut raw = bus.subscribe();
    let mut output = Output::default();
    {
        let mut work = std::pin::pin!(drive_voice_stream(
            &mut bus,
            LlmStream::new(SilentSource(clock.clone())),
            SilenceTicks {
                index: 0,
                clock: clock.clone()
            },
            || clock.load(Ordering::SeqCst),
            VoiceStreamConfig {
                generation,
                policy: VoiceChunkPolicy::default()
            },
            |command| output.submit(command),
            move |snapshot| observed.lock().unwrap().push(snapshot),
        ));
        assert!(matches!(
            work.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
        assert_eq!(
            reports
                .lock()
                .unwrap()
                .iter()
                .map(|p| (p.text_bytes, p.terminal))
                .collect::<Vec<_>>(),
            [(0, false), (0, false)]
        );
        assert!(ledger.lock().unwrap().is_empty());
        assert!(drain(&mut raw).is_empty());
        clock.store(2_100, Ordering::SeqCst);
        assert!(matches!(
            work.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
    }
    assert_eq!(ledger.lock().unwrap().len(), 1);
    assert_eq!(reports.lock().unwrap().len(), 3);
    assert!(reports.lock().unwrap()[2].terminal);
}

#[test]
fn invalid_resident_cadence_closes_raw_subscribers_without_tts_or_terminal() {
    for policy in [
        VoiceChunkPolicy {
            min_words: 0,
            ..VoiceChunkPolicy::default()
        },
        VoiceChunkPolicy {
            max_wait_ms: 0,
            ..VoiceChunkPolicy::default()
        },
    ] {
        let generation = GenerationEpoch {
            session: uuid::Uuid::new_v4(),
            value: 1,
        };
        let ledger = Arc::new(Mutex::new(Vec::new()));
        let mut bus = LlmEventBus::new(Box::new(Sink(ledger.clone())));
        let mut raw = bus.subscribe();
        let mut output = Output::default();
        {
            let source = LlmStream::new(Source {
                events: vec![LlmStreamEvent::TextStart {
                    part_id: "t".into(),
                }],
                position: Arc::new(AtomicUsize::new(0)),
                time: Arc::new(AtomicU64::new(0)),
            });
            let mut work = std::pin::pin!(drive_voice_stream(
                &mut bus,
                source,
                Ticks {
                    position: Arc::new(AtomicUsize::new(0)),
                    time: Arc::new(AtomicU64::new(0))
                },
                || 0,
                VoiceStreamConfig { generation, policy },
                |command| output.submit(command),
                |_| {},
            ));
            assert!(matches!(
                work.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(VoiceStreamFailure::InvalidPolicy))
            ));
        }
        assert!(output.0.is_empty());
        assert!(matches!(
            Pin::new(&mut raw).poll_next(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(None)
        ));
        assert!(ledger.lock().unwrap().is_empty());
        drop(bus);
        assert!(ledger.lock().unwrap().is_empty());
    }
}

#[test]
fn rejected_start_closes_raw_subscribers_without_terminal_write() {
    struct RejectStart(Vec<TtsCommand>);
    impl TtsSeamClient for RejectStart {
        fn submit(&mut self, command: TtsCommand) -> Result<()> {
            let reject = matches!(command, TtsCommand::Start { .. });
            self.0.push(command);
            if reject {
                Err(crate::Error::InvalidConfig("start refused".into()))
            } else {
                Ok(())
            }
        }
    }
    let generation = GenerationEpoch {
        session: uuid::Uuid::new_v4(),
        value: 1,
    };
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let mut bus = LlmEventBus::new(Box::new(Sink(ledger.clone())));
    let mut raw = bus.subscribe();
    let mut output = RejectStart(Vec::new());
    {
        let source = LlmStream::new(Source {
            events: vec![],
            position: Arc::new(AtomicUsize::new(0)),
            time: Arc::new(AtomicU64::new(0)),
        });
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
            |command| output.submit(command),
            |_| {},
        ));
        assert!(matches!(
            work.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(VoiceStreamFailure::Tts(_)))
        ));
    }
    assert_eq!(
        output.0,
        [
            TtsCommand::Start { generation },
            TtsCommand::Cancel { generation }
        ]
    );
    assert!(matches!(
        Pin::new(&mut raw).poll_next(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(None)
    ));
    drop(bus);
    assert!(ledger.lock().unwrap().is_empty());
}

#[test]
fn request_buffered_adapter_drains_responses_between_twenty_chunks() {
    use crate::voice_cascade::tts_spikes::{
        AudioDelivery, AudioEncoding, IrodoriAdapter, ProviderAudio, ProviderConfig,
        ProviderOperation, ProviderWork, RuntimePins, StreamingCapability, TransportQueue,
        VoiceContext,
    };
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<ProviderWork>>>);
    impl TransportQueue for Capture {
        fn try_submit(&mut self, work: ProviderWork) -> Result<()> {
            self.0.lock().unwrap().push(work);
            Ok(())
        }
    }
    struct BufferedSource {
        sent: usize,
        drained: Arc<AtomicUsize>,
    }
    impl Stream for BufferedSource {
        type Item = LlmResult<LlmStreamEvent>;
        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.sent >= 2 && self.drained.load(Ordering::SeqCst) < (self.sent - 1).min(20) {
                return Poll::Pending;
            }
            let index = self.sent;
            self.sent += 1;
            let event = match index {
                0 => LlmStreamEvent::TextStart {
                    part_id: "t".into(),
                },
                1..=20 => LlmStreamEvent::TextDelta {
                    part_id: "t".into(),
                    text: "x.".into(),
                },
                21 => LlmStreamEvent::Done {
                    message: LlmMessage {
                        role: LlmMessageRole::Assistant,
                        content: vec![ContentPart::Text {
                            text: "x.".repeat(20),
                        }],
                    },
                    usage: LlmUsage::zero(),
                    finish_reason: FinishReason::Stop,
                },
                _ => return Poll::Ready(None),
            };
            Poll::Ready(Some(Ok(event)))
        }
    }
    struct Responses {
        adapter: Arc<Mutex<IrodoriAdapter<Capture>>>,
        queue: Arc<Mutex<Vec<ProviderWork>>>,
        drained: Arc<AtomicUsize>,
        generation: GenerationEpoch,
    }
    impl Stream for Responses {
        type Item = u64;
        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let index = self.drained.load(Ordering::SeqCst);
            let submission = {
                let queue = self.queue.lock().unwrap();
                queue
                    .iter()
                    .find(|work| {
                        work.sequence == index as u64 + 1
                            && matches!(
                                work.operation,
                                ProviderOperation::Flush {
                                    buffered_text: Some(_)
                                }
                            )
                    })
                    .map(|work| work.sequence)
            };
            let Some(submission) = submission else {
                return Poll::Pending;
            };
            let frame = self
                .adapter
                .lock()
                .unwrap()
                .handle_pcm(ProviderAudio {
                    generation: self.generation,
                    chunk_index: index as u64,
                    delivery: AudioDelivery::BufferedResponse { submission },
                    sample_rate: 24_000,
                    channels: 1,
                    encoding: AudioEncoding::Pcm16Le,
                    bytes: &[1, 0],
                })
                .expect("provider response drains one pending slot");
            assert_eq!(frame.origin.chunk_index, index as u64);
            self.drained.store(index + 1, Ordering::SeqCst);
            Poll::Ready(Some(0))
        }
    }
    let generation = GenerationEpoch {
        session: uuid::Uuid::new_v4(),
        value: 1,
    };
    let queue = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(Mutex::new(
        IrodoriAdapter::new(
            ProviderConfig {
                pins: RuntimePins {
                    checkpoint: "test-checkpoint".into(),
                    runtime: "test-runtime".into(),
                    boot_id: "test-boot".into(),
                },
                sample_rate: 24_000,
                streaming: StreamingCapability::RequestBuffered,
                voice: VoiceContext::default(),
            },
            Capture(queue.clone()),
        )
        .unwrap(),
    ));
    let drained = Arc::new(AtomicUsize::new(0));
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let mut bus = LlmEventBus::new(Box::new(Sink(ledger.clone())));
    let mut raw = bus.subscribe();
    {
        let submission = adapter.clone();
        let mut work = std::pin::pin!(drive_voice_stream(
            &mut bus,
            LlmStream::new(BufferedSource {
                sent: 0,
                drained: drained.clone()
            }),
            Responses {
                adapter: adapter.clone(),
                queue: queue.clone(),
                drained: drained.clone(),
                generation
            },
            || 0,
            VoiceStreamConfig {
                generation,
                policy: VoiceChunkPolicy::default()
            },
            move |command| submission.lock().unwrap().submit(command),
            |_| {},
        ));
        assert!(matches!(
            work.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
    }
    assert_eq!(drained.load(Ordering::SeqCst), 20);
    let commands = queue.lock().unwrap();
    assert_eq!(
        commands
            .iter()
            .filter(|work| matches!(work.operation, ProviderOperation::Flush { .. }))
            .count(),
        20
    );
    assert!(matches!(
        commands.last().unwrap().operation,
        ProviderOperation::End {
            buffered_text: None
        }
    ));
    assert!(
        !commands
            .iter()
            .any(|work| matches!(work.operation, ProviderOperation::Cancel))
    );
    drop(commands);
    adapter.lock().unwrap().handle_done(generation).unwrap();
    let events = drain(&mut raw);
    assert_eq!(events.len(), 22);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, LlmStreamEvent::TextDelta { text, .. } if text == "x."))
            .count(),
        20
    );
    assert_eq!(ledger.lock().unwrap().len(), 1);
}
