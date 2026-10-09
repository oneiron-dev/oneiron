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

#[test]
fn both_hosted_adapters_keep_two_chunks_from_one_delta_and_end_while_responses_wait() -> Result<()>
{
    use crate::voice_cascade::hosted_tts::{
        HostedProvider, HostedTransport, HostedTtsAdapter, HostedWork,
    };
    use crate::voice_identity::ref_bank::{VoiceRefOrigin, VoiceRefPack, VoiceRegisterClip};
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<HostedWork>>>);
    impl HostedTransport for Capture {
        fn try_submit(&mut self, work: HostedWork) -> Result<()> {
            self.0.lock().unwrap().push(work);
            Ok(())
        }
    }
    for provider in [HostedProvider::Cartesia, HostedProvider::ElevenLabsFlash] {
        let _dir = tempfile::tempdir().expect("temporary vault");
        let vault = crate::Vault::open(_dir.path(), crate::VaultConfig::device())
            .expect("open seeded vault");
        let pack = VoiceRefPack {
            version: 1,
            id: "owner-stream".into(),
            voice_id: "owner-stream-voice".into(),
            owner: crate::EntityId::now(),
            origin: VoiceRefOrigin::Captured,
            clips: vec![VoiceRegisterClip {
                register: "neutral".into(),
                media_type: "audio/wav".into(),
                audio: vec![1, 2],
                transcript: "reference".into(),
            }],
        };
        vault.store_voice_ref_pack(&pack)?;
        let request = vault.prepare_voice_clone(&pack.voice_id, provider.target(), false)?;
        vault.record_voice_target_clone(&request, "provisioned", 1)?;
        let generation = GenerationEpoch {
            session: uuid::Uuid::new_v4(),
            value: 1,
        };
        let queue = Arc::new(Mutex::new(Vec::new()));
        let mut adapter = HostedTtsAdapter::bind(
            &vault,
            &pack.voice_id,
            provider,
            false,
            Capture(queue.clone()),
        )?;
        let ledger = Arc::new(Mutex::new(Vec::new()));
        let mut bus = LlmEventBus::new(Box::new(Sink(ledger.clone())));
        let events = vec![
            LlmStreamEvent::TextStart {
                part_id: "t".into(),
            },
            LlmStreamEvent::TextDelta {
                part_id: "t".into(),
                text: "Hello. World.".into(),
            },
            LlmStreamEvent::Done {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: "Hello. World.".into(),
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
            },
        ];
        {
            let mut work = std::pin::pin!(drive_voice_stream(
                &mut bus,
                LlmStream::new(Source {
                    events,
                    position: Arc::new(AtomicUsize::new(0)),
                    time: Arc::new(AtomicU64::new(0))
                }),
                Ticks {
                    position: Arc::new(AtomicUsize::new(0)),
                    time: Arc::new(AtomicU64::new(0))
                },
                || 0,
                VoiceStreamConfig {
                    generation,
                    policy: VoiceChunkPolicy::default()
                },
                |command| adapter.submit(command),
                |_| {},
            ));
            assert!(matches!(
                work.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(()))
            ));
        }
        assert_eq!(ledger.lock().unwrap().len(), 1);
        let commands = queue.lock().unwrap().clone();
        assert_eq!(commands.len(), 2);
        let texts: Vec<_> = commands
            .iter()
            .map(|command| {
                let HostedWork::Render(request) = command else {
                    panic!("normal delta cancelled")
                };
                assert_eq!(request.generation, generation);
                request.body[match provider {
                    HostedProvider::Cartesia => "transcript",
                    HostedProvider::ElevenLabsFlash => "text",
                }]
                .as_str()
                .unwrap()
                .to_owned()
            })
            .collect();
        assert_eq!(texts, ["Hello.", " World."]);
        // Both requests were admitted with no response yet; End is already accepted.
        assert_eq!(adapter.receive_pcm(generation, 0, 0, &[1, 0])?.samples, [1]);
        assert!(adapter.receive_pcm(generation, 1, 0, &[1, 0]).is_err());
        adapter.finish_response(generation, 0)?;
        assert_eq!(adapter.receive_pcm(generation, 1, 0, &[2, 0])?.samples, [2]);
        adapter.finish_response(generation, 1)?;
        assert_eq!(queue.lock().unwrap().len(), 2);
    }
    Ok(())
}
