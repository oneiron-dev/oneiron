//! Local fakes for the research-connector fixture. They stand in for the
//! upstreams only: a model provider, a paid endpoint and a key resolver. None
//! of them checks a teacher list or a lease; everything that refuses is the
//! production admission.
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use futures_core::Stream;

use super::super::super::{
    BudgetLease, ContentPart, FinishReason, LlmBackend, LlmCapability, LlmGenerateFuture,
    LlmMessage, LlmMessageRole, LlmResponse, LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult,
    LlmUsage, ModelId, RetryableLlmError, SingleRouteBackend,
};
use super::super::{PaidConnector, RunAdmission, RunDenied};
use crate::llm::LlmRequest;

/// The test key a resolver hands out. It must never appear in a receipt.
pub(super) const SENTINEL_KEY: &str = "sk-test-sentinel-0000";

pub(super) fn block_on<F: Future>(future: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// One call that reached the fake provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Sent {
    pub(super) model: String,
    pub(super) request_digest: String,
    pub(super) lease: String,
}

/// How the fake provider answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reply {
    /// Answers with this many input and output tokens.
    Usage { input: u64, output: u64 },
    /// Does the work, then the response is lost on the way back.
    LostAfterWork,
    /// Takes the request and never answers.
    Hang,
}

/// A provider that serves any model it is reached with, as a real key would,
/// and records what reached it. It supports every capability but those it is
/// told to refuse.
pub(super) struct FakeProvider {
    sent: Mutex<Vec<Sent>>,
    reply: Mutex<Reply>,
    refused: Mutex<Vec<LlmCapability>>,
}

impl FakeProvider {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            sent: Mutex::new(Vec::new()),
            reply: Mutex::new(Reply::Usage {
                input: 3,
                output: 1,
            }),
            refused: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn refuse(&self, capability: LlmCapability) {
        self.refused.lock().expect("refused").push(capability);
    }

    pub(super) fn reply_with(&self, reply: Reply) {
        *self.reply.lock().expect("reply") = reply;
    }

    pub(super) fn sent(&self) -> Vec<Sent> {
        self.sent.lock().expect("sent").clone()
    }

    fn record(&self, request: &LlmRequest, lease: &BudgetLease) -> Reply {
        self.sent.lock().expect("sent").push(Sent {
            model: request.model.as_str().to_owned(),
            request_digest: request.canonical_hash_hex().expect("digest"),
            lease: lease.id().to_owned(),
        });
        *self.reply.lock().expect("reply")
    }
}

fn answer(request: &LlmRequest, input: u64, output: u64) -> LlmResponse {
    let mut usage = LlmUsage::zero();
    usage.input.total = input;
    usage.output.total = output;
    usage.raw_provider = serde_json::json!({ "served_model": request.model.as_str() });
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: "teacher output".to_owned(),
            }],
        },
        usage,
        finish_reason: FinishReason::Stop,
    }
}

impl SingleRouteBackend for FakeProvider {}

impl LlmBackend for FakeProvider {
    fn supports(&self, _model: &ModelId, capability: LlmCapability) -> bool {
        !self.refused.lock().expect("refused").contains(&capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let reply = self.record(&request, lease);
        Box::pin(async move {
            match reply {
                Reply::Usage { input, output } => Ok(answer(&request, input, output)),
                Reply::LostAfterWork => Err(RetryableLlmError::Timeout.into()),
                Reply::Hang => std::future::pending().await,
            }
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let reply = self.record(&request, lease);
        let events = match reply {
            Reply::Usage { input, output } => {
                let response = answer(&request, input, output);
                VecDeque::from([
                    Ok(LlmStreamEvent::TextDelta {
                        part_id: "0".to_owned(),
                        text: "teacher output".to_owned(),
                    }),
                    Ok(LlmStreamEvent::Done {
                        message: response.message,
                        usage: response.usage,
                        finish_reason: response.finish_reason,
                    }),
                ])
            }
            Reply::LostAfterWork | Reply::Hang => {
                VecDeque::from([Err(RetryableLlmError::StreamCut.into())])
            }
        };
        Ok(LlmStream::new(Events(events)))
    }
}

struct Events(VecDeque<LlmResult<LlmStreamEvent>>);

impl Stream for Events {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.get_mut().0.pop_front())
    }
}

/// A key resolver that hands out the sentinel key and counts each resolution.
#[derive(Default)]
pub(super) struct FakeResolver {
    resolved: Mutex<u32>,
}

impl FakeResolver {
    fn resolve(&self) -> &'static str {
        *self.resolved.lock().expect("resolved") += 1;
        SENTINEL_KEY
    }

    pub(super) fn resolved(&self) -> u32 {
        *self.resolved.lock().expect("resolved")
    }
}

/// A paid endpoint that accepts every call that reaches it with a key, and
/// counts sends and billable units.
#[derive(Default)]
pub(super) struct FakePaidEndpoint {
    sends: Mutex<Vec<(String, u64)>>,
}

impl FakePaidEndpoint {
    fn send(&self, key: &str, units: u64) -> u64 {
        self.sends
            .lock()
            .expect("sends")
            .push((key.to_owned(), units));
        units
    }

    /// Authorized sends: those that carried a key.
    pub(super) fn sends(&self) -> usize {
        self.sends.lock().expect("sends").len()
    }

    pub(super) fn billable_units(&self) -> u64 {
        self.sends
            .lock()
            .expect("sends")
            .iter()
            .map(|(_, units)| units)
            .sum()
    }
}

/// The shape a leased paid adapter takes: it asks the run admission to start
/// the call's permit, then resolves the key, then sends. The broker's real
/// adapter is not built; this proves the admission contract it must call.
pub(super) fn paid_call(
    run: &RunAdmission,
    lease: &BudgetLease,
    connector: &PaidConnector,
    resolver: &FakeResolver,
    endpoint: &FakePaidEndpoint,
    units: u64,
) -> Result<u64, RunDenied> {
    run.dispatch_paid(lease, connector)?;
    let key = resolver.resolve();
    Ok(endpoint.send(key, units))
}
