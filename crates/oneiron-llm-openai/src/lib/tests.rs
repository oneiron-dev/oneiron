//! The adapter under a run admission's gate: its preflight refuses what its
//! send would, before the call's permit starts.
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::llm::run_admission::{
    BudgetLine, CallOutcome, KeyCustody, LeaseUnit, MemoryReceipts, OfferBinding, OfferRoute,
    Payer, RunAdmission, RunCall, RunDeclaration, RunDenied, RunEvent,
};
use oneiron::llm::{
    CallClass, CallEnvelope, CallPurpose, ModelTierRef, ResponseFormat, SingleSend, TierPrecedence,
};
use oneiron::{
    BudgetLease, ContentPart, FatalLlmError, LlmBackend, LlmCatalogEntry, LlmError, LlmMessage,
    LlmMessageRole, LlmRequest, ModelId, ModelLocality,
};
use serde_json::json;

use super::{
    OpenAiCompatBackend, OpenAiCompatConfig, OpenAiCompatFuture, OpenAiCompatHttpRequest,
    OpenAiCompatHttpResponse, OpenAiCompatProviderStream, OpenAiCompatTransport,
    OpenAiCompatTransportError,
};

const MODEL: &str = "fake/teacher@v1";

/// A transport that answers every request once and counts what it sent.
struct OneShot {
    sent: Arc<Mutex<u32>>,
}

impl SingleSend for OneShot {}

impl OpenAiCompatTransport for OneShot {
    fn execute<'a>(
        &'a self,
        _request: OpenAiCompatHttpRequest,
        _lease: &'a BudgetLease,
    ) -> OpenAiCompatFuture<'a> {
        *self.sent.lock().expect("sent") += 1;
        Box::pin(async {
            Ok(OpenAiCompatHttpResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: json!({
                    "choices": [{
                        "message": { "role": "assistant", "content": "ok" },
                        "finish_reason": "stop"
                    }],
                    "usage": { "prompt_tokens": 3, "completion_tokens": 1 }
                }),
            })
        })
    }

    fn stream<'a>(
        &'a self,
        _request: OpenAiCompatHttpRequest,
        _lease: &'a BudgetLease,
    ) -> Result<OpenAiCompatProviderStream<'a>, OpenAiCompatTransportError> {
        Err(OpenAiCompatTransportError::Connection)
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    match std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the fake transport answers at once"),
    }
}

fn request() -> LlmRequest {
    let purpose = CallPurpose::Other {
        name: "teacher".to_owned(),
    };
    LlmRequest {
        model: ModelId::new(MODEL).expect("model"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("teacher".to_owned())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "label this pair".to_owned(),
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}

#[test]
fn an_option_the_adapter_rejects_is_refused_before_the_permit_starts() {
    let sent = Arc::new(Mutex::new(0));
    let entry = LlmCatalogEntry {
        model: ModelId::new(MODEL).expect("model"),
        display_name: "teacher".to_owned(),
        locality: ModelLocality::ThirdParty,
        context_window_tokens: 8_192,
        max_output_tokens: None,
        cost: None,
        capabilities: Vec::new(),
        metadata: BTreeMap::new(),
    };
    let backend = Arc::new(OpenAiCompatBackend::new(
        OpenAiCompatConfig::from_catalog([entry]),
        OneShot {
            sent: Arc::clone(&sent),
        },
    ));
    let receipts = Arc::new(MemoryReceipts::default());
    let line = BudgetLine {
        limit_units: 20,
        reserve_units: 6,
        unit: LeaseUnit::tokens(),
    };
    let run = RunAdmission::new(
        "run-1",
        RunDeclaration::undeclared(line),
        None,
        receipts.clone(),
    );
    let offer = OfferBinding {
        offer: "teacher@model.test".to_owned(),
        model: ModelId::new(MODEL).expect("model"),
        route: OfferRoute::new("openai", "https://model.test").expect("route"),
        locality: ModelLocality::ThirdParty,
        payer: Payer::CustomerKey,
        credential_binding: Some("customer-key-1".to_owned()),
        catalog_revision: None,
        custody: KeyCustody::T0,
        rates: Vec::new(),
    };
    let gated = run.gate(backend, &offer);
    let mut bad = request();
    bad.provider_options.insert(
        "openai".to_owned(),
        json!({ "parallel_tool_calls": "not-a-boolean" }),
    );
    let permit = run
        .admit(RunCall {
            selector: None,
            request: &bad,
            offer: &offer,
        })
        .expect("permit");
    assert_eq!(
        ready(gated.generate(bad, permit.lease())).map(|_| ()),
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    );
    assert_eq!(*sent.lock().expect("sent"), 0);
    assert!(receipts.rows().iter().any(|row| matches!(
        row.event,
        RunEvent::Denied {
            reason: RunDenied::BackendRefused,
            ..
        }
    )));
    // Unstarted, the permit still carries a call the adapter accepts.
    let response = ready(gated.generate(request(), permit.lease())).expect("answer");
    permit
        .settle(CallOutcome::Answered(&response.usage))
        .expect("settle");
    assert_eq!(*sent.lock().expect("sent"), 1);
    assert_eq!((run.read().used_units, run.read().reserved_units), (4, 0));
}
