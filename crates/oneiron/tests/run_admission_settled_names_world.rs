//! Census row L5-25 (DEC-0005 world privacy, fix 12): every provider call on a
//! private world writes a receipt with the world it read. Since #7727 the
//! `Admitted` receipt names the world a model call named in its scope; the
//! call's `Dispatched` row (the provider call itself) and its `Settled` row
//! must name the same world, joined to the admission by the call's lease.
//!
//! Each call goes through the public `RunAdmission::call` over a gated fake
//! provider that answers at once, or through `RunAdmission::admit` and
//! `RunPermit::settle` for a call that never went out, and is read back from
//! the run's receipt sink as the JSON a host sink writes.
//!
//! `cargo test --locked -p oneiron --all-features --test
//! run_admission_settled_names_world`.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oneiron::llm::run_admission::{
    BudgetLine, CallOutcome, KeyCustody, LeaseUnit, MemoryReceipts, OfferBinding, OfferRoute,
    Payer, RunAdmission, RunCall, RunDeclaration, RunEvent,
};
use oneiron::llm::{self, ReplyAssertions, SingleRouteBackend};
use oneiron::{
    BudgetLease, ContentPart, EntityId, FatalLlmError, FinishReason, LlmBackend, LlmGenerateFuture,
    LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmResult, LlmStreamResult, LlmUsage,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The model every request and offer here names.
const MODEL: &str = "test/model@r1";
/// What each call reserves, in tokens.
const CALL_RESERVE: u64 = 500;

/// Polls `future` to its end; the fake provider answers at once, so nothing
/// here waits on anything else.
fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("a gated call pending on something other than its provider's answer");
}

/// A provider that answers every call at once with one short text.
struct AnsweringProvider;

impl LlmBackend for AnsweringProvider {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let mut usage = LlmUsage::zero();
        usage.raw_provider = serde_json::json!({});
        Box::pin(std::future::ready(Ok(LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: "consolidated".to_owned(),
                    signature: None,
                }],
            },
            usage,
            finish_reason: FinishReason::Stop,
            reply_assertions: ReplyAssertions::default(),
            token_scores: None,
        })))
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

impl SingleRouteBackend for AnsweringProvider {
    fn preflight(&self, _request: &LlmRequest, _stream: bool) -> LlmResult<()> {
        Ok(())
    }
}

/// One model request whose scope names `world`.
fn request_in(world: Option<EntityId>) -> TestResult<LlmRequest> {
    Ok(LlmRequest {
        model: llm::ModelId::new(MODEL)?,
        envelope: llm::CallEnvelope {
            scope: llm::Scope {
                world,
                ..llm::Scope::default()
            },
            purpose: llm::CallPurpose::Consolidation,
            class: llm::CallClass::BestEffort,
            tier: llm::TierPrecedence::for_purpose(
                &llm::CallPurpose::Consolidation,
                llm::ModelTierRef("default".into()),
            ),
            response_format: llm::ResponseFormat::Text,
            locality: llm::ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "consolidate this partition".to_owned(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    })
}

/// The customer's own key for the model on the owner's own server.
fn customer_offer() -> TestResult<OfferBinding> {
    Ok(OfferBinding {
        offer: format!("{MODEL}@model.test"),
        model: llm::ModelId::new(MODEL)?,
        route: OfferRoute::new("fake", "https://model.test:443")?,
        locality: llm::ModelLocality::OwnServer,
        payer: Payer::CustomerKey,
        credential_binding: Some("customer-key-1".to_owned()),
        catalog_revision: Some("catalog-7".to_owned()),
        custody: KeyCustody::T0,
        rates: Vec::new(),
        payer_person: None,
    })
}

/// A declared run with room for every call here, and its receipts.
fn declared_run() -> (RunAdmission, Arc<MemoryReceipts>) {
    let receipts = Arc::new(MemoryReceipts::default());
    let run = RunAdmission::new(
        format!("settled-world:{}", EntityId::now().to_hex()),
        RunDeclaration::declared(BudgetLine {
            limit_units: 10_000,
            reserve_units: CALL_RESERVE,
            unit: LeaseUnit::tokens(),
        }),
        None,
        receipts.clone(),
    );
    (run, receipts)
}

/// Every receipt of kind `event` (`"dispatched"`, `"settled"`) as the JSON a
/// host sink writes, in order.
fn rows_of(receipts: &MemoryReceipts, event: &str) -> TestResult<Vec<Value>> {
    let mut rows = Vec::new();
    for row in receipts.rows() {
        let kind = match &row.event {
            RunEvent::Admitted(_) => "admitted",
            RunEvent::Dispatched { .. } => "dispatched",
            RunEvent::Settled { .. } => "settled",
            RunEvent::Denied { .. } => "denied",
            _ => "other",
        };
        if kind == event {
            rows.push(serde_json::to_value(&row)?);
        }
    }
    Ok(rows)
}

/// Sends one call per entry of `worlds` through the run's gate, in order.
fn call_through_gate(run: &RunAdmission, worlds: &[Option<EntityId>]) -> TestResult {
    let offer = customer_offer()?;
    let gated = run.gate(Arc::new(AnsweringProvider), &offer);
    for world in worlds {
        let request = request_in(*world)?;
        block_on_ready(run.call(
            &gated,
            RunCall {
                selector: None,
                request: &request,
                offer: &offer,
            },
        ))
        .map_err(|error| format!("call in world {world:?} failed: {error:?}"))?;
    }
    Ok(())
}

#[test]
fn a_settled_receipt_names_its_admitted_world() -> TestResult {
    let harbor = EntityId::now();
    let (run, receipts) = declared_run();
    call_through_gate(&run, &[Some(harbor), None])?;
    // A call admitted in the world and settled before it went out.
    let offer = customer_offer()?;
    let request = request_in(Some(harbor))?;
    let permit = run
        .admit(RunCall {
            selector: None,
            request: &request,
            offer: &offer,
        })
        .map_err(|denied| format!("unsent call refused: {denied:?}"))?;
    permit
        .settle(CallOutcome::Failed)
        .map_err(|denied| format!("unsent call did not settle: {denied:?}"))?;

    let settled = rows_of(&receipts, "settled")?;
    assert_eq!(
        settled.len(),
        3,
        "one Settled receipt per call: {settled:?}"
    );
    let named: Vec<Option<&Value>> = settled.iter().map(|row| row.get("world")).collect();
    let harbor_json = serde_json::to_value(harbor)?;
    assert_eq!(
        named,
        vec![Some(&harbor_json), None, Some(&harbor_json)],
        "each Settled receipt names the world its call was admitted in, and a call that named \
         none claims none: {settled:?}",
    );
    Ok(())
}

#[test]
fn a_dispatched_receipt_names_its_admitted_world() -> TestResult {
    let harbor = EntityId::now();
    let orchard = EntityId::now();
    let (run, receipts) = declared_run();
    call_through_gate(&run, &[Some(harbor), None, Some(orchard)])?;

    let dispatched = rows_of(&receipts, "dispatched")?;
    assert_eq!(
        dispatched.len(),
        3,
        "one Dispatched receipt per provider call: {dispatched:?}"
    );
    let named: Vec<Option<&Value>> = dispatched.iter().map(|row| row.get("world")).collect();
    assert_eq!(
        named,
        vec![
            Some(&serde_json::to_value(harbor)?),
            None,
            Some(&serde_json::to_value(orchard)?),
        ],
        "each provider call's Dispatched receipt names the world its admission named: \
         {dispatched:?}",
    );
    // The Admitted rows the dispatches join to name the same worlds.
    let admitted = rows_of(&receipts, "admitted")?;
    let admitted_worlds: Vec<Option<&Value>> =
        admitted.iter().map(|row| row.get("world")).collect();
    assert_eq!(admitted_worlds, named, "{admitted:?}");
    Ok(())
}
