//! Census row L5-25 (DEC-0005 world privacy, fix 12): every provider call on a
//! private world writes a receipt with the world it read, a refused one too.
//! A fallback held on the device writes one `Denied` row per held rung
//! (#world-privacy-models-built); that row names the world the held call
//! named, through `RunAdmission::refuse_in_world`, as the ladder's hold
//! refuses. A dispatch the run refuses after admission names the world its
//! permit was admitted in, joined by the permit's lease.
//!
//! The hold's judge stays content-free: the row names the call's own world,
//! never which world kept a call that named none on the device.
//!
//! `cargo test --locked -p oneiron --all-features --test
//! run_admission_denied_names_world`.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferBinding, OfferRoute, Payer,
    RunAdmission, RunCall, RunDeclaration, RunDenied, RunEvent,
};
use oneiron::llm::{self, DispatchRefused, SingleRouteBackend};
use oneiron::{
    BudgetLease, ContentPart, EntityId, FatalLlmError, LlmBackend, LlmGenerateFuture, LlmMessage,
    LlmMessageRole, LlmRequest, LlmResult, LlmStreamResult,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The model every request and offer here names.
const MODEL: &str = "test/model@r1";
/// What each call reserves, in tokens.
const CALL_RESERVE: u64 = 500;
/// The reason a held rung's refusal carries, as the ladder's hold names it.
const HELD: &str = "world_stays_on_device";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("a gated call pending on something other than its own refusal");
}

/// A provider no call here reaches: every call is refused before it sends.
struct UnreachedProvider;

impl LlmBackend for UnreachedProvider {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        panic!("a refused dispatch reached the provider");
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

impl SingleRouteBackend for UnreachedProvider {
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

/// The customer's own key `credential` for the model on the owner's server.
fn customer_offer(credential: &str) -> TestResult<OfferBinding> {
    Ok(OfferBinding {
        offer: format!("{MODEL}@model.test"),
        model: llm::ModelId::new(MODEL)?,
        route: OfferRoute::new("fake", "https://model.test:443")?,
        locality: llm::ModelLocality::OwnServer,
        payer: Payer::CustomerKey,
        credential_binding: Some(credential.to_owned()),
        catalog_revision: Some("catalog-7".to_owned()),
        custody: KeyCustody::T0,
        rates: Vec::new(),
        payer_person: None,
    })
}

fn declared_run() -> (RunAdmission, Arc<MemoryReceipts>) {
    let receipts = Arc::new(MemoryReceipts::default());
    let run = RunAdmission::new(
        format!("denied-world:{}", EntityId::now().to_hex()),
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

/// The run's `Denied` receipts, as the JSON a host sink writes, in order.
fn denied_rows(receipts: &MemoryReceipts) -> TestResult<Vec<Value>> {
    let mut rows = Vec::new();
    for row in receipts.rows() {
        if matches!(row.event, RunEvent::Denied { .. }) {
            rows.push(serde_json::to_value(&row)?);
        }
    }
    Ok(rows)
}

#[test]
fn a_denied_receipt_names_the_held_world() -> TestResult {
    let harbor = EntityId::now();
    let (run, receipts) = declared_run();
    // Two held rungs, as the ladder's hold refuses them: one for a call in
    // the world, one for a call that named none.
    let reason = run.refuse_in_world(
        Some("consolidation"),
        MODEL,
        RunDenied::KeptOnDevice { reason: HELD },
        Some(harbor),
    );
    assert_eq!(reason, RunDenied::KeptOnDevice { reason: HELD });
    run.refuse_in_world(
        Some("consolidation"),
        MODEL,
        RunDenied::KeptOnDevice { reason: HELD },
        None,
    );

    let rows = denied_rows(&receipts)?;
    assert_eq!(rows.len(), 2, "one Denied receipt per held rung: {rows:?}");
    assert_eq!(
        rows[0].get("world"),
        Some(&serde_json::to_value(harbor)?),
        "the held rung's Denied receipt names the world its call named: {}",
        rows[0],
    );
    assert_eq!(
        rows[1].get("world"),
        None,
        "a held call that named no world claims none: {}",
        rows[1],
    );
    Ok(())
}

#[test]
fn a_refused_dispatch_names_its_admitted_world() -> TestResult {
    let harbor = EntityId::now();
    let (run, receipts) = declared_run();
    let admitted_under = customer_offer("customer-key-1")?;
    let request = request_in(Some(harbor))?;
    let permit = run
        .admit(RunCall {
            selector: None,
            request: &request,
            offer: &admitted_under,
        })
        .map_err(|denied| format!("call refused at admission: {denied:?}"))?;
    // The same run's gate for another key on the same route: the dispatch
    // check refuses the permit, and the run writes a Denied row for its lease.
    let other_key = run.gate(
        Arc::new(UnreachedProvider),
        &customer_offer("customer-key-2")?,
    );
    let sent = block_on_ready(other_key.generate(request.clone(), permit.lease()));
    assert!(
        sent.is_err(),
        "a permit admitted under another key never starts"
    );
    drop(permit);

    let rows = denied_rows(&receipts)?;
    let refused: Vec<&Value> = rows
        .iter()
        .filter(|row| row.get("lease").is_some())
        .collect();
    assert_eq!(refused.len(), 1, "one lease-keyed Denied receipt: {rows:?}");
    assert_eq!(
        refused[0].get("world"),
        Some(&serde_json::to_value(harbor)?),
        "the refused dispatch's Denied receipt names the world its permit was admitted in: {}",
        refused[0],
    );
    let reason = receipts.rows().into_iter().find_map(|row| match row.event {
        RunEvent::Denied {
            lease: Some(_),
            reason,
            ..
        } => Some(reason),
        _ => None,
    });
    assert_eq!(
        reason,
        Some(RunDenied::Dispatch {
            refused: DispatchRefused::OfferMismatch
        }),
    );
    Ok(())
}
