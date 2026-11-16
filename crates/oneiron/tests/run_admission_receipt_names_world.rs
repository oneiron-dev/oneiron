//! Census row L5-25 (DEC-0005 world privacy, fix 12): every provider call on a
//! private world writes a receipt with the world it read. The run admission's
//! `Admitted` receipt names the world a model call named in its scope, so the
//! owner can see which private world's words a call carried.
//!
//! Each call goes through the public `RunAdmission::admit`, as a gated backend
//! admits before it sends, and is read back from the run's receipt sink as the
//! JSON a host sink writes. A call that names no world gets no world on its
//! receipt: its true world provenance is not known at admission (DEC-0005
//! :446).
//!
//! `cargo test --locked -p oneiron --all-features --test
//! run_admission_receipt_names_world`.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::llm;
use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferBinding, OfferRoute, Payer,
    RunAdmission, RunCall, RunDeclaration, RunEvent,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The model every request and offer here names.
const MODEL: &str = "test/model@r1";
/// What each call reserves, in tokens.
const CALL_RESERVE: u64 = 500;

/// One model request whose scope names `world`.
fn request_in(world: Option<EntityId>) -> TestResult<llm::LlmRequest> {
    Ok(llm::LlmRequest {
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
        messages: vec![llm::LlmMessage {
            role: llm::LlmMessageRole::User,
            content: vec![llm::ContentPart::Text {
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

/// Admits one call per entry of `worlds`, in order, on one declared run, and
/// returns the run's `Admitted` receipts as the JSON a host sink writes.
fn admitted_receipts(worlds: &[Option<EntityId>]) -> TestResult<Vec<Value>> {
    let receipts = Arc::new(MemoryReceipts::default());
    let run = RunAdmission::new(
        format!("receipt-world:{}", EntityId::now().to_hex()),
        RunDeclaration::declared(BudgetLine {
            limit_units: 10_000,
            reserve_units: CALL_RESERVE,
            unit: LeaseUnit::tokens(),
        }),
        None,
        receipts.clone(),
    );
    let offer = customer_offer()?;
    for world in worlds {
        let request = request_in(*world)?;
        // The receipt is written at admission; the permit is not dispatched.
        let _permit = run
            .admit(RunCall {
                selector: None,
                request: &request,
                offer: &offer,
            })
            .map_err(|denied| format!("call in world {world:?} refused: {denied:?}"))?;
    }
    let rows = receipts
        .rows()
        .into_iter()
        .filter(|row| matches!(row.event, RunEvent::Admitted(_)))
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[test]
fn a_model_call_receipt_names_the_world_its_scope_named() -> TestResult {
    let harbor = EntityId::now();
    let orchard = EntityId::now();
    let rows = admitted_receipts(&[Some(harbor), Some(orchard), None])?;
    assert_eq!(rows.len(), 3, "one Admitted receipt per call: {rows:?}");
    for (row, world) in rows.iter().zip([harbor, orchard]) {
        assert_eq!(
            row.get("world"),
            Some(&serde_json::to_value(world)?),
            "the Admitted receipt names the world {} its call read: {row}",
            world.to_hex(),
        );
    }
    assert_eq!(
        rows[2].get("world"),
        None,
        "a call that names no world claims none on its receipt: {}",
        rows[2],
    );
    Ok(())
}

#[test]
fn a_receipt_names_only_its_own_calls_world() -> TestResult {
    let harbor = EntityId::now();
    let rows = admitted_receipts(&[None, Some(harbor), None])?;
    assert_eq!(rows.len(), 3, "one Admitted receipt per call: {rows:?}");
    let named: Vec<Option<&Value>> = rows.iter().map(|row| row.get("world")).collect();
    assert_eq!(
        named,
        vec![None, Some(&serde_json::to_value(harbor)?), None],
        "only the call in the world names it; the calls around it name none",
    );
    Ok(())
}
