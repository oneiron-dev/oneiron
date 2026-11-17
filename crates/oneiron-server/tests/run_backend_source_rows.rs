//! A run backend's sourced call names the rows its request was read from
//! (FIX-LIST [CODE-MODE-STEP-SOURCES-UNWITNESSED], part B). An engine step
//! hands its backend the rows it computed for the step's request
//! (`LlmBackend::generate_sourced`); a Dreamer thing child's backend is a
//! `RunBackend` behind its counted wrapper. The call's permit and its
//! `Admitted` receipt carry those rows (FIX 5760), so a later read of what
//! the call made is released by their worlds. Unknown rows (`None`) stay
//! unknown, and a call made without rows names none.
//!
//! `cargo test --locked -p oneiron-server --all-features --test
//! run_backend_source_rows`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use fake_llm::{FakeLlm, Reply};
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::{MemoryReceipts, RunEvent};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    EntityId, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence,
};
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::{ModelRuntime, RunBackend, undeclared_run};

/// The longest a call here may take.
const CALL_LIMIT: Duration = Duration::from_secs(60);

/// A runtime whose reasoner seat is one model on `server`.
fn runtime(server: &FakeLlm) -> ModelRuntime {
    let models = format!(
        r#"
[providers.house]
kind = "local-openai-compat"
base_url = "{}"
[roles.generative_reasoner]
rungs = [{{ model = "house:step-model" }}]
"#,
        server.base_url
    );
    let config = ModelsConfig::from_toml(&models, None).expect("a valid models config");
    ModelRuntime::build(Some(&config), oneiron::HostingPrivacyPosture::SelfHostLocal)
}

fn request(model: &ModelId) -> LlmRequest {
    LlmRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("answer".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "run the step".into(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

fn budget() -> BudgetGuard {
    BudgetGuard::new("run-backend-rows", 100_000, BudgetExhaustionPolicy::Suspend)
}

/// How a call reaches the backend.
enum Call {
    Generate,
    Sourced(Option<Vec<EntityId>>),
}

/// One call on a `RunBackend` over the reasoner's seat, made as `call`
/// says: the source rows of each `Admitted` receipt it left.
async fn admitted_rows(call: Call) -> Vec<Option<Vec<EntityId>>> {
    let server = FakeLlm::start(Vec::new(), Some(Reply::text("done"))).await;
    let runtime = runtime(&server);
    let seat = runtime
        .seat(ModelRole::GenerativeReasoner)
        .expect("the reasoner's seat");
    let receipts = Arc::new(MemoryReceipts::default());
    let run = undeclared_run("run-backend-rows", budget(), None, Arc::clone(&receipts));
    let backend = RunBackend::new(Arc::clone(&seat.ladder), run);
    // The caller's lease is the caller's own meter's: the backend sends on
    // its run's permits.
    let carrier = budget();
    let lease = carrier.admit().expect("the carrier admits a lease").lease;
    let request = request(&seat.model);
    let sent = match call {
        Call::Generate => backend.generate(request, &lease),
        Call::Sourced(rows) => backend.generate_sourced(request, &lease, rows),
    };
    tokio::time::timeout(CALL_LIMIT, sent)
        .await
        .expect("the call ends")
        .expect("the seat answers the call");
    assert_eq!(server.seen().len(), 1, "one call reached the model");
    receipts
        .rows()
        .into_iter()
        .filter_map(|row| match row.event {
            RunEvent::Admitted(facts) => Some(facts.source_rows),
            _ => None,
        })
        .collect()
}

/// The rows the engine names for a step's request ride on the call's
/// permit: its `Admitted` receipt names exactly them.
#[tokio::test]
async fn a_sourced_call_names_the_rows_its_request_was_read_from() {
    let rows = vec![EntityId::now(), EntityId::now()];
    let admitted = admitted_rows(Call::Sourced(Some(rows.clone()))).await;
    assert!(!admitted.is_empty(), "the call was admitted");
    assert!(
        admitted.iter().all(|named| named.as_ref() == Some(&rows)),
        "every Admitted receipt names the request's rows: {admitted:?}"
    );
}

/// Rows the engine does not know stay unknown, and a call made with no
/// rows names none: nothing stands in for them.
#[tokio::test]
async fn an_unknown_or_unnamed_call_names_no_rows() {
    for call in [Call::Sourced(None), Call::Generate] {
        let admitted = admitted_rows(call).await;
        assert!(!admitted.is_empty(), "the call was admitted");
        assert!(
            admitted.iter().all(Option::is_none),
            "no Admitted receipt names rows: {admitted:?}"
        );
    }
}
