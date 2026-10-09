use super::*;

use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, LlmMessage, LlmMessageRole, ModelId, ModelTierRef,
    ResponseFormat, TierPrecedence,
};
use std::sync::{Arc, Barrier};
use std::thread;

mod per_call;

fn on_device_request() -> LlmRequest {
    LlmRequest {
        model: ModelId::new("test/model@r1").expect("model id"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OnDevice,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: Vec::new(),
        }],
        tools: Vec::new(),
        params: std::collections::BTreeMap::new(),
        provider_options: std::collections::BTreeMap::new(),
    }
}

#[test]
fn on_device_continuation_racing_abort_never_gets_transiently_denied() {
    for _ in 0..128 {
        let guard = Arc::new(BudgetGuard::with_reserve_units(
            "job",
            10,
            10,
            BudgetExhaustionPolicy::ContinueOnLocal,
        ));
        let metered = guard.admit().expect("initial lease");
        let request = Arc::new(on_device_request());
        let start = Arc::new(Barrier::new(2));

        let local_guard = Arc::clone(&guard);
        let local_request = Arc::clone(&request);
        let local_start = Arc::clone(&start);
        let local = thread::spawn(move || {
            local_start.wait();
            local_guard.admit_for_request(&local_request)
        });

        let abort_guard = Arc::clone(&guard);
        let abort_start = Arc::clone(&start);
        let lease = metered.lease.clone();
        let abort = thread::spawn(move || {
            abort_start.wait();
            abort_guard.abort(&lease)
        });

        let admission = local.join().expect("local admission thread");
        abort.join().expect("abort thread").expect("abort lease");
        assert!(
            admission.is_ok(),
            "local continuation was denied despite either free capacity or local policy: {admission:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// ONE-1348 `budget_policy` row-accounting tests.
//
// Fixed tiny units against the policy-aware constructor. The existing
// single-pool tests above stay untouched; the two regression tests below
// prove the empty/absent table is byte-for-byte the legacy meter.
// ---------------------------------------------------------------------------

fn policy_test_actor(seed: u8) -> WriteActor {
    WriteActor::new(
        EntityId::from_bytes([seed; 16]).expect("test actor id"),
        oneiron_contracts::edge::EdgeActorClass::Agent,
    )
}

fn actor_row(seed: u8, floor: Option<u64>, cap: Option<u64>) -> BudgetPolicyRow {
    BudgetPolicyRow::new(
        BudgetPolicySelector::Actor(EntityId::from_bytes([seed; 16]).expect("test actor id")),
        floor,
        cap,
    )
}
