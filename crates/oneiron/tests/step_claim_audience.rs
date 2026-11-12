//! A `dreamer.step` claim holds its call's raw response, so it carries the
//! call's exposure (S63E-RULED, live leak 2): a step whose call is bound to a
//! relationship files a claim inside that relationship, which a member
//! outside it does not read. On main the claim was stamped `rel: all`.
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! step_claim_audience`. On the testkit: a copy of the empty fixture vault,
//! and a scripted model that answers each prompt by its digest.
use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oneiron::claim::{PointRead, ScopedReadActorKey};
use oneiron::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm::{DREAMER_STEP_PREDICATE, DurableStepContext, Scope, StepOutcome, call_as_step};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::temporal::TimeRange;
use oneiron::write_envelope::WriteActor;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};
use oneiron::{EntityId, Vault};
use oneiron_testkit::{FixtureVault, ScriptedBackend, Step, fixture_cache};

fn block_on<F: Future>(future: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl std::task::Wake for ThreadWaker {
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

fn request(scope: Scope, text: &str) -> LlmRequest {
    LlmRequest {
        model: ModelId::new("test/model@r1").expect("model id"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope,
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: text.to_owned(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: std::collections::BTreeMap::new(),
        provider_options: std::collections::BTreeMap::new(),
        host_segments: None,
    }
}

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"human",
        )
        .expect("a person");
    id
}

/// The `dreamer.step` claims in the vault, by id.
fn step_claims(vault: &Vault) -> BTreeSet<EntityId> {
    vault
        .entities_by_type(ENTITY_TYPE_CLAIM)
        .expect("claims")
        .into_iter()
        .filter(|id| {
            vault
                .get_claim(id)
                .expect("claim")
                .is_some_and(|body| body.predicate == DREAMER_STEP_PREDICATE)
        })
        .collect()
}

#[test]
fn a_step_claim_from_a_relationship_bound_call_stays_inside_the_relationship() {
    let copy = FixtureVault::empty(&fixture_cache!())
        .expect("the empty fixture")
        .copy()
        .expect("a private copy");
    let vault = copy.open().expect("vault");
    let actor = person(&vault);
    let subject = person(&vault);
    let outsider = person(&vault);
    let attempt = match DreamerRunnerStore::new(&vault)
        .enqueue(EnqueueDreamerAttempt {
            attempt_type: "step-audience-test".to_owned(),
            input: rmpv::Value::from("input"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("run-test".to_owned()),
            now: 10,
        })
        .expect("attempt")
    {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        other => panic!("unexpected enqueue outcome: {other:?}"),
    };
    let ctx = DurableStepContext {
        vault: &vault,
        attempt_id: attempt,
        run_id: Some("run-test".to_owned()),
        envelope_actor: WriteActor::new(actor, EdgeActorClass::Agent),
        subject,
        deadline: None,
        now_ms: 10_000,
        spend_scope: None,
    };
    let guard =
        BudgetGuard::with_reserve_units("step-test", 10_000, 500, BudgetExhaustionPolicy::Suspend);

    // A call bound to one relationship: its words are that relationship's.
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 10, end: 10 },
            10,
            b"relationship",
        )
        .expect("a relationship");
    let bound = Scope {
        relationship: Some(BTreeSet::from([relationship])),
        ..Scope::default()
    };
    let bound_request = request(bound, "words from a relationship-limited MESSAGE");
    let open_request = request(Scope::default(), "open words");
    let backend = ScriptedBackend::new(vec![
        Step::text(
            "bound",
            ScriptedBackend::digest_of(&bound_request),
            "the private words, echoed back",
        )
        .buffered()
        .usage(100, 50),
        Step::text(
            "open",
            ScriptedBackend::digest_of(&open_request),
            "an open answer",
        )
        .buffered()
        .usage(100, 50),
    ])
    .expect("the script");
    let before = step_claims(&vault);
    assert!(matches!(
        block_on(call_as_step(&ctx, &backend, &guard, bound_request,)).expect("the bound step"),
        StepOutcome::Finished { .. }
    ));
    let filed: Vec<EntityId> = step_claims(&vault).difference(&before).copied().collect();
    let [claim] = filed.as_slice() else {
        panic!("one step claim, found {}", filed.len());
    };
    let body = vault.get_claim(claim).expect("claim").expect("step claim");
    assert_eq!(
        body.rel
            .as_ref()
            .map(|rel| rel.iter().copied().collect::<Vec<_>>()),
        Some(vec![relationship]),
        "the step claim carries the call's relationship, never all"
    );

    // A member outside the relationship reads nothing of it.
    let outside = vault.scoped_read(
        ScopedReadActorKey::with_actor_class(
            outsider.to_hex(),
            EdgeActorClass::Human.gate_actor_class(),
        )
        .expect("outsider key")
        .require_access_grants(Some(outsider)),
    );
    assert_eq!(
        outside
            .read(&[PointRead::id(*claim)], None)
            .expect("outsider read")
            .value,
        vec![None]
    );

    // An unbound call's claim is as before.
    let before = step_claims(&vault);
    assert!(matches!(
        block_on(call_as_step(&ctx, &backend, &guard, open_request,)).expect("the unbound step"),
        StepOutcome::Finished { .. }
    ));
    let filed: Vec<EntityId> = step_claims(&vault).difference(&before).copied().collect();
    let [open] = filed.as_slice() else {
        panic!("one step claim, found {}", filed.len());
    };
    assert_eq!(
        vault
            .get_claim(open)
            .expect("claim")
            .expect("step claim")
            .rel,
        None
    );
    backend.finish();
}
