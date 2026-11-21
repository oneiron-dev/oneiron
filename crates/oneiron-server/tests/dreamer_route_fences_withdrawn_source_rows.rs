//! A Dreamer call sends nothing of its input again once a row it was read
//! from is erased (FIX-LIST [DREAMER-STEP-RESENDS-ERASED-SOURCE-WORDS]).
//!
//! A Dreamer step sends on its role's route, which a pass lends the engine
//! bound to the rows each call's input was read from (FIX 6998): the sieve
//! follower's ask and fold, an extraction, a profile. The request's bytes
//! hold those rows' words. The step's transport retry sends the same request
//! again on the same backend (`llm/step/retry.rs`), and the ladder sends it
//! again once a rung that refused it for its rate is back; each send warms
//! the provider's prompt cache, keyed by those bytes, with them again. Once
//! the owner erases one of the rows (GDPR erase) while the call is out, no
//! later send may carry its words.
//!
//! Each case stores two CLAIMs about one PERSON: one the owner then erases,
//! one that stays. The route is the one a pass lends
//! (`test_doors::dreamer_sourced_route`), over a one-rung seat on a scripted
//! local model, its rests kept in the vault as a served vault's are.
//!
//! Test 1, a step's resend: a call bound to both rows and a call bound to
//! the kept row alone are each answered (guard). The owner erases one row.
//! The first request sent again on its bound backend, as the step's retry
//! sends it, fails and reaches nothing, while the second, sent again, is
//! answered (guard). On main the resend reaches the model and is answered
//! (RED).
//!
//! Test 2, a rate wait's resend: the model refuses a send for its rate, with
//! a one-second reset. A call bound to the kept row waits the limit out and
//! is answered by its resend (guard). For a call bound to both rows the
//! model holds its refusal until the owner's erase has committed: the call
//! then fails, and nothing more reaches the model. On main the ladder sends
//! it again after the wait and it is answered (RED).
//!
//! Test 3, a durable step's fallback (REVIEW-10342 round 1): a durable
//! step, whose fatal failures a deterministic fallback answers as the merge
//! resolution's value step's do, runs through the production step layer on
//! the lent route. One bound to the kept row is answered by the model
//! (guard). The owner erases a row; a step bound to both rows then reaches
//! no model and ends with an error, and its fallback answers nothing. On the
//! fence's first build the fence's refusal is an invalid request, which the
//! fallback answers, so the step finishes as if the provider had failed
//! (RED).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test
//! dreamer_route_fences_withdrawn_source_rows`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::dreamer_runner::EnqueueDreamerConsolidationAttempt;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::MemoryReceipts;
use oneiron::llm::{DurableStepContext, StepOutcome, call_as_step};
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ClaimApprovalStatus,
    ClaimBody, ClaimLifecycleStatus, ClaimSubject, ContentPart, DeterministicFallback,
    DreamerConsolidationScope, DreamerRunnerStore, EdgeActorClass, EnqueueDreamerAttemptOutcome,
    EntityId, LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef,
    ResponseFormat, TierPrecedence, TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::undeclared_run;
use oneiron_server::test_doors::dreamer_sourced_route::{LentDreamerRoute, lent_dreamer_route};
use serde_json::{Value, json};

/// The words of the CLAIM the owner erases, which only that row holds.
const ERASED_WORDS: &str = "Mara keeps her clinic visit on the ninth floor of the harbour annex.";

/// The words of the CLAIM that stays.
const KEPT_WORDS: &str = "The ferry timetable moved the last crossing to 21 40.";

/// How long the scripted model's rate refusal says its limit lasts: well
/// inside the vault's shipped longest wait (60 s), so the ladder waits it
/// out and sends again.
const COOLDOWN_SECS: u64 = 1;

/// The longest a call here may take.
const CALL_LIMIT: Duration = Duration::from_secs(60);

/// A seat of one model on `model`, for the role [`lent`] lends.
fn models(model: &FakeLlm) -> ModelsConfig {
    let models = format!(
        r#"
[providers.house]
kind = "local-openai-compat"
base_url = "{}"
[roles.generative_reasoner]
rungs = [{{ model = "house:step-model" }}]
"#,
        model.base_url
    );
    ModelsConfig::from_toml(&models, None).expect("FIXTURE: a valid models config")
}

fn budget() -> BudgetGuard {
    BudgetGuard::new(
        "dreamer-route-source-fence",
        100_000,
        BudgetExhaustionPolicy::Suspend,
    )
}

/// A vault in `dir` with its device keystore installed.
fn opened(dir: &Path) -> Arc<Vault> {
    let vault = Arc::new(Vault::open(dir, VaultConfig::device()).unwrap());
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault
}

/// The route a pass lends its role, over the seat on `model`, its rests in
/// `vault`.
fn lent(model: &FakeLlm, vault: &Arc<Vault>) -> LentDreamerRoute {
    let run = undeclared_run(
        "dreamer-route-source-fence",
        budget(),
        None,
        Arc::new(MemoryReceipts::default()),
    );
    lent_dreamer_route(&models(model), vault, ModelRole::GenerativeReasoner, run)
        .expect("FIXTURE: the seat serves the role")
}

/// A Dreamer call whose input is `words`.
fn request(model: &ModelId, words: &str) -> LlmRequest {
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
                text: words.to_owned(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

/// A durable Dreamer step whose input is `words`: a deterministic fallback
/// answers any fatal failure of its call, as the merge resolution's value
/// step's does (`executor/merge_resolution.rs`).
fn durable_request(model: &ModelId, words: &str) -> LlmRequest {
    let mut request = request(model, words);
    request.envelope.class = CallClass::Durable {
        fallback: DeterministicFallback {
            name: "json_rules_v1".into(),
            config: Some(
                json!({"version": 1, "rows": [{"failure": "fatal", "value": {"value": null}}]}),
            ),
        },
    };
    request
}

/// A queued consolidation attempt in `vault`, for durable steps to run under.
fn queued_attempt(vault: &Vault) -> oneiron::AttemptId {
    let enqueued = DreamerRunnerStore::new(vault)
        .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: rmpv::Value::from("input:durable-step-source-fence"),
            parent_attempt: None,
            dedupe_key: Some("durable-step-source-fence".to_owned()),
            run_id: None,
            now: 10,
        })
        .expect("FIXTURE: the attempt is queued");
    match enqueued {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        // The outcome enum is `#[non_exhaustive]` outside the crate.
        other => panic!("FIXTURE: unexpected enqueue outcome {other:?}"),
    }
}

/// The PERSON the stored CLAIMs are about.
fn stored_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"Mara",
        )
        .expect("FIXTURE: the PERSON is stored");
    id
}

/// A CLAIM about `subject` whose value is `words`, stored in `vault`.
fn stored_claim(vault: &Vault, subject: EntityId, words: &str) -> EntityId {
    let id = EntityId::now();
    let body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(words),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: the claim body");
    vault
        .put_claim(&id, &body, TimeRange { start: 10, end: 10 }, 10)
        .expect("FIXTURE: the CLAIM is stored");
    id
}

/// The owner's privacy (GDPR) erase of `row`, confirmed from its preview.
fn privacy_erase(vault: &Vault, row: EntityId) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault owner");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let preview = memory
        .preview_entity_delete(&row)
        .expect("FIXTURE: the row previews for erase");
    memory
        .confirm_entity_erase(
            &preview,
            EraseOptions {
                reason: EraseReason::GdprDelete,
                also_same_bytes: false,
                veto_starter: None,
            },
        )
        .expect("FIXTURE: the privacy erase runs");
    assert!(
        vault.is_deleted_shell(&row).unwrap(),
        "FIXTURE: the erase leaves the row deleted"
    );
}

/// The model's rate refusal, back in [`COOLDOWN_SECS`].
fn rate_limited() -> Reply {
    Reply::Error {
        status: 429,
        headers: vec![("retry-after".into(), COOLDOWN_SECS.to_string())],
        body: json!({"error": {"message": "rate limit", "type": "rate_limit_error"}}),
    }
}

/// Every text part of a request body the model received, joined.
fn sent_text(body: &Value) -> String {
    body["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|message| match &message["content"] {
            Value::String(text) => text.clone(),
            Value::Array(parts) => parts
                .iter()
                .filter_map(|part| part["text"].as_str())
                .collect::<Vec<_>>()
                .join(""),
            _ => String::new(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `sent`, which must end within [`CALL_LIMIT`].
async fn ended<T>(sent: impl Future<Output = T>) -> T {
    tokio::time::timeout(CALL_LIMIT, sent)
        .await
        .expect("the call ends")
}

#[test]
fn a_step_resend_sends_nothing_once_a_source_row_is_erased() {
    run_on_engine_stack("dreamer-route-erased-step-resend", || async {
        let model = FakeLlm::start(Vec::new(), Some(Reply::text("read"))).await;
        let dir = tempfile::tempdir().unwrap();
        let vault = opened(dir.path());
        let person = stored_person(&vault);
        let erased = stored_claim(&vault, person, ERASED_WORDS);
        let kept = stored_claim(&vault, person, KEPT_WORDS);
        let route = lent(&model, &vault);
        let carrier = budget();
        let lease = carrier
            .admit()
            .expect("FIXTURE: the carrier admits a lease")
            .lease;
        let both = route.sourced(vec![erased, kept]);
        let alone = route.sourced(vec![kept]);
        let stale = request(route.model(), &format!("{ERASED_WORDS}\n{KEPT_WORDS}"));
        let clean = request(route.model(), KEPT_WORDS);

        // Guard: each bound call goes out and is answered.
        ended(both.generate(stale.clone(), &lease))
            .await
            .expect("FIXTURE: a call bound to live rows is answered");
        ended(alone.generate(clean.clone(), &lease))
            .await
            .expect("FIXTURE: a call bound to the kept row is answered");
        assert_eq!(
            model.seen().len(),
            2,
            "FIXTURE: both calls reached the model"
        );

        privacy_erase(&vault, erased);
        let resent = ended(both.generate(stale, &lease)).await;
        assert!(
            resent.is_err(),
            "a resend bound to a row erased since was answered"
        );
        // Guard: a resend bound to the kept row alone still goes out.
        ended(alone.generate(clean, &lease))
            .await
            .expect("FIXTURE: a resend bound to the kept row alone is answered");
        let seen = model.seen();
        assert_eq!(
            seen.len(),
            3,
            "the resend of a request read from a row erased since reached the model"
        );
        assert!(
            !sent_text(&seen[2].body).contains(ERASED_WORDS),
            "FIXTURE: the kept row's resend holds none of the erased words"
        );
    });
}

#[test]
fn a_rate_wait_resend_sends_nothing_once_a_source_row_is_erased() {
    run_on_engine_stack("dreamer-route-erased-rate-resend", || async {
        let model = FakeLlm::start(Vec::new(), Some(Reply::text("read"))).await;
        let dir = tempfile::tempdir().unwrap();
        let vault = opened(dir.path());
        let person = stored_person(&vault);
        let erased = stored_claim(&vault, person, ERASED_WORDS);
        let kept = stored_claim(&vault, person, KEPT_WORDS);
        let route = lent(&model, &vault);
        let carrier = budget();
        let lease = carrier
            .admit()
            .expect("FIXTURE: the carrier admits a lease")
            .lease;
        let both = route.sourced(vec![erased, kept]);
        let alone = route.sourced(vec![kept]);

        // Guard: a call bound to the kept row, refused for its rate, waits
        // the limit out and is answered by its resend.
        model.push(rate_limited());
        ended(alone.generate(request(route.model(), KEPT_WORDS), &lease))
            .await
            .expect("FIXTURE: a rate-refused call of a live row is answered after the wait");
        assert_eq!(
            model.seen().len(),
            2,
            "FIXTURE: the wait's resend went out and was answered"
        );

        // The same refusal for a call bound to both rows, held by the model
        // until the owner's erase has committed.
        model.push(Reply::HoldThen(Box::new(rate_limited())));
        let stale = request(route.model(), &format!("{ERASED_WORDS}\n{KEPT_WORDS}"));
        let sent = ended(both.generate(stale, &lease));
        let erase = async {
            model.wait_holding().await;
            privacy_erase(&vault, erased);
            model.release();
        };
        let (outcome, ()) = tokio::join!(sent, erase);
        assert!(
            outcome.is_err(),
            "a call whose row was erased in its rate wait was answered by its resend"
        );
        assert_eq!(
            model.seen().len(),
            3,
            "the rate wait's resend of a request read from a row erased since reached the model"
        );
    });
}

#[test]
fn a_durable_step_bound_to_an_erased_row_ends_on_no_fallback() {
    run_on_engine_stack("dreamer-route-erased-durable-step", || async {
        let model = FakeLlm::start(Vec::new(), Some(Reply::text("read"))).await;
        let dir = tempfile::tempdir().unwrap();
        let vault = opened(dir.path());
        let person = stored_person(&vault);
        let erased = stored_claim(&vault, person, ERASED_WORDS);
        let kept = stored_claim(&vault, person, KEPT_WORDS);
        let route = lent(&model, &vault);
        let both = route.sourced(vec![erased, kept]);
        let alone = route.sourced(vec![kept]);
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the vault owner");
        let step = DurableStepContext {
            vault: &vault,
            attempt_id: queued_attempt(&vault),
            run_id: None,
            envelope_actor: WriteActor::new(owner, EdgeActorClass::Human),
            subject: person,
            deadline: None,
            now_ms: 20_000,
            spend_scope: None,
            wake_pass_bound: false,
        };
        let guard = budget();

        // Guard: a durable step bound to the kept row is answered by the model.
        let answered = ended(call_as_step(
            &step,
            &*alone,
            &guard,
            durable_request(route.model(), KEPT_WORDS),
        ))
        .await;
        assert!(
            matches!(
                answered,
                Ok(StepOutcome::Finished {
                    failure_policy: None,
                    ..
                })
            ),
            "FIXTURE: a durable step of a live row is answered by the model"
        );
        assert_eq!(
            model.seen().len(),
            1,
            "FIXTURE: that step reached the model"
        );

        privacy_erase(&vault, erased);
        let refused = ended(call_as_step(
            &step,
            &*both,
            &guard,
            durable_request(route.model(), &format!("{ERASED_WORDS}\n{KEPT_WORDS}")),
        ))
        .await;
        assert_eq!(
            model.seen().len(),
            1,
            "FIXTURE: a step bound to a row erased since reached the model"
        );
        assert!(
            !matches!(refused, Ok(StepOutcome::Finished { .. })),
            "a durable step bound to a row erased before its send finished on its fallback, \
             as if its provider had failed"
        );
    });
}
