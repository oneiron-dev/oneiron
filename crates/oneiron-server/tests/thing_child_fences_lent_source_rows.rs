//! A Dreamer thing child sends nothing of its input again once a row its
//! lent slices were read from is erased (FIX-LIST
//! [DREAMER-UNSOURCED-ROLE-CALLS-SEND-UNFENCED]).
//!
//! A thing child generates on its own backend, which its host builds over
//! the Dreamer's extraction route (`ai_host/dreamer_thing.rs`). Its code
//! steps' requests may copy any lent slice's transcript, through the
//! console or a port answer, and a step names no complete set of rows
//! (`step_source_rows` is unknown for a host-built task), so the backend
//! itself must read the lent rows again. The ladder sends a request again
//! once a rung that refused it for its rate is back, and the step sends it
//! again on its transport retry; each send warms the provider's prompt
//! cache with its words. Once the owner erases a lent row (GDPR erase)
//! while the child runs, no later send may carry its words.
//!
//! Each case stores two CLAIMs about one PERSON: one the owner then erases,
//! one that stays. Each child's backend is the one its host builds
//! (`test_doors::dreamer_thing_child_route`), over a one-rung seat on a
//! scripted local model, its rests kept in the vault as a served vault's
//! are; each step names no rows, as a child's does.
//!
//! Test 1, a step's resend: a child lent both rows and a child lent the
//! kept row alone each send a step and are answered (guard). The owner
//! erases one row. The first child's step sent again fails and reaches
//! nothing, while the second's, sent again, is answered (guard). On main
//! the resend reaches the model and is answered (RED).
//!
//! Test 2, a rate wait's resend: the model refuses a send for its rate, with
//! a one-second reset. A child lent the kept row waits the limit out and is
//! answered by its resend (guard). For a child lent both rows the model
//! holds its refusal until the owner's erase has committed: the step then
//! fails, and nothing more reaches the model. On main the ladder sends it
//! again after the wait and it is answered (RED).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test
//! thing_child_fences_lent_source_rows`.
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
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::MemoryReceipts;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ClaimApprovalStatus,
    ClaimBody, ClaimLifecycleStatus, ClaimSubject, ContentPart, EdgeActorClass, EntityId,
    LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence, TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::undeclared_run;
use oneiron_server::test_doors::dreamer_thing_child_route::{ThingChildRoute, thing_child_route};
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

/// A seat of one model on `model`, for the role [`child`] generates on.
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
        "thing-child-source-fence",
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

/// A thing child's generation as its host builds it, over the seat on
/// `model`, its rests in `vault`, for a child lent slices read from `lent`.
fn child(model: &FakeLlm, vault: &Arc<Vault>, lent: Vec<EntityId>) -> ThingChildRoute {
    let run = undeclared_run(
        "thing-child-source-fence",
        budget(),
        None,
        Arc::new(MemoryReceipts::default()),
    );
    thing_child_route(
        &models(model),
        vault,
        ModelRole::GenerativeReasoner,
        run,
        lent,
    )
    .expect("FIXTURE: the seat serves the role")
}

/// A code step's request whose input is `words`.
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
fn a_step_resend_sends_nothing_once_a_lent_row_is_erased() {
    run_on_engine_stack("thing-child-erased-step-resend", || async {
        let model = FakeLlm::start(Vec::new(), Some(Reply::text("read"))).await;
        let dir = tempfile::tempdir().unwrap();
        let vault = opened(dir.path());
        let person = stored_person(&vault);
        let erased = stored_claim(&vault, person, ERASED_WORDS);
        let kept = stored_claim(&vault, person, KEPT_WORDS);
        let both = child(&model, &vault, vec![erased, kept]);
        let alone = child(&model, &vault, vec![kept]);
        let carrier = budget();
        let lease = carrier
            .admit()
            .expect("FIXTURE: the carrier admits a lease")
            .lease;
        let stale = request(both.model(), &format!("{ERASED_WORDS}\n{KEPT_WORDS}"));
        let clean = request(alone.model(), KEPT_WORDS);

        // Guard: each child's step goes out and is answered.
        ended(both.backend().generate_sourced(stale.clone(), &lease, None))
            .await
            .expect("FIXTURE: a step of a child lent live rows is answered");
        ended(
            alone
                .backend()
                .generate_sourced(clean.clone(), &lease, None),
        )
        .await
        .expect("FIXTURE: a step of a child lent the kept row is answered");
        assert_eq!(
            model.seen().len(),
            2,
            "FIXTURE: both steps reached the model"
        );

        privacy_erase(&vault, erased);
        let resent = ended(both.backend().generate_sourced(stale, &lease, None)).await;
        assert!(
            resent.is_err(),
            "a step resend of a child lent a row erased since was answered"
        );
        // Guard: the step of a child lent the kept row alone still goes out.
        ended(alone.backend().generate_sourced(clean, &lease, None))
            .await
            .expect("FIXTURE: a step of a child lent the kept row alone is answered");
        let seen = model.seen();
        assert_eq!(
            seen.len(),
            3,
            "the resend of a step of a child lent a row erased since reached the model"
        );
        assert!(
            !sent_text(&seen[2].body).contains(ERASED_WORDS),
            "FIXTURE: the kept row's resend holds none of the erased words"
        );
    });
}

#[test]
fn a_rate_wait_resend_sends_nothing_once_a_lent_row_is_erased() {
    run_on_engine_stack("thing-child-erased-rate-resend", || async {
        let model = FakeLlm::start(Vec::new(), Some(Reply::text("read"))).await;
        let dir = tempfile::tempdir().unwrap();
        let vault = opened(dir.path());
        let person = stored_person(&vault);
        let erased = stored_claim(&vault, person, ERASED_WORDS);
        let kept = stored_claim(&vault, person, KEPT_WORDS);
        let both = child(&model, &vault, vec![erased, kept]);
        let alone = child(&model, &vault, vec![kept]);
        let carrier = budget();
        let lease = carrier
            .admit()
            .expect("FIXTURE: the carrier admits a lease")
            .lease;

        // Guard: a step of a child lent the kept row, refused for its rate,
        // waits the limit out and is answered by its resend.
        model.push(rate_limited());
        let clean = request(alone.model(), KEPT_WORDS);
        ended(alone.backend().generate_sourced(clean, &lease, None))
            .await
            .expect("FIXTURE: a rate-refused step of a live row is answered after the wait");
        assert_eq!(
            model.seen().len(),
            2,
            "FIXTURE: the wait's resend went out and was answered"
        );

        // The same refusal for a step of a child lent both rows, held by the
        // model until the owner's erase has committed.
        model.push(Reply::HoldThen(Box::new(rate_limited())));
        let stale = request(both.model(), &format!("{ERASED_WORDS}\n{KEPT_WORDS}"));
        let sent = ended(both.backend().generate_sourced(stale, &lease, None));
        let erase = async {
            model.wait_holding().await;
            privacy_erase(&vault, erased);
            model.release();
        };
        let (outcome, ()) = tokio::join!(sent, erase);
        assert!(
            outcome.is_err(),
            "a step whose lent row was erased in its rate wait was answered by its resend"
        );
        assert_eq!(
            model.seen().len(),
            3,
            "the rate wait's resend of a step of a child lent a row erased since reached the model"
        );
    });
}
