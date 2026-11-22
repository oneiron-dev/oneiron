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
//! The child's compaction (review P1 on #10301): the child's console, which
//! may hold a lent row's words, is sealed into a window that names no row
//! (row ids come from bridge outcomes, not the loan), and its compaction
//! pass is admitted on the child's own generation (`profiled::seat`). Each
//! pass goes out on code mode's house route, its calls metered on the
//! generation the child's host lends
//! (`test_doors::dreamer_thing_child_route::thing_child_generation`).
//!
//! Test 3, a pass after the erase: a child lent both rows compacts a window
//! holding both rows' words and is answered (guard). The owner erases one
//! row. The child's next pass over those words fails and reaches nothing,
//! while a child lent the kept row alone compacts its window and is
//! answered (guard). On main the pass reaches the model and is answered
//! (RED).
//!
//! Test 4, a rate wait's resend: as test 2, for a compaction pass. On main
//! the pass is sent again after the wait and answered (RED).
//!
//! Test 5, a spent window's wait (review round 2 on #10301): the model
//! refuses a send for a spent usage window, back in one second. A child
//! lent the kept row waits for the reset and is answered, and the owner is
//! asked nothing (guard). For a child lent both rows the model holds its
//! refusal until the owner's erase has committed: nothing more reaches the
//! model (guard), and the step ends as the invalid request a withdrawn
//! input is, which no step retries, with no quota question kept for the
//! owner. On the fence before this fix the walk ended as an unanswered
//! call: a rate refusal a step retries, after asking the owner about the
//! window (RED).
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
use oneiron::authority::MachineRole;
use oneiron::code_run::ScopedChildGeneration;
use oneiron::compaction::CompactionRequest;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::MemoryReceipts;
use oneiron::llm::{FatalLlmError, LlmError};
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ClaimApprovalStatus,
    ClaimBody, ClaimLifecycleStatus, ClaimSubject, ContentPart, EdgeActorClass, EntityId,
    LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence, TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::undeclared_run;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::compaction_pass::profiled_house_pass;
use oneiron_server::test_doors::dreamer_thing_child_route::{
    ThingChildRoute, thing_child_generation, thing_child_route,
};
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

/// The model's refusal for a spent usage window, back in
/// [`COOLDOWN_SECS`]: its offer parks until then, and a call that ends
/// unanswered on it asks the owner about the window.
fn window_spent() -> Reply {
    Reply::Error {
        status: 429,
        headers: vec![("retry-after".into(), COOLDOWN_SECS.to_string())],
        body: json!({"error": {"message": "usage limit reached", "type": "usage_limit_reached"}}),
    }
}

/// Where the runtime keeps each quota question for the owner
/// (`models/cooldown.rs` `QUESTION_PREFIX`).
const QUOTA_QUESTION_PREFIX: &str = "models:offer-cooldown:v1:ask:";

/// The keys of the quota questions `vault` keeps for its owner.
fn quota_questions(vault: &Vault) -> Vec<String> {
    vault
        .sync_state_keys_with_prefix(QUOTA_QUESTION_PREFIX)
        .expect("FIXTURE: the quota questions read")
}

/// The text of one request message: a string, or its text parts joined.
fn message_text(message: &Value) -> String {
    match &message["content"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

/// Every text part of a request body the model received, joined.
fn sent_text(body: &Value) -> String {
    body["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .map(message_text)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The scripted model's summary, which only its reply holds.
const SUMMARY: &str = "The owner noted one crossing time.";

/// The scripted model's answer to a compaction call: a summary of the span
/// its input names.
fn summary_reply(body: &Value) -> String {
    let input: Value = body["messages"]
        .as_array()
        .and_then(|messages| messages.last())
        .and_then(|message| serde_json::from_str(&message_text(message)).ok())
        .unwrap_or(Value::Null);
    json!({"from": input["from"], "through": input["through"], "summary": SUMMARY}).to_string()
}

/// One local provider as the chat role's one-rung seat, with code mode's
/// compaction live on it under the workspace's test prompt package.
fn compaction_models(model: &FakeLlm) -> ModelsConfig {
    let prompts = oneiron::prompt::workspace_test_prompt_package_root()
        .expect("FIXTURE: the workspace's test prompt package");
    ModelsConfig::from_toml(
        &format!(
            "default = \"local:test-model\"\n\
             [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
             [code_mode]\nprompt_package = {:?}\n\
             [code_mode.compaction]\nwindow_tokens = 1500\nhot_steps = 1\n\
             [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{}\"\n\
             context_tokens = 32768\n",
            prompts.display().to_string(),
            model.base_url,
        ),
        None,
    )
    .expect("FIXTURE: a valid models config")
}

/// A rooted vault in `dir` served with its AI host attached under
/// `models`, as `oneiron serve` starts one: the keystore before the server,
/// then the host root and this install's live machine profile.
async fn served(dir: &Path, models: &ModelsConfig) -> (Arc<SyncServer>, AiHost) {
    let vault = opened(dir);
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("thing-child-source-fence".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let issuer = vault.load_host_slip_issuer().unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .unwrap();
    let (server, host) = AiHost::attach(server, Some(models)).await;
    (Arc::new(server), host)
}

/// The child's console sealed into a window over `texts`: it names no row.
fn sealed(vault: &Vault, texts: &[&str]) -> CompactionRequest {
    oneiron::test_doors::compaction_request::sealed_window(vault, texts, 200)
        .expect("FIXTURE: the sealed window")
}

/// One house compaction pass of `request` on the child's `generation`, off
/// the runtime the pass blocks on.
async fn child_pass(
    server: &Arc<SyncServer>,
    generation: &Arc<dyn ScopedChildGeneration>,
    request: CompactionRequest,
) -> Result<(), String> {
    let server = Arc::clone(server);
    let generation = Arc::clone(generation);
    ended(tokio::task::spawn_blocking(move || {
        profiled_house_pass(&server, budget(), generation, &request)
    }))
    .await
    .expect("FIXTURE: the pass thread ends")
    .map(|answer| assert!(answer.summary.contains(SUMMARY), "FIXTURE: {answer:?}"))
}

/// Every compaction call the scripted model saw: its system message is the
/// compaction prompt.
fn compaction_calls(model: &FakeLlm) -> Vec<Value> {
    model
        .seen()
        .into_iter()
        .map(|seen| seen.body)
        .filter(|body| message_text(&body["messages"][0]).contains("You compact"))
        .collect()
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

#[test]
fn a_compaction_pass_sends_nothing_once_a_lent_row_is_erased() {
    run_on_engine_stack("thing-child-erased-compaction", || async {
        let model =
            FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(summary_reply)))).await;
        let dir = tempfile::tempdir().unwrap();
        let (server, _host) = served(dir.path(), &compaction_models(&model)).await;
        let vault = server.vault();
        let person = stored_person(vault);
        let erased = stored_claim(vault, person, ERASED_WORDS);
        let kept = stored_claim(vault, person, KEPT_WORDS);
        let both = thing_child_generation(vault, vec![erased, kept]);
        let alone = thing_child_generation(vault, vec![kept]);

        // Guard: a pass of a child lent live rows goes out and is answered.
        child_pass(&server, &both, sealed(vault, &[ERASED_WORDS, KEPT_WORDS]))
            .await
            .expect("FIXTURE: a pass of a child lent live rows is answered");
        assert_eq!(
            compaction_calls(&model).len(),
            1,
            "FIXTURE: the pass reached the model"
        );

        privacy_erase(vault, erased);
        let again = child_pass(&server, &both, sealed(vault, &[ERASED_WORDS, KEPT_WORDS])).await;
        assert!(
            again.is_err(),
            "a compaction pass of a child lent a row erased since was answered"
        );
        // Guard: the pass of a child lent the kept row alone still goes out.
        child_pass(&server, &alone, sealed(vault, &[KEPT_WORDS]))
            .await
            .expect("FIXTURE: a pass of a child lent the kept row alone is answered");
        let calls = compaction_calls(&model);
        assert_eq!(
            calls.len(),
            2,
            "the compaction pass of a child lent a row erased since reached the model"
        );
        assert!(
            !sent_text(&calls[1]).contains(ERASED_WORDS),
            "FIXTURE: the kept row's pass holds none of the erased words"
        );
    });
}

#[test]
fn a_compaction_rate_wait_resend_sends_nothing_once_a_lent_row_is_erased() {
    run_on_engine_stack("thing-child-erased-compaction-rate", || async {
        let model =
            FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(summary_reply)))).await;
        let dir = tempfile::tempdir().unwrap();
        let (server, _host) = served(dir.path(), &compaction_models(&model)).await;
        let vault = server.vault();
        let person = stored_person(vault);
        let erased = stored_claim(vault, person, ERASED_WORDS);
        let kept = stored_claim(vault, person, KEPT_WORDS);
        let both = thing_child_generation(vault, vec![erased, kept]);
        let alone = thing_child_generation(vault, vec![kept]);

        // Guard: a pass of a child lent the kept row, refused for its rate,
        // waits the limit out and is answered by its resend.
        model.push(rate_limited());
        child_pass(&server, &alone, sealed(vault, &[KEPT_WORDS]))
            .await
            .expect("FIXTURE: a rate-refused pass of a live row is answered after the wait");
        assert_eq!(
            compaction_calls(&model).len(),
            2,
            "FIXTURE: the wait's resend went out and was answered"
        );

        // The same refusal for a pass of a child lent both rows, held by the
        // model until the owner's erase has committed.
        model.push(Reply::HoldThen(Box::new(rate_limited())));
        let sent = child_pass(&server, &both, sealed(vault, &[ERASED_WORDS, KEPT_WORDS]));
        let erase = async {
            model.wait_holding().await;
            privacy_erase(vault, erased);
            model.release();
        };
        let (outcome, ()) = tokio::join!(sent, erase);
        assert!(
            outcome.is_err(),
            "a compaction pass whose lent row was erased in its rate wait was answered by its resend"
        );
        assert_eq!(
            compaction_calls(&model).len(),
            3,
            "the rate wait's resend of a pass of a child lent a row erased since reached the model"
        );
    });
}

#[test]
fn a_window_wait_withdrawn_by_an_erase_ends_unretried_and_asks_the_owner_nothing() {
    run_on_engine_stack("thing-child-erased-window-wait", || async {
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

        // Guard: a step of a child lent the kept row, refused for a spent
        // window, waits for its reset and is answered by its resend; an
        // answered call asks the owner nothing.
        model.push(window_spent());
        let clean = request(alone.model(), KEPT_WORDS);
        ended(alone.backend().generate_sourced(clean, &lease, None))
            .await
            .expect("FIXTURE: a window-refused step of a live row is answered after the reset");
        assert_eq!(
            model.seen().len(),
            2,
            "FIXTURE: the reset's resend went out and was answered"
        );
        assert_eq!(
            quota_questions(&vault),
            Vec::<String>::new(),
            "FIXTURE: an answered call keeps no quota question"
        );

        // The same refusal for a step of a child lent both rows, held by the
        // model until the owner's erase has committed.
        model.push(Reply::HoldThen(Box::new(window_spent())));
        let stale = request(both.model(), &format!("{ERASED_WORDS}\n{KEPT_WORDS}"));
        let sent = ended(both.backend().generate_sourced(stale, &lease, None));
        let erase = async {
            model.wait_holding().await;
            privacy_erase(&vault, erased);
            model.release();
        };
        let (outcome, ()) = tokio::join!(sent, erase);
        let error = outcome.expect_err("FIXTURE: a step whose lent row was erased is not answered");
        assert_eq!(
            model.seen().len(),
            3,
            "FIXTURE: nothing more reached the model after the erase"
        );
        assert_eq!(
            error,
            LlmError::from(FatalLlmError::InvalidRequest),
            "a step whose lent row was erased in its window wait ended as a refusal a step retries"
        );
        assert_eq!(
            quota_questions(&vault),
            Vec::<String>::new(),
            "a step whose lent row was erased in its window wait asked the owner about the window"
        );
    });
}
