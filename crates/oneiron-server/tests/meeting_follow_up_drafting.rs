//! The host's meeting follow-up drafting worker (CAL-08; Engine RULING
//! CAL-08-FOLLOWUP-APPROVAL = A, Sun 15 Nov 12:04): a landed transcript's
//! queued drafting attempt is claimed by the running host, its model is
//! asked once, and the owner's promised follow-up lands as a draft in the
//! owner's inbox. Nothing is sent.
//!
//! The model is the scripted local fake (`support/fake_llm.rs`); the host is
//! started as a standalone host starts (`AiHost::start`), with the Dreamer and
//! the workflow pump off, so only this worker takes up the queue.
//!
//! Red on PR-E2a's head: no worker claims the attempt, and the
//! `meeting_follow_up_prompt` key is not a `[models.dreamer.wording]` key
//! there, so each test fails.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! meeting_follow_up_drafting`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
use oneiron::calendar::follow_up::{
    MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND, PREDICATE_MEETING_FOLLOW_UP,
};
use oneiron::calendar::transcript::{
    TranscriptFileDropRequest, TranscriptIngestOutcome, ingest_file_drop_transcript,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::models::ModelsConfig;
use rmpv::Value;

use crate::engine_stack::run_on_engine_stack;
use crate::fake_llm::{FakeLlm, Reply};

const TRANSCRIPT: &str = "Owen: I will send you the slides tomorrow\nYuki: Thanks, that helps";
const WORDS: &str = "Hi Yuki, here are the slides from today's meeting.";
/// The host's own drafting instruction (`meeting_follow_up_prompt`).
const INSTRUCTION: &str =
    "Host wording: list the follow-ups the owner promised, in the reply contract.";
/// How long the worker gets to take up a queued attempt.
const TAKE_UP: Duration = Duration::from_secs(60);

struct Fixture {
    vault: Arc<Vault>,
    owner: EntityId,
    host: AiHost,
    model: FakeLlm,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

/// A device vault this process owns, its engine MACHINE writers provisioned
/// and this install's signing keys loaded (the Dreamer signs the drafts),
/// and a host started on it whose generative seat is the scripted fake.
async fn fixture(script: Vec<Reply>, fallback: Option<Reply>) -> Fixture {
    let model = FakeLlm::start(script, fallback).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        Arc::new(Vault::open_owned(dir.path(), VaultConfig::device()).expect("an owned vault"));
    oneiron::test_support::provision_engine_machines(&vault);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    let models =
        ModelsConfig::from_toml(&models_text(&model.base_url), None).expect("models config");
    let host = AiHost::start(Arc::clone(&vault), Some(&models), true).await;
    Fixture {
        vault,
        owner,
        host,
        model,
        _dir: dir,
    }
}

fn models_text(base_url: &str) -> String {
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n\
         [dreamer.wording]\nmeeting_follow_up_prompt = \"{INSTRUCTION}\"\n\
         [workflows]\nenabled = false\nretry_backoff_secs = 1\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n"
    )
}

impl Fixture {
    /// The owner's name, as a names-class claim about the owner's PERSON.
    fn name_the_owner(&self, name: &str) {
        let now = self.vault.now_recorded_at();
        self.vault
            .put_claim(
                &EntityId::now(),
                &ClaimBody::new(
                    "person.name",
                    ClaimSubject::Entity(self.owner),
                    Value::from(name),
                    1.0,
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                )
                .expect("the name claim"),
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .expect("the owner's name");
    }

    /// A PERSON the vault knows by `name`.
    fn person(&self, name: &str) -> EntityId {
        let id = EntityId::now();
        let now = self.vault.now_recorded_at();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &Value::Map(vec![(Value::from("name"), Value::from(name))]),
        )
        .expect("encode the person body");
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .expect("put the person");
        id
    }

    /// One file-drop meeting transcript: its landing queues the drafting.
    fn ingest(&self, text: &str) {
        let outcome = ingest_file_drop_transcript(
            &self.vault,
            TranscriptFileDropRequest {
                source_blob_ref: EntityId::now(),
                decoded_text: text,
                arrived_at_ms: self.vault.now_recorded_at() * 1_000,
            },
        )
        .expect("the transcript lands");
        assert!(
            matches!(outcome, TranscriptIngestOutcome::Session { .. }),
            "a speaker transcript mints a session"
        );
    }

    /// Every drafting attempt row: each try is a row of its own.
    fn attempts(&self) -> Vec<AttemptRecord> {
        AttemptQueue::new(&self.vault)
            .list()
            .expect("the attempt queue")
            .into_iter()
            .filter(|attempt| attempt.kind == MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND)
            .collect()
    }

    /// Whether the drafting is done: a completed try and no try left.
    fn drafting_completed(&self) -> bool {
        let attempts = self.attempts();
        attempts
            .iter()
            .any(|attempt| attempt.state == AttemptState::Completed)
            && attempts.iter().all(|attempt| {
                matches!(
                    attempt.state,
                    AttemptState::Completed | AttemptState::Failed
                )
            })
    }

    /// The follow-up drafts about `about`.
    fn drafts(&self, about: EntityId) -> Vec<ClaimBody> {
        self.vault
            .claims_for_subject(&about)
            .expect("claims about the person")
            .into_iter()
            .filter_map(|id| self.vault.get_claim(&id).expect("get claim"))
            .filter(|body| body.predicate == PREDICATE_MEETING_FOLLOW_UP)
            .collect()
    }

    /// The messages of each model request that asked for follow-ups (it
    /// carries the host's drafting instruction), as JSON text.
    fn asked(&self) -> Vec<String> {
        self.model
            .seen()
            .iter()
            .map(|call| call.body["messages"].to_string())
            .filter(|messages| messages.contains(INSTRUCTION))
            .collect()
    }
}

/// A reply in the engine's contract: one follow-up to P1, citing both TURNs.
fn contract_reply() -> Reply {
    Reply::text(
        serde_json::json!({
            "follow_ups": [{ "recipient": "P1", "text": WORDS, "evidence_turn_refs": ["T1", "T2"] }]
        })
        .to_string(),
    )
}

async fn eventually(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    condition()
}

#[test]
fn a_landed_promise_becomes_one_owner_draft_after_one_model_call() {
    run_on_engine_stack("follow-up-drafted", || async {
        let fx = fixture(vec![contract_reply()], None).await;
        fx.name_the_owner("Owen");
        let yuki = fx.person("Yuki");
        let sends = fx.vault.standalone_outbound_intent_count().unwrap();
        fx.ingest(TRANSCRIPT);

        assert!(
            eventually(TAKE_UP, || fx.drafting_completed()).await,
            "the host never completed the drafting; attempts {:?}",
            fx.attempts()
        );
        let drafts = fx.drafts(yuki);
        assert_eq!(drafts.len(), 1, "one draft, about its recipient");
        assert_eq!(drafts[0].subject, ClaimSubject::Entity(yuki));
        assert_eq!(
            drafts[0].approval,
            ClaimApprovalStatus::Proposed,
            "the draft waits for the owner"
        );
        assert_eq!(drafts[0].source, Some(ClaimSource::Imported));
        assert_eq!(
            fx.vault.standalone_outbound_intent_count().unwrap(),
            sends,
            "a draft is never a send"
        );

        let asked = fx.asked();
        assert_eq!(
            asked.len(),
            1,
            "one model call, in the host's wording: {} calls",
            fx.model.seen().len()
        );
        let asked = &asked[0];
        assert!(
            asked.contains("[T1] Owen: I will send you the slides tomorrow"),
            "the labelled transcript is the user message: {asked}"
        );
        assert!(asked.contains("P1 \\\"Yuki\\\""), "Yuki is listed: {asked}");
        fx.host.shutdown().await;
    });
}

#[test]
fn a_reply_outside_the_contract_completes_the_attempt_and_is_not_asked_again() {
    run_on_engine_stack("follow-up-poison", || async {
        // A second ask would draft: the fallback reply is in the contract.
        let fx = fixture(
            vec![Reply::text("There are no follow-ups in this meeting.")],
            Some(contract_reply()),
        )
        .await;
        fx.name_the_owner("Owen");
        let yuki = fx.person("Yuki");
        fx.ingest(TRANSCRIPT);

        assert!(
            eventually(TAKE_UP, || fx.drafting_completed()).await,
            "the refused reply did not complete the drafting; attempts {:?}",
            fx.attempts()
        );
        // Several retry backoffs (1 s each) pass: no try is left to run.
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(fx.asked().len(), 1, "the model is asked once");
        assert_eq!(fx.attempts().len(), 1, "no retry row was minted");
        assert!(fx.drafts(yuki).is_empty(), "a refused reply drafts nothing");
        fx.host.shutdown().await;
    });
}

#[test]
fn a_model_fault_is_tried_again_and_the_next_try_drafts() {
    run_on_engine_stack("follow-up-fault", || async {
        let fx = fixture(vec![Reply::Status(500), contract_reply()], None).await;
        fx.name_the_owner("Owen");
        let yuki = fx.person("Yuki");
        fx.ingest(TRANSCRIPT);

        assert!(
            eventually(TAKE_UP, || fx.drafting_completed()
                && !fx.drafts(yuki).is_empty())
            .await,
            "the faulted drafting never drafted; attempts {:?}",
            fx.attempts()
        );
        assert_eq!(fx.asked().len(), 2, "one call per try");
        let attempts = fx.attempts();
        let failed: Vec<&AttemptRecord> = attempts
            .iter()
            .filter(|attempt| attempt.last_error.as_deref() == Some("follow_up_model_call_failed"))
            .collect();
        assert_eq!(failed.len(), 1, "the faulted try is kept: {attempts:?}");
        assert!(
            attempts
                .iter()
                .any(|attempt| attempt.retry_of == Some(failed[0].id)
                    && attempt.state == AttemptState::Completed),
            "a fresh try retried it and completed: {attempts:?}"
        );
        assert_eq!(fx.drafts(yuki).len(), 1);
        fx.host.shutdown().await;
    });
}
