//! The host's commitment reminder wording worker on tries that cannot
//! succeed (FIX REMINDER-WORDING-BAD-PAYLOAD-RETRIES and the reminder half
//! of FIX ATTEMPT-WORKER-FLAT-RETRY-BACKOFF).
//!
//! A payload that does not decode ends its attempt: its bytes never change,
//! so a retry could only fail the same way, and the send reads the fixed
//! wording while none is filed. A try that fails for a reason that does not
//! clear is tried again after `models.workflows.retry_backoff_secs` times the
//! tries so far, so the second retry waits twice as long as the first.
//!
//! No model is asked: both faults stop the try before its model call. The
//! host is attached to a server as `model_step_health_rest` attaches it,
//! with the Dreamer and the workflow pump off. Its generative seat is the
//! scripted local fake, which only makes the worker run.
//!
//! Red on main: the undecodable payload is retried (a failed row
//! `wording_payload_invalid` and a successor), and every retry waits the same
//! `retry_backoff_secs`.
//!
//! `cargo test --locked -p oneiron-server --test
//! commitment_reminder_wording_retry`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, EnqueueAttempt, EnqueueOutcome,
};
use oneiron::commitment_wake::{
    COMMITMENT_REMINDER_CONTENT_PREFIX, COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND,
    CommitmentReminderVoice, CommitmentReminderWordingPayload,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::server::SyncServer;

use crate::engine_stack::run_on_engine_stack;
use crate::fake_llm::FakeLlm;

/// `models.workflows.retry_backoff_secs` for these hosts.
const BACKOFF_SECS: u64 = 3;
/// How long the worker gets to take up a queued try.
const TAKE_UP: Duration = Duration::from_secs(60);

struct Fixture {
    vault: Arc<Vault>,
    host: AiHost,
    _server: SyncServer,
    // Answers nothing: no try reaches its model call.
    _model: FakeLlm,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

/// A device vault served with its AI host attached, whose generative seat
/// is the scripted fake.
async fn fixture() -> Fixture {
    let model = FakeLlm::start(Vec::new(), None).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("a vault"));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("reminder-wording-retry".into()),
            ..Default::default()
        },
    )
    .expect("the server");
    let models = ModelsConfig::from_toml(&models_text(&model.base_url), None).expect("models");
    let (server, host) = AiHost::attach(server, Some(&models)).await;
    Fixture {
        vault,
        host,
        _server: server,
        _model: model,
        _dir: dir,
    }
}

fn models_text(base_url: &str) -> String {
    format!(
        "[providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         revision = \"rev-a\"\ntimeout_secs = 5\n\
         [roles.generative_reasoner]\nrungs = [{{ model = \"local:reasoner\" }}]\n\
         [dreamer]\nenabled = false\n\
         [workflows]\nenabled = false\nretry_backoff_secs = {BACKOFF_SECS}\n"
    )
}

impl Fixture {
    /// Queues one wording try with `payload` as its bytes.
    fn queue(&self, payload: Vec<u8>) -> AttemptRecord {
        let outcome = AttemptQueue::new(&self.vault)
            .enqueue(EnqueueAttempt {
                kind: COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND.to_owned(),
                payload,
                dedupe_key: None,
                run_id: None,
                now: self.vault.now_recorded_at(),
            })
            .expect("queue the wording");
        let EnqueueOutcome::Enqueued(attempt) = outcome else {
            panic!("a fresh wording try is queued: {outcome:?}");
        };
        attempt
    }

    /// A stored claim that is not a commitment: a reminder ref naming it
    /// fails its source read on every try.
    fn claim_that_is_not_a_commitment(&self) -> EntityId {
        let subject = EntityId::now();
        self.vault
            .put_entity(
                &subject,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"reminder wording retry subject",
            )
            .expect("the subject");
        let body = ClaimBody::new(
            "test.not_a_commitment",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("a stored claim"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("the claim body");
        let id = EntityId::now();
        self.vault
            .put_claim(&id, &body, TimeRange { start: 2, end: 2 }, 2)
            .expect("the claim");
        id
    }

    /// Every wording try: each try is a row of its own.
    fn attempts(&self) -> Vec<AttemptRecord> {
        AttemptQueue::new(&self.vault)
            .list()
            .expect("the attempt queue")
            .into_iter()
            .filter(|attempt| attempt.kind == COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND)
            .collect()
    }

    fn attempt(&self, id: AttemptId) -> Option<AttemptRecord> {
        self.attempts().into_iter().find(|attempt| attempt.id == id)
    }

    /// The try that retried `id`, once it exists.
    fn retry_of(&self, id: AttemptId) -> Option<AttemptRecord> {
        self.attempts()
            .into_iter()
            .find(|attempt| attempt.retry_of == Some(id))
    }
}

/// How long a retry waits: its scheduled instant past the instant it was
/// minted at.
fn wait_secs(retry: &AttemptRecord) -> u64 {
    retry
        .scheduled_at
        .expect("a retry is scheduled")
        .saturating_sub(retry.created_at)
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
fn an_undecodable_payload_completes_its_attempt_and_is_not_tried_again() {
    run_on_engine_stack("reminder-wording-bad-payload", || async {
        let fx = fixture().await;
        let attempt = fx.queue(b"not a wording payload".to_vec());
        assert!(
            eventually(TAKE_UP, || fx
                .attempt(attempt.id)
                .is_some_and(|row| row.state.is_terminal()))
            .await,
            "the host never settled the try; attempts {:?}",
            fx.attempts()
        );
        // Longer than one retry wait: a successor would have been minted.
        tokio::time::sleep(Duration::from_secs(BACKOFF_SECS + 1)).await;
        let attempts = fx.attempts();
        assert_eq!(
            fx.attempt(attempt.id).map(|row| row.state),
            Some(AttemptState::Completed),
            "an undecodable payload ends its attempt: {attempts:?}"
        );
        assert_eq!(attempts.len(), 1, "no retry was minted: {attempts:?}");
        fx.host.shutdown().await;
    });
}

#[test]
fn a_try_that_keeps_failing_waits_longer_each_time() {
    run_on_engine_stack("reminder-wording-retry-spacing", || async {
        let fx = fixture().await;
        let reminder = format!(
            "{COMMITMENT_REMINDER_CONTENT_PREFIX}{}:due:4102444800",
            fx.claim_that_is_not_a_commitment().to_hex()
        );
        let payload = serde_json::to_vec(&CommitmentReminderWordingPayload {
            content_ref: reminder,
            voice: CommitmentReminderVoice { persona_ref: None },
        })
        .expect("the payload");
        let first = fx.queue(payload);
        let mut second = None;
        assert!(
            eventually(TAKE_UP, || {
                second = fx.retry_of(first.id);
                second.is_some()
            })
            .await,
            "the failed try was not retried; attempts {:?}",
            fx.attempts()
        );
        let second = second.expect("the first retry");
        let mut third = None;
        assert!(
            eventually(TAKE_UP, || {
                third = fx.retry_of(second.id);
                third.is_some()
            })
            .await,
            "the retry was not retried; attempts {:?}",
            fx.attempts()
        );
        let third = third.expect("the second retry");
        let attempts = fx.attempts();
        for failed in [first.id, second.id] {
            let row = fx.attempt(failed).expect("a failed try stays readable");
            assert_eq!(row.state, AttemptState::Failed, "{attempts:?}");
            assert_eq!(
                row.last_error.as_deref(),
                Some("wording_source_read_failed"),
                "{attempts:?}"
            );
        }
        // The retry's own instant is recorded in the write that mints it,
        // at most a second after the worker read the clock.
        assert!(
            wait_secs(&second) <= BACKOFF_SECS,
            "the first retry waits one backoff: {attempts:?}"
        );
        assert!(
            wait_secs(&third) >= 2 * BACKOFF_SECS - 1,
            "the second retry waits two backoffs, not {} s: {attempts:?}",
            wait_secs(&third)
        );
        fx.host.shutdown().await;
    });
}
