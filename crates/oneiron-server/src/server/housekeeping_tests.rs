//! Done-means for host housekeeping: a running server, its lifecycle loop on a
//! short tick over a vault on a manual clock, retires what the engine said
//! would retire, with no call from the test but moving the clock.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::store::ports::ManualClock;
use oneiron::sync::WindowKey;
use oneiron::voice_identity::{
    VoiceAttributionEvidence, VoiceConsentBasis, VoiceConsentEventV1, VoiceConsentState,
    VoiceEmbeddingFamily, VoiceEmbeddingSpaceV1, VoiceEnrollmentOrigin, VoiceEnrollmentRequest,
    VoiceEnrollmentSampleV1, VoiceMatchPolicy, VoiceMatchRequest, VoicePrintPurpose,
    VoiceSegmentEmbeddingInput,
};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, DeleteReason, EdgeActorClass,
    EntityId, TimeRange, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};

use super::core::SyncServer;
use super::housekeeping::admit_every_pass;
use super::lifecycle::{LifecycleJobKind, LifecycleScheduler};
use crate::config::SyncServerConfig;

const T0: u64 = 1_800_000_000;
const TICK: Duration = Duration::from_millis(50);

struct Running {
    dir: tempfile::TempDir,
    clock: Arc<ManualClock>,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    lifecycle: Option<LifecycleScheduler>,
}

impl Running {
    /// A vault at `T0` on a manual clock, seeded by `seed` before any
    /// server holds it.
    fn seeded(seed: impl FnOnce(&Path, &Vault)) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let vault = open(dir.path(), &clock);
        seed(dir.path(), &vault);
        let server = Arc::new(
            SyncServer::new(Arc::clone(&vault), SyncServerConfig::default()).expect("server"),
        );
        Self {
            dir,
            clock,
            vault,
            server,
            lifecycle: None,
        }
    }

    /// Stops serving and closes the vault, as a reap does, then opens it
    /// again at `at`, as the supervisor's wake does.
    async fn reaped_then_woken_at(self, at: u64) -> Self {
        let Self {
            dir,
            clock,
            vault,
            server,
            lifecycle,
        } = self;
        if let Some(lifecycle) = lifecycle {
            lifecycle.stop().await;
        }
        drop(server);
        drop(vault);
        clock.set(at);
        let vault = open(dir.path(), &clock);
        let server = Arc::new(
            SyncServer::new(Arc::clone(&vault), SyncServerConfig::default()).expect("server"),
        );
        Self {
            dir,
            clock,
            vault,
            server,
            lifecycle: None,
        }
    }

    /// Starts the lifecycle loop, as `serve` does, on a short tick.
    fn serve(&mut self) {
        self.lifecycle = Some(
            self.server
                .spawn_lifecycle_scheduler_every(TICK, admit_every_pass()),
        );
    }

    /// Lets the first passes run, then waits until none is in flight, so a
    /// clock move lands between passes.
    async fn settle(&self) {
        tokio::time::sleep(TICK * 10).await;
        let key = self
            .server
            .lifecycle_job_key(LifecycleJobKind::Housekeeping);
        eventually("the pass in flight to end", || {
            self.server
                .lifecycle_in_flight
                .try_lock()
                .is_ok_and(|in_flight| !in_flight.contains(&key))
        })
        .await;
    }
}

fn open(dir: &Path, clock: &Arc<ManualClock>) -> Arc<Vault> {
    let mut config = oneiron::VaultConfig::device();
    config.store_clock = clock.bundle();
    Arc::new(Vault::open_owned(dir, config).expect("open vault"))
}

/// Waits, ticks passing, until `done` holds.
async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "{what} did not happen");
        tokio::time::sleep(TICK).await;
    }
}

/// The metadata header a stored record carries ahead of its body.
const RECORD_HEADER_LEN: usize = 25;

#[derive(serde::Deserialize)]
struct SweepTimes {
    sweep_queued_at: Option<u64>,
    sweep_complete_at: Option<u64>,
}

/// The two sweep times of a REDACTION_AUDIT receipt, read off its stored body.
fn sweep_times(vault: &Vault, receipt: &EntityId) -> SweepTimes {
    let raw = vault.get_raw(receipt).expect("read").expect("receipt");
    assert_eq!(raw[0], oneiron::registry::ENTITY_TYPE_REDACTION_AUDIT);
    rmp_serde::from_slice(&raw[RECORD_HEADER_LEN..]).expect("receipt body")
}

/// The server has served the erased entity's window: a sync client fetched it
/// and left, so the window stays registered, held by no one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_running_server_discharges_an_erasure_obligation_under_a_window_it_served() {
    let mut receipt = None;
    let mut running = Running::seeded(|_, vault| {
        let erased = EntityId::from_bytes([0xB7; 16]).expect("id");
        vault
            .put_entity(
                &erased,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: T0, end: T0 },
                T0,
                b"someone to forget",
            )
            .expect("seed");
        let deleted = vault
            .delete_entity_with_reason(&erased, DeleteReason::GdprDelete)
            .expect("erase");
        receipt = deleted.receipt_id;
    });
    let receipt = receipt.expect("a hard erase writes a receipt");
    let window = WindowKey::from_timestamp(T0);
    drop(
        running
            .server
            .serve_window(&window)
            .await
            .expect("serve the window"),
    );
    assert!(
        running
            .server
            .reassert_manager
            .loaded_keys()
            .contains(&window)
    );
    let queued = sweep_times(&running.vault, &receipt);
    assert!(queued.sweep_queued_at.is_some());
    assert_eq!(queued.sweep_complete_at, None);
    assert!(
        !running
            .vault
            .sync_queue_rows_with_prefix(b"h:")
            .expect("rows")
            .is_empty()
    );

    running.serve();
    eventually("the obligation to be discharged", || {
        sweep_times(&running.vault, &receipt)
            .sweep_complete_at
            .is_some()
    })
    .await;
    assert!(
        running
            .vault
            .sync_queue_rows_with_prefix(b"h:")
            .expect("rows")
            .is_empty()
    );
}

fn voice_space() -> VoiceEmbeddingSpaceV1 {
    VoiceEmbeddingSpaceV1::new(
        VoiceEmbeddingFamily::EcapaTdnn,
        "ecapa/voxceleb",
        "rev-1",
        16_000,
        4,
        "mono/16k/vad-v1",
    )
    .expect("space")
}

fn voice_match(session: &str, space: &VoiceEmbeddingSpaceV1) -> VoiceMatchRequest {
    VoiceMatchRequest {
        voice_session_ref: session.to_owned(),
        recording_id: "recording-1".to_owned(),
        space_id: space.space_id.clone(),
        segments: vec![VoiceSegmentEmbeddingInput {
            segment_id: "seg-1".to_owned(),
            diarization_label: "cluster-seg-1".to_owned(),
            start_ms: 0,
            end_ms: 1_000,
            space_id: space.space_id.clone(),
            vector: vec![1.0, 0.0, 0.0, 0.0],
        }],
        invite_attendee_refs: Vec::new(),
        policy: VoiceMatchPolicy::with_known_default(0.7),
        created_at: T0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_voice_print_past_its_retention_deadline_matches_no_one_and_a_running_server_deletes_it()
{
    let subject = EntityId::from_bytes([0x55; 16]).expect("id");
    let relationship = EntityId::from_bytes([0x56; 16]).expect("id");
    let space = voice_space();
    let mut running = Running::seeded(|_, vault| {
        vault
            .put_entity(
                &relationship,
                oneiron::registry::ENTITY_TYPE_RELATIONSHIP,
                TimeRange { start: 1, end: 1 },
                1,
                b"relationship",
            )
            .expect("seed");
        vault
            .record_voice_consent(&VoiceConsentEventV1 {
                event_id: "consent-1".to_owned(),
                subject_ref: subject,
                recorded_by_ref: EntityId::from_bytes([0x58; 16]).expect("id"),
                occurred_at: 100,
                purposes: vec![VoicePrintPurpose::MeetingAttribution],
                basis: VoiceConsentBasis::ConversationalNotice {
                    notice: "asked before recording".to_owned(),
                },
                state: VoiceConsentState::Granted,
            })
            .expect("consent");
        vault
            .enroll_voice_print(&VoiceEnrollmentRequest {
                subject_ref: subject,
                contact_ref: None,
                relationship_ref: Some(relationship),
                consent_event_ref: "consent-1".to_owned(),
                purpose: VoicePrintPurpose::MeetingAttribution,
                space: space.clone(),
                samples: vec![VoiceEnrollmentSampleV1 {
                    sample_id: "s-1".to_owned(),
                    source_ref: "session-solo-1".to_owned(),
                    language: "en".to_owned(),
                    origin: VoiceEnrollmentOrigin::AuthenticatedSoloSession {
                        session_ref: "session-solo-1".to_owned(),
                        speaker_count: 1,
                    },
                    duration_ms: 4_000,
                    source_sha256: "ab".repeat(32),
                    vector: vec![1.0, 0.0, 0.0, 0.0],
                }],
                requested_at: 200,
            })
            .expect("enroll");
    });
    let vault = Arc::clone(&running.vault);
    let matched = vault
        .resolve_voice_segments(&voice_match("call-while-retained", &space))
        .expect("match");
    assert_eq!(matched.segments[0].subject_ref, Some(subject));

    // The relationship ended long enough ago that the print is past its
    // deletion deadline: it recognizes no one, before any sweep runs.
    vault
        .end_voice_relationship(subject, relationship, T0 - 1_000, 100)
        .expect("end relationship");
    let overdue = vault
        .resolve_voice_segments(&voice_match("call-past-deadline", &space))
        .expect("match");
    assert_eq!(overdue.segments[0].subject_ref, None, "{overdue:?}");
    assert!(!matches!(
        overdue.segments[0].evidence,
        VoiceAttributionEvidence::EnrolledPrint { .. }
    ));

    running.serve();
    // Ending a relationship needs the print it ends: once the print is
    // deleted, there is none.
    eventually("the overdue print to be deleted", || {
        vault
            .end_voice_relationship(subject, relationship, T0 - 1_000, 100)
            .is_err_and(|error| error.kind() == oneiron::ErrorKind::EntityNotFound)
    })
    .await;
}

/// A T2 secret lease of 60 seconds whose value is written to a file under
/// `dir`. Returns the file.
fn lease_a_file(dir: &Path, vault: &Vault) -> PathBuf {
    use rmpv::Value;
    let target = dir
        .canonicalize()
        .expect("canonical tempdir")
        .join("workspace")
        .join(".secrets")
        .join("api.key");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
    // The value field is the engine's own, so the record goes through the
    // public body codec, as the manifest flow writes it.
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let body = Value::Map(vec![
        (Value::from("schema_version"), Value::from(1_u64)),
        (Value::from("name"), Value::from("local")),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(b"housekeeping-lease-fixture-value".to_vec()),
        ),
        (Value::from("status"), Value::from("active")),
        (Value::from("registered_at"), Value::from(T0)),
        (Value::from("rotated_at"), Value::Nil),
        (Value::from("rotation_generation"), Value::from(0_u64)),
        (
            Value::from("bindings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("effector"), Value::from("connector:test")),
                (Value::from("tier_ceiling"), Value::from(2_u64)),
                (
                    Value::from("scopes"),
                    Value::Array(vec![Value::from("read")]),
                ),
            ])]),
        ),
        (Value::from("manifest_ref"), Value::from("secrets.toml")),
        (
            Value::from("declared_paths"),
            Value::Array(vec![Value::from(target.to_str().expect("utf-8 target"))]),
        ),
        (
            Value::from("policy_floor_snapshot"),
            Value::Map(vec![
                (Value::from("portable"), band(0, 2)),
                (Value::from("device_bound"), band(0, 2)),
                (Value::from("cross_vault"), band(0, 0)),
                (Value::from("rotation_max_age_secs"), Value::Nil),
                (Value::from("env_bindings"), Value::Map(vec![])),
            ]),
        ),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("encode");
    let record = oneiron::secret_custody::decode_secret_custody_body(&bytes).expect("decode");
    vault.register_secret(record).expect("register secret");
    let lease = vault
        .materialize_secret_lease("local", "connector:test", 60)
        .expect("lease");
    vault
        .register_secret_local(&lease.lease.lease_id, &target, "project-alpha")
        .expect("register file");
    target
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_running_server_expires_a_secret_lease_and_removes_its_file() {
    let mut path = None;
    let mut running = Running::seeded(|dir, vault| path = Some(lease_a_file(dir, vault)));
    let path = path.expect("seeded");
    running.serve();
    running.settle().await;
    assert!(path.exists(), "the lease is live: its file stays");

    running.clock.set(T0 + 61);
    eventually("the expired lease's file to be removed", || !path.exists()).await;
}

/// A managed vault is reaped while a lease is outstanding. The wake ledger it
/// leaves the supervisor asks to be woken when the lease comes due; woken
/// then, the first pass expires the lease and removes its file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reaped_vault_wakes_when_its_lease_comes_due_and_expires_it() {
    let mut path = None;
    let mut running = Running::seeded(|dir, vault| path = Some(lease_a_file(dir, vault)));
    let path = path.expect("seeded");
    running.serve();
    running.settle().await;

    // The reap pulls the ledger, then the process exits.
    let ledger = crate::managed::WakeLedger::load(
        Arc::clone(&running.vault),
        "wake-test".to_owned(),
        running.dir.path().join("supervisor.sock"),
        &oneiron_vault_contract::Credentials {
            dek: [1; 32],
            token: [2; 32],
        },
    )
    .expect("ledger");
    let entries = ledger.export(&running.server).expect("export");
    drop(ledger);
    let wake = entries
        .iter()
        .find(|entry| entry.id == "housekeeping")
        .unwrap_or_else(|| panic!("no wake for the lease: {entries:?}"));
    assert_eq!(
        wake.at,
        oneiron_vault_contract::Schedule::Exact { at: T0 + 60 }
    );

    let mut running = running.reaped_then_woken_at(T0 + 60).await;
    assert!(path.exists(), "nothing ran while the vault was down");
    running.serve();
    eventually("the lease's file to be removed", || !path.exists()).await;
    assert_eq!(
        running.vault.expire_secret_leases(T0 + 60).expect("sweep"),
        0,
        "the lease is already expired"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_running_server_demotes_a_critical_confirm_past_its_window() {
    let claim = EntityId::from_bytes([0x81; 16]).expect("id");
    let mut running = Running::seeded(|_, vault| {
        let actor = EntityId::from_bytes([0x20; 16]).expect("id");
        let subject = EntityId::from_bytes([0x21; 16]).expect("id");
        for id in [actor, subject] {
            vault
                .put_entity(
                    &id,
                    oneiron::registry::ENTITY_TYPE_PERSON,
                    TimeRange { start: T0, end: T0 },
                    T0,
                    b"person",
                )
                .expect("seed");
        }
        let candidate = ClaimCandidate::new(
            "health.allergy",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("peanuts"),
            1.0,
        )
        .with_scope(rmpv::Value::Map(vec![(
            rmpv::Value::from("sensitivity"),
            rmpv::Value::from("public"),
        )]));
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(rmpv::Value::from("housekeeping test")).expect("provenance"),
            ClaimApprovalStatus::Auto,
        );
        vault
            .batch()
            .claim_candidate(
                &claim,
                candidate,
                &envelope,
                TimeRange { start: T0, end: T0 },
                T0,
            )
            .commit()
            .expect("critical write");
    });
    let approval = |vault: &Vault| {
        vault
            .get_claim(&claim)
            .expect("read")
            .expect("claim")
            .approval
    };
    assert_eq!(approval(&running.vault), ClaimApprovalStatus::Auto);

    running.serve();
    running.settle().await;
    assert_eq!(
        approval(&running.vault),
        ClaimApprovalStatus::Auto,
        "inside its window the confirm stays open"
    );

    running.clock.set(T0 + 301);
    eventually("the confirm past its window to be demoted", || {
        approval(&running.vault) == ClaimApprovalStatus::Proposed
    })
    .await;
}

/// The lifecycle tick finishes the dependent walks main's #1471 left past
/// their first batch before it starts the housekeeping pass, on every tick
/// (Engine merge check on #1456).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tick_finishes_dependent_walks_before_it_starts_the_pass() {
    let mut running = Running::seeded(|_, _| {});
    let steps = |running: &Running| {
        running
            .server
            .housekeeping_passes
            .tick_steps
            .lock()
            .expect("steps")
            .clone()
    };

    running.serve();
    eventually("two ticks", || steps(&running).len() >= 4).await;

    let steps = steps(&running);
    assert!(
        steps
            .chunks_exact(2)
            .all(|tick| tick == ["dependent walks", "housekeeping pass"]),
        "{steps:?}"
    );
}
