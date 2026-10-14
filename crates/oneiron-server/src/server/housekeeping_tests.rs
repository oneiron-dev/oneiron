//! Done-means for host housekeeping: a running server, its lifecycle loop on a
//! short tick over a vault on a manual clock, retires what the engine said
//! would retire, with no call from the test but moving the clock.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::store::ports::ManualClock;
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
use tokio::task::JoinHandle;

use super::core::SyncServer;
use super::housekeeping::admit_every_pass;
use super::lifecycle::LifecycleJobKind;
use crate::config::SyncServerConfig;

const T0: u64 = 1_800_000_000;
const TICK: Duration = Duration::from_millis(50);

struct Running {
    _dir: tempfile::TempDir,
    clock: Arc<ManualClock>,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    lifecycle: Option<JoinHandle<()>>,
}

impl Running {
    /// A vault at `T0` on a manual clock, seeded by `seed` before any
    /// server holds it.
    fn seeded(seed: impl FnOnce(&Path, &Vault)) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let mut config = oneiron::VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Arc::new(Vault::open_owned(dir.path(), config).expect("open vault"));
        seed(dir.path(), &vault);
        let server = Arc::new(
            SyncServer::new(Arc::clone(&vault), SyncServerConfig::default()).expect("server"),
        );
        Self {
            _dir: dir,
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

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(lifecycle) = self.lifecycle.take() {
            lifecycle.abort();
        }
    }
}

/// Waits, ticks passing, until `done` holds.
async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "{what} did not happen");
        tokio::time::sleep(TICK).await;
    }
}

#[derive(serde::Deserialize)]
struct SweepTimes {
    sweep_queued_at: Option<u64>,
    sweep_complete_at: Option<u64>,
}

/// The two sweep times of a REDACTION_AUDIT receipt, read off its stored body.
fn sweep_times(vault: &Vault, receipt: &EntityId) -> SweepTimes {
    let raw = vault.get_raw(receipt).expect("read").expect("receipt");
    assert_eq!(raw[0], oneiron::registry::ENTITY_TYPE_REDACTION_AUDIT);
    rmp_serde::from_slice(&raw[oneiron::batch::ENTITY_METADATA_HEADER_LEN..]).expect("receipt body")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_running_server_discharges_an_erasure_obligation() {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_running_server_expires_a_secret_lease_and_removes_its_file() {
    use oneiron::secret_custody::{
        CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding,
        SecretCustodyFloor, SecretCustodyRecord, SecretCustodyStatus,
    };
    let mut path = None;
    let mut running = Running::seeded(|dir, vault| {
        let target = dir
            .canonicalize()
            .expect("canonical tempdir")
            .join("workspace")
            .join(".secrets")
            .join("api.key");
        std::fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
        vault
            .register_secret(SecretCustodyRecord {
                schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
                name: "local".to_owned(),
                class: CustodyClass::CustodyPortable,
                device_only: false,
                value_bytes: b"housekeeping-lease-fixture-value".to_vec(),
                status: SecretCustodyStatus::Active,
                registered_at: T0,
                rotated_at: None,
                rotation_generation: 0,
                bindings: vec![SecretBinding {
                    effector: "connector:test".to_owned(),
                    tier_ceiling: CustodyTier::T2LocalRegistered,
                    scopes: vec!["read".to_owned()],
                }],
                manifest_ref: "secrets.toml".to_owned(),
                declared_paths: vec![target.to_string_lossy().into_owned()],
                policy_floor_snapshot: SecretCustodyFloor::default(),
            })
            .expect("register secret");
        let lease = vault
            .materialize_secret_lease("local", "connector:test", 60)
            .expect("lease");
        vault
            .register_secret_local(&lease.lease.lease_id, &target, "project-alpha")
            .expect("register file");
        path = Some(target);
    });
    let path = path.expect("seeded");
    running.serve();
    running.settle().await;
    assert!(path.exists(), "the lease is live: its file stays");

    running.clock.set(T0 + 61);
    eventually("the expired lease's file to be removed", || !path.exists()).await;
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
