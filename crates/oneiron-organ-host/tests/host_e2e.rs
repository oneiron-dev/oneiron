//! The host against a real organ process (the probe), over real vault blobs.
//! Each test pins a substrate rule of the design page: inputs cross as
//! sealed regions the engine hashed, deadlines and revoked grants stop a
//! hostile organ, crashes back off then quarantine, and the grant refuses
//! what it does not name.
#![cfg(unix)]

use std::thread;
use std::time::{Duration, Instant};

use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::SecretSight;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_organ_host::{
    CallClass, HostConfig, HostError, OrganCall, OrganHost, OrganInput, OrganSpec, OrganState,
    SightedInput, Unavailable,
};
use oneiron_organ_protocol::Value;

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-organ-probe");
const BIN: &str = "application/octet-stream";

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 256 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    (dir, vault)
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn put_blob(vault: &Vault, bytes: &[u8], media_type: &str) -> OrganInput {
    let actor = EntityId::now();
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"uploader")
        .expect("actor");
    let artifact = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new("blob", media_type),
            at(1),
            1,
        )
        .expect("artifact");
    let version = vault
        .append_blob_artifact_version(
            &artifact,
            bytes,
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(actor, EdgeActorClass::Human),
            at(2),
            2,
        )
        .expect("version");
    OrganInput {
        artifact,
        version: version.version,
    }
}

fn host() -> OrganHost {
    let host = OrganHost::new(HostConfig::default());
    let mut spec = OrganSpec::first_party("probe", PROBE);
    spec.verbs = [
        "organ.touch",
        "organ.echo",
        "probe.sleep",
        "probe.crash",
        "probe.fork",
        "probe.outputs",
    ]
    .map(String::from)
    .into();
    spec.media_types = vec![BIN.to_owned()];
    host.install(spec);
    host
}

fn call(verb: &str, args: Value, inputs: Vec<OrganInput>, grant: &str) -> OrganCall {
    OrganCall {
        organ: "probe".into(),
        verb: verb.into(),
        schema: 1,
        args,
        body: None,
        // The test's vault holds no secret marks, so every sight reads the stored bytes.
        inputs: inputs
            .into_iter()
            .map(|input| SightedInput {
                input,
                sight: SecretSight::Owner,
            })
            .collect(),
        class: CallClass::Agent,
        deadline: Duration::from_secs(10),
        grant: grant.into(),
    }
}

fn sleep_args(ms: u64, obey_cancel: bool) -> Value {
    Value::Map(vec![
        ("ms".into(), ms.into()),
        ("obey_cancel".into(), obey_cancel.into()),
    ])
}

fn report_u64(report: &Value, key: &str) -> Option<u64> {
    report
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))?
        .1
        .as_u64()
}

#[test]
fn a_missed_deadline_cancels_then_kills_and_the_next_call_starts_clean() {
    let (_dir, vault) = vault();
    let host = host();
    let mut hostile = call("probe.sleep", sleep_args(60_000, false), Vec::new(), "g");
    hostile.deadline = Duration::from_millis(300);
    let started = Instant::now();
    let err = host.call(&vault, hostile).expect_err("deadline");
    assert!(matches!(err, HostError::DeadlineExceeded), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "killed promptly"
    );
    let echoed = host
        .call(&vault, call("organ.echo", "after".into(), Vec::new(), "g"))
        .expect("a fresh process answers");
    assert_eq!(echoed.report, Value::from("after"));
    let status = host.status("probe").expect("installed");
    assert_eq!(status.spawns, 2);
    assert_eq!(status.recent_crashes, 0, "a deadline kill is not a crash");
}

#[test]
fn a_deadline_past_the_clock_is_answered_not_a_panic() {
    // Review repro (#1370): `Instant + Duration::MAX` panicked before
    // admission.
    let (_dir, vault) = vault();
    let host = host();
    let mut patient = call("organ.echo", "patient".into(), Vec::new(), "g");
    patient.deadline = Duration::MAX;
    let echoed = host.call(&vault, patient).expect("a far deadline answers");
    assert_eq!(echoed.report, Value::from("patient"));
}

#[test]
fn a_revoked_grant_stops_a_hostile_call_mid_flight() {
    let (_dir, vault) = vault();
    let host = host();
    host.warm("probe").expect("warm");
    let started = Instant::now();
    let outcome = thread::scope(|scope| {
        let running = scope.spawn(|| {
            host.call(
                &vault,
                call(
                    "probe.sleep",
                    sleep_args(60_000, false),
                    Vec::new(),
                    "doomed",
                ),
            )
        });
        thread::sleep(Duration::from_millis(300));
        host.revoke_grant("doomed");
        running.join().expect("join")
    });
    assert!(matches!(outcome, Err(HostError::Revoked)), "{outcome:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    let again = host.call(&vault, call("organ.echo", 1.into(), Vec::new(), "doomed"));
    assert!(matches!(again, Err(HostError::Revoked)));
    host.call(&vault, call("organ.echo", 1.into(), Vec::new(), "other"))
        .expect("other grants still run");
}

#[test]
fn crashes_back_off_then_quarantine() {
    let (_dir, vault) = vault();
    let host = host();
    let mut crashes = 0;
    let deadline = Instant::now() + Duration::from_secs(60);
    while crashes < 5 && Instant::now() < deadline {
        match host.call(&vault, call("probe.crash", Value::Nil, Vec::new(), "g")) {
            Err(HostError::Crashed(_)) => crashes += 1,
            Err(HostError::Backoff { retry_after, .. }) => thread::sleep(retry_after),
            other => panic!("unexpected {other:?}"),
        }
    }
    let status = host.status("probe").expect("installed");
    assert_eq!(
        status.state,
        OrganState::Unavailable(Unavailable::Quarantined),
    );
    let refused = host.call(&vault, call("organ.echo", 1.into(), Vec::new(), "g"));
    assert!(
        matches!(refused, Err(HostError::Unavailable { .. })),
        "{refused:?}"
    );
}

#[test]
fn the_grant_refuses_what_it_does_not_name() {
    let (_dir, vault) = vault();
    let host = host();
    let png = put_blob(&vault, b"not granted", "image/png");
    let refused = host.call(&vault, call("organ.touch", Value::Nil, vec![png], "g"));
    assert!(
        matches!(refused, Err(HostError::MediaTypeNotGranted(_))),
        "{refused:?}"
    );
    let mut unnamed = call("organ.echo", 1.into(), Vec::new(), "g");
    unnamed.verb = "probe.unnamed".into();
    let refused = host.call(&vault, unnamed);
    assert!(
        matches!(refused, Err(HostError::UnknownVerb { .. })),
        "{refused:?}"
    );
    assert_eq!(
        host.status("probe").expect("installed").spawns,
        0,
        "refused before any process started",
    );
}

#[test]
fn a_version_outside_the_pin_is_refused_at_handshake() {
    let (_dir, vault) = vault();
    let host = OrganHost::new(HostConfig::default());
    let mut spec = OrganSpec::first_party("probe", PROBE);
    spec.verbs = vec!["organ.echo".into()];
    spec.version_pin = Some("0.0.0-elsewhere".into());
    host.install(spec);
    let refused = host.call(&vault, call("organ.echo", 1.into(), Vec::new(), "g"));
    assert!(
        matches!(refused, Err(HostError::Handshake(_))),
        "{refused:?}"
    );
    assert!(matches!(
        host.status("probe").expect("installed").state,
        OrganState::Unavailable(Unavailable::Incompatible(_)),
    ));
}

fn rogue(mode: &str, config: HostConfig) -> OrganHost {
    let host = OrganHost::new(config);
    let mut spec = OrganSpec::first_party("probe", PROBE);
    spec.args = vec![mode.into()];
    spec.verbs = vec!["organ.echo".into()];
    host.install(spec);
    host
}

#[test]
fn an_organ_that_stops_reading_cannot_hold_a_call_past_its_deadline() {
    // The call frame is far larger than the socket buffer, so the send
    // itself blocks: the deadline must bound the write, not just the reply.
    // On macOS, MSG_DONTWAIT does not stop a send that waits for room, so
    // this call hung there until the socket was made nonblocking.
    let (_dir, vault) = vault();
    let config = HostConfig::default();
    let grace = config.cancel_grace;
    let host = rogue("--deaf", config);
    host.warm("probe").expect("warm");
    // A call cut off part way stops the organ. One late before its first
    // byte (a host too loaded to send for a whole second) leaves it warm
    // and in step, which is right too: call again.
    for _ in 0..3 {
        let mut stuck = call(
            "organ.echo",
            "x".repeat(8 * 1024 * 1024).into(),
            Vec::new(),
            "g",
        );
        stuck.deadline = Duration::from_secs(1);
        let bound = stuck.deadline + grace;
        let started = Instant::now();
        let err = host.call(&vault, stuck).expect_err("deadline");
        let took = started.elapsed();
        assert!(matches!(err, HostError::DeadlineExceeded), "{err:?}");
        // Within its deadline and the grace, and a margin for a loaded host.
        assert!(took < bound + Duration::from_secs(1), "{took:?}");
        let status = host.status("probe").expect("installed");
        assert_eq!(status.recent_crashes, 0);
        if !matches!(status.state, OrganState::Warm) {
            assert!(matches!(status.state, OrganState::Cold), "{status:?}");
            break;
        }
    }
}

#[test]
fn a_dripped_handshake_fails_at_its_deadline() {
    // One byte every 100 ms: each read makes progress, so only a deadline
    // over the whole handshake stops it.
    let (_dir, vault) = vault();
    let config = HostConfig {
        handshake_timeout: Duration::from_millis(500),
        ..HostConfig::default()
    };
    let host = rogue("--drip", config);
    // A caller whose own deadline ends the start first is the one that is
    // late: the organ is not charged a crash.
    let mut hurried = call("organ.echo", 1.into(), Vec::new(), "g");
    hurried.deadline = Duration::from_millis(200);
    let err = host.call(&vault, hurried).expect_err("caller deadline");
    assert!(matches!(err, HostError::DeadlineExceeded), "{err:?}");
    assert_eq!(host.status("probe").expect("installed").recent_crashes, 0);
    let started = Instant::now();
    let err = host
        .call(&vault, call("organ.echo", 1.into(), Vec::new(), "g"))
        .expect_err("start");
    assert!(matches!(err, HostError::StartFailed { .. }), "{err:?}");
    let status = host.status("probe").expect("installed");
    assert_eq!(
        status.recent_crashes, 1,
        "a stalled start backs off as a crash, not a refusal"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_call_late_for_the_writer_harms_no_other_call() {
    // A paused organ (stopped by a signal) lets one large call fill the
    // socket. A second call whose deadline passes while it waits for the
    // writer sent nothing: it fails alone, and the large call lands.
    let (_dir, vault) = vault();
    let host = host();
    host.call(&vault, call("organ.echo", 1.into(), Vec::new(), "g"))
        .expect("warm");
    let pid = host.status("probe").expect("installed").pid.expect("warm");
    let pid = i32::try_from(pid).expect("pid");
    // SAFETY: kill(2) on the organ this test started.
    unsafe {
        libc::kill(pid, libc::SIGSTOP);
    }
    let resume = thread::spawn(move || {
        thread::sleep(Duration::from_millis(400));
        // SAFETY: as above.
        unsafe {
            libc::kill(pid, libc::SIGCONT);
        }
    });
    thread::scope(|scope| {
        let large = scope.spawn(|| {
            let args = "x".repeat(8 * 1024 * 1024).into();
            host.call(&vault, call("organ.echo", args, Vec::new(), "g"))
        });
        thread::sleep(Duration::from_millis(100));
        let mut quick = call("organ.echo", 2.into(), Vec::new(), "g");
        quick.deadline = Duration::from_millis(50);
        let err = host.call(&vault, quick).expect_err("deadline");
        assert!(matches!(err, HostError::DeadlineExceeded), "{err:?}");
        large
            .join()
            .expect("large call thread")
            .expect("the large call lands");
    });
    resume.join().expect("resume");
    let status = host.status("probe").expect("installed");
    assert_eq!((status.spawns, status.recent_crashes), (1, 0));
}

#[cfg(target_os = "linux")]
#[test]
fn an_answer_with_too_many_regions_is_refused_and_the_organ_lives() {
    // Each output is over the inline threshold, so each wants a region; a
    // frame carries at most 16.
    let (_dir, vault) = vault();
    let host = host();
    let args = Value::Map(vec![
        ("count".into(), 17.into()),
        ("bytes".into(), (70 * 1024).into()),
    ]);
    let err = host
        .call(&vault, call("probe.outputs", args, Vec::new(), "g"))
        .expect_err("too many regions");
    assert!(
        matches!(&err, HostError::Organ(error) if matches!(error.code, oneiron_organ_protocol::ErrorCode::TooLarge)),
        "{err:?}"
    );
    let status = host.status("probe").expect("installed");
    assert_eq!((status.spawns, status.recent_crashes), (1, 0));
}

/// Whether `pid` is a live process (a zombie is not).
#[cfg(target_os = "linux")]
fn running(pid: i64) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit(')')
            .next()
            .is_some_and(|rest| !rest.trim_start().starts_with('Z'))
    })
}
