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
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_organ_host::{
    CallClass, HostConfig, HostError, OrganCall, OrganHost, OrganInput, OrganSpec, OrganState,
    Unavailable,
};
use oneiron_organ_protocol::{FrameError, Hash32, touch_fold};

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
    ]
    .map(String::from)
    .into();
    spec.media_types = vec![BIN.to_owned()];
    host.install(spec);
    host
}

fn call(verb: &str, args: rmpv::Value, inputs: Vec<OrganInput>, grant: &str) -> OrganCall {
    OrganCall {
        organ: "probe".into(),
        verb: verb.into(),
        schema: 1,
        args,
        body: None,
        inputs,
        class: CallClass::Agent,
        deadline: Duration::from_secs(10),
        grant: grant.into(),
    }
}

fn sleep_args(ms: u64, obey_cancel: bool) -> rmpv::Value {
    rmpv::Value::Map(vec![
        ("ms".into(), ms.into()),
        ("obey_cancel".into(), obey_cancel.into()),
    ])
}

fn report_u64(report: &rmpv::Value, key: &str) -> Option<u64> {
    report
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))?
        .1
        .as_u64()
}

#[test]
fn inputs_cross_as_regions_and_the_engine_hashes_them() {
    let (_dir, vault) = vault();
    let big: Vec<u8> = (0..3 * 1024 * 1024 + 5)
        .map(|i: u32| (i % 251) as u8)
        .collect();
    let small = b"seven bytes, then some".to_vec();
    let inputs = vec![put_blob(&vault, &big, BIN), put_blob(&vault, &small, BIN)];
    let host = host();
    for _ in 0..2 {
        let outcome = host
            .call(
                &vault,
                call("organ.touch", rmpv::Value::Nil, inputs.clone(), "g"),
            )
            .expect("touch");
        assert_eq!(
            report_u64(&outcome.report, "fold"),
            Some(touch_fold(&big) ^ touch_fold(&small)),
            "the organ read exactly the bytes the vault holds",
        );
        assert_eq!(
            report_u64(&outcome.report, "len"),
            Some((big.len() + small.len()) as u64)
        );
        let hashes: Vec<Hash32> = outcome
            .receipt
            .inputs
            .iter()
            .map(|i| i.content_hash)
            .collect();
        assert_eq!(hashes, vec![Hash32::of(&big), Hash32::of(&small)]);
        assert_eq!(outcome.receipt.organ.name, "probe");
    }
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
    assert_eq!(echoed.report, rmpv::Value::from("after"));
    let status = host.status("probe").expect("installed");
    assert_eq!(status.spawns, 2);
    assert_eq!(status.recent_crashes, 0, "a deadline kill is not a crash");
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
        match host.call(
            &vault,
            call("probe.crash", rmpv::Value::Nil, Vec::new(), "g"),
        ) {
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
    let refused = host.call(
        &vault,
        call("organ.touch", rmpv::Value::Nil, vec![png], "g"),
    );
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
    let (_dir, vault) = vault();
    let host = rogue("--deaf", HostConfig::default());
    let mut stuck = call(
        "organ.echo",
        "x".repeat(8 * 1024 * 1024).into(),
        Vec::new(),
        "g",
    );
    stuck.deadline = Duration::from_millis(500);
    let started = Instant::now();
    let err = host.call(&vault, stuck).expect_err("deadline");
    assert!(matches!(err, HostError::DeadlineExceeded), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
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
fn a_call_too_large_to_send_leaves_the_organ_unharmed() {
    let (_dir, vault) = vault();
    let host = OrganHost::new(HostConfig::default());
    let mut spec = OrganSpec::first_party("probe", PROBE);
    spec.verbs = vec!["organ.echo".into()];
    spec.max_call_frame = 4096;
    host.install(spec);
    let small = || call("organ.echo", 1.into(), Vec::new(), "g");
    host.call(&vault, small()).expect("small call");
    for _ in 0..6 {
        let big = call("organ.echo", "x".repeat(8192).into(), Vec::new(), "g");
        let err = host.call(&vault, big).expect_err("too large");
        assert!(
            matches!(err, HostError::Frame(FrameError::TooLarge { .. })),
            "{err:?}"
        );
    }
    let status = host.status("probe").expect("installed");
    assert_eq!(
        (status.spawns, status.recent_crashes),
        (1, 0),
        "refused calls neither kill nor count"
    );
    host.call(&vault, small()).expect("still warm");
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

#[cfg(target_os = "linux")]
#[test]
fn stopping_an_organ_kills_what_it_forked() {
    // A forked child inherits the organ's mappings and socket; killing the
    // organ alone would leave it holding them.
    let (_dir, vault) = vault();
    let host = host();
    let forked = host
        .call(
            &vault,
            call("probe.fork", rmpv::Value::Nil, Vec::new(), "g"),
        )
        .expect("fork");
    let pid = forked.report.as_i64().expect("the child's pid");
    assert!(pid > 0 && running(pid));
    assert!(host.unload("probe"));
    let deadline = Instant::now() + Duration::from_secs(3);
    while running(pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(!running(pid), "the forked child outlived its organ");
}
