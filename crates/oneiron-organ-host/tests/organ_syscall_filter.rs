//! The organ's syscall filter (census L4-09, ARCH-0075 "Syscalls"): an
//! organ that calls ptrace dies by the seccomp kill, SIGSYS, and so does a
//! process it forked; an organ under the filter still answers its ordinary
//! calls, inputs read through regions included. Linux only: macOS has no
//! seccomp.
#![cfg(target_os = "linux")]

use std::time::Duration;

use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::SecretSight;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_organ_host::{
    CallClass, HostConfig, HostError, OrganCall, OrganHost, OrganInput, OrganSpec, SightedInput,
};
use oneiron_organ_protocol::{Value, touch_fold};

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-organ-probe");
const BIN: &str = "application/octet-stream";

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
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

fn put_blob(vault: &Vault, bytes: &[u8]) -> OrganInput {
    let actor = EntityId::now();
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"uploader")
        .expect("actor");
    let artifact = EntityId::now();
    vault
        .put_blob_artifact(&artifact, &BlobArtifactBody::new("blob", BIN), at(1), 1)
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

/// A host with the probe installed as a first-party organ.
fn host() -> OrganHost {
    let host = OrganHost::new(HostConfig::default());
    let mut spec = OrganSpec::first_party("probe", PROBE);
    spec.verbs = ["organ.touch", "organ.echo", "probe.ptrace"]
        .map(String::from)
        .into();
    spec.media_types = vec![BIN.to_owned()];
    host.install(spec);
    host
}

fn call(verb: &str, args: Value, inputs: Vec<OrganInput>) -> OrganCall {
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
        grant: "g".into(),
    }
}

fn ptrace_args(in_child: bool) -> Value {
    Value::Map(vec![("in_child".into(), in_child.into())])
}

fn report_i64(report: &Value, key: &str) -> Option<i64> {
    report
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))?
        .1
        .as_i64()
}

#[test]
fn an_organ_that_calls_ptrace_dies_by_the_syscall_filter() {
    let (_dir, vault) = vault();
    let host = host();
    // A process the organ forked holds the filter too: its ptrace call ends
    // it by SIGSYS, the seccomp kill, before the call returns.
    let child = host
        .call(&vault, call("probe.ptrace", ptrace_args(true), Vec::new()))
        .expect("the organ itself made no denied call and answers");
    assert_eq!(
        (
            report_i64(&child.report, "signal"),
            report_i64(&child.report, "exit")
        ),
        (Some(i64::from(libc::SIGSYS)), Some(-1)),
        "the organ's forked child ended by SIGSYS at its ptrace call: {:?}",
        child.report,
    );
    // The organ's own ptrace call kills the organ under its call.
    let organ = host.call(&vault, call("probe.ptrace", ptrace_args(false), Vec::new()));
    assert!(
        matches!(organ, Err(HostError::Crashed(_))),
        "an organ's own ptrace call ends it: {organ:?}",
    );
}

#[test]
fn an_organ_under_the_syscall_filter_answers_its_ordinary_calls() {
    let (_dir, vault) = vault();
    let host = host();
    let echoed = host
        .call(
            &vault,
            call("organ.echo", "after the filter".into(), Vec::new()),
        )
        .expect("echo");
    assert_eq!(echoed.report, Value::from("after the filter"));
    let big: Vec<u8> = (0..2 * 1024 * 1024 + 3)
        .map(|i: u32| (i % 251) as u8)
        .collect();
    let small = b"seven bytes, then some".to_vec();
    let inputs = vec![put_blob(&vault, &big), put_blob(&vault, &small)];
    let touched = host
        .call(&vault, call("organ.touch", Value::Nil, inputs))
        .expect("touch over regions");
    let fold = touched
        .report
        .as_map()
        .and_then(|map| map.iter().find(|(k, _)| k.as_str() == Some("fold")))
        .and_then(|(_, value)| value.as_u64());
    assert_eq!(
        fold,
        Some(touch_fold(&big) ^ touch_fold(&small)),
        "the filtered organ mapped and read every input byte",
    );
}
