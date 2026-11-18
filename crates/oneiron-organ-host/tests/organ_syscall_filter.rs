//! The organ's syscall filter (census L4-09, ARCH-0075 "Syscalls", FIX
//! [ORGAN-SECCOMP-ALLOW-LIST]): an organ that calls ptrace dies by the
//! seccomp kill, SIGSYS, and so does a process it forked; so does a call
//! its allow-list does not name (an inet socket), and so does a call aimed
//! at another process (a signal, a limit, a descriptor's owner, a
//! priority), while the same calls at its own process answer; it reads
//! its own limits but setting one answers EPERM, and it may name its own
//! threads but makes no other prctl. An organ
//! under the filter still answers its ordinary calls, inputs read through
//! regions included, and every verb of the probe answers under its list.
//! Linux only: macOS has no seccomp.
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
    spec.verbs = [
        "organ.touch",
        "organ.echo",
        "probe.ptrace",
        "probe.inet_socket",
        "probe.reach",
        "probe.sleep",
        "probe.outputs",
        "probe.fork",
    ]
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

/// The args of a call that the organ makes in a child it forks, or itself.
fn in_child(child: bool) -> Value {
    Value::Map(vec![("in_child".into(), child.into())])
}

/// The args of a `probe.reach` call: `which` call aimed at `pid`, the
/// probe's own process when `None`, with `nice` for `priority`.
fn reach(which: &str, pid: Option<i64>, nice: i64) -> Value {
    let mut args = vec![("call".into(), which.into()), ("nice".into(), nice.into())];
    if let Some(pid) = pid {
        args.push(("pid".into(), pid.into()));
    }
    Value::Map(args)
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
        .call(&vault, call("probe.ptrace", in_child(true), Vec::new()))
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
    let organ = host.call(&vault, call("probe.ptrace", in_child(false), Vec::new()));
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

#[test]
fn an_organ_call_outside_its_allow_list_dies_by_the_syscall_filter() {
    let (_dir, vault) = vault();
    let host = host();
    // The host hands an organ its one socket on fd 3, so no organ's list
    // names `socket`: a process the organ forked dies by SIGSYS at an inet
    // socket, before the call returns.
    let child = host
        .call(
            &vault,
            call("probe.inet_socket", in_child(true), Vec::new()),
        )
        .expect("the organ itself made no call outside its list and answers");
    assert_eq!(
        (
            report_i64(&child.report, "signal"),
            report_i64(&child.report, "exit")
        ),
        (Some(i64::from(libc::SIGSYS)), Some(-1)),
        "the organ's forked child ended by SIGSYS at its inet socket: {:?}",
        child.report,
    );
    // The organ's own inet socket kills the organ under its call.
    let organ = host.call(
        &vault,
        call("probe.inet_socket", in_child(false), Vec::new()),
    );
    assert!(
        matches!(organ, Err(HostError::Crashed(_))),
        "an organ's own inet socket ends it: {organ:?}",
    );
}

#[test]
fn an_organ_call_aimed_at_another_process_dies_by_the_syscall_filter() {
    let (_dir, vault) = vault();
    // At its own process a signal 0 and a read of its own limits answer:
    // the filter allows them by the organ's own pid (or 0 for itself).
    let host = host();
    for (which, pid) in [("signal", None), ("limits", None), ("limits", Some(0))] {
        let own = host
            .call(
                &vault,
                call("probe.reach", reach(which, pid, 0), Vec::new()),
            )
            .unwrap_or_else(|err| panic!("{which} at its own process ({pid:?}): {err:?}"));
        assert_eq!(
            report_i64(&own.report, "returned"),
            Some(0),
            "{which} at its own process ({pid:?}) answers: {:?}",
            own.report,
        );
    }
    // At the host's process, the organ's parent, each kills the organ
    // under its call before the call runs: a signal (even signal 0, which
    // only checks permission), a read of its limits, an owner for a
    // descriptor's signals, its own nice value set again. Each on a host
    // of its own, so no crash backoff stands between them.
    let host_pid = std::process::id();
    // SAFETY: getpriority(2) of this process reads and writes no memory.
    let nice = i64::from(unsafe { libc::getpriority(libc::PRIO_PROCESS, host_pid) });
    for which in ["signal", "limits", "owner", "priority"] {
        let new_host = host();
        let organ = new_host.call(
            &vault,
            call(
                "probe.reach",
                reach(which, Some(i64::from(host_pid)), nice),
                Vec::new(),
            ),
        );
        assert!(
            matches!(organ, Err(HostError::Crashed(_))),
            "{which} at the host's process ends the organ: {organ:?}",
        );
    }
}

#[test]
fn an_organ_sets_no_limit_and_makes_no_prctl_but_a_thread_name() {
    let (_dir, vault) = vault();
    let host = host();
    // Its open-file limit set again to what it reads answers EPERM: no
    // organ lifts the limits its grant set (a first-party organ's hard
    // limits are open), and the organ lives on.
    let set = host
        .call(
            &vault,
            call("probe.reach", reach("set_limits", None, 0), Vec::new()),
        )
        .expect("setting a limit answers");
    assert_eq!(
        (
            report_i64(&set.report, "returned"),
            report_i64(&set.report, "errno")
        ),
        (Some(-1), Some(i64::from(libc::EPERM))),
        "setting its own limit is refused: {:?}",
        set.report,
    );
    // Naming its own thread answers, as a thread pool's start does.
    let named = host
        .call(
            &vault,
            call("probe.reach", reach("name", None, 0), Vec::new()),
        )
        .expect("naming its thread answers");
    assert_eq!(
        report_i64(&named.report, "returned"),
        Some(0),
        "naming its thread: {:?}",
        named.report,
    );
    // Any other prctl, even a read, kills the organ under its call.
    let new_host = host();
    let dumpable = new_host.call(
        &vault,
        call("probe.reach", reach("dumpable", None, 0), Vec::new()),
    );
    assert!(
        matches!(dumpable, Err(HostError::Crashed(_))),
        "a prctl past a thread name ends the organ: {dumpable:?}",
    );
}

#[test]
fn every_probe_verb_answers_under_its_allow_list() {
    let (_dir, vault) = vault();
    let host = host();
    let slept = host.call(
        &vault,
        call(
            "probe.sleep",
            Value::Map(vec![("ms".into(), 5u64.into())]),
            Vec::new(),
        ),
    );
    assert!(slept.is_ok(), "sleep: {slept:?}");
    // One output inline, one past the inline bound, which crosses as a
    // sealed region the organ made.
    for bytes in [16u64, 256 * 1024] {
        let made = host
            .call(
                &vault,
                call(
                    "probe.outputs",
                    Value::Map(vec![
                        ("count".into(), 2u64.into()),
                        ("bytes".into(), bytes.into()),
                    ]),
                    Vec::new(),
                ),
            )
            .expect("outputs");
        assert_eq!(made.outputs.len(), 2, "{bytes}-byte outputs");
    }
    let forked = host
        .call(&vault, call("probe.fork", Value::Nil, Vec::new()))
        .expect("fork");
    assert!(
        forked.report.as_i64().is_some_and(|pid| pid > 0),
        "fork answers its child's pid: {:?}",
        forked.report,
    );
    let echoed = host
        .call(&vault, call("organ.echo", "still here".into(), Vec::new()))
        .expect("echo after every verb");
    assert_eq!(echoed.report, Value::from("still here"));
}
