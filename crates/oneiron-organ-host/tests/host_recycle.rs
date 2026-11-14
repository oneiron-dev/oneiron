//! The organ code `internal` names a bug, and the host recycles the live
//! process after three in a row (ARCH-0075, organ error codes), against a
//! real organ process (the probe). A recycle is the host's own decision: no
//! crash is counted and no backoff set. A call still in flight on the
//! recycled process ends as the organ answers it, and the process is
//! stopped after. A recycled process that dies on its own still counts its
//! crash. Any other answer ends the run.
#![cfg(target_os = "linux")]

use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::Duration;

use oneiron::{Vault, VaultConfig};
use oneiron_organ_host::{
    Answered, AskGrant, AskHandler, AskHandlers, AskRequest, CallClass, HostConfig, HostError,
    OrganCall, OrganHost, OrganSpec, OrganState, OrganStatus,
};
use oneiron_organ_protocol::{AskRefusal, ErrorCode, Value};

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-organ-probe");
/// The ask that holds a call in flight ([`Hold`]).
const HOLD: &str = "probe.hold";

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    (dir, vault)
}

/// The probe with the default first-party grant: two threads, so a second
/// call runs beside one in flight.
fn host() -> OrganHost {
    let host = OrganHost::new(HostConfig::default());
    let mut spec = OrganSpec::first_party("probe", PROBE);
    spec.verbs = vec!["organ.echo".into(), "probe.ask".into()];
    spec.asks = vec![AskGrant::new(HOLD, 1)];
    host.install(spec);
    host
}

/// Holds the call that asks in flight: says it was asked, then answers once
/// it is let go, or after ten seconds, so a failing test cannot hang.
struct Hold {
    asked: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl AskHandler for Hold {
    fn answer(&self, _: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        let _ = self.asked.send(());
        let release = self.release.lock().expect("release");
        let _ = release.recv_timeout(Duration::from_secs(10));
        Ok(Answered::default())
    }
}

fn call(verb: &str, args: Value) -> OrganCall {
    OrganCall {
        organ: "probe".into(),
        verb: verb.into(),
        schema: 1,
        args,
        body: None,
        inputs: Vec::new(),
        class: CallClass::Agent,
        deadline: Duration::from_secs(10),
        grant: "g".into(),
    }
}

/// `probe.ask` that asks nothing and then fails: the organ answers `internal`.
fn failing() -> OrganCall {
    call(
        "probe.ask",
        Value::Map(vec![
            ("times".into(), 0_u64.into()),
            ("fail".into(), true.into()),
        ]),
    )
}

/// `probe.ask` that asks [`HOLD`] once: in flight until the hold lets go.
fn held() -> OrganCall {
    call(
        "probe.ask",
        Value::Map(vec![
            ("verb".into(), HOLD.into()),
            ("times".into(), 1_u64.into()),
        ]),
    )
}

fn answers_internal(host: &OrganHost, vault: &Vault) {
    match host.call(vault, failing()) {
        Err(HostError::Organ(error)) => assert_eq!(error.code, ErrorCode::Internal, "{error:?}"),
        other => panic!("expected the organ's internal answer, got {other:?}"),
    }
}

fn echoes(host: &OrganHost, vault: &Vault, word: &str) {
    let echoed = host
        .call(vault, call("organ.echo", word.into()))
        .expect("the organ answers");
    assert_eq!(echoed.report, Value::from(word));
}

fn status(host: &OrganHost) -> OrganStatus {
    host.status("probe").expect("installed")
}

/// Whether `pid` is a live process (a zombie is not). The host reaps an
/// organ it stops before the stop returns.
fn running(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit(')')
            .next()
            .is_some_and(|rest| !rest.trim_start().starts_with('Z'))
    })
}

/// Waits, without sleeping, until `pid` is reaped. The host's reader reaps
/// an organ that died on its own only after it saw the socket close and
/// marked the process ended, so a reaped organ is one the host knows ended.
fn reaped(pid: u32) -> bool {
    let entry = format!("/proc/{pid}");
    (0..10_000_000).any(|_| {
        let gone = !std::path::Path::new(&entry).exists();
        if !gone {
            thread::yield_now();
        }
        gone
    })
}

#[test]
fn three_internal_answers_in_a_row_recycle_the_process() {
    let (_dir, vault) = vault();
    let host = host();
    host.warm("probe").expect("warm");
    let first = status(&host).pid.expect("a live process");
    for _ in 0..2 {
        answers_internal(&host, &vault);
        let now = status(&host);
        assert_eq!((now.state, now.pid), (OrganState::Warm, Some(first)));
    }
    answers_internal(&host, &vault);
    let recycled = status(&host);
    assert_eq!(
        (recycled.state, recycled.pid),
        (OrganState::Cold, None),
        "the third internal in a row recycles the live process",
    );
    assert_eq!(
        (recycled.spawns, recycled.recent_crashes),
        (1, 0),
        "a recycle is not a crash",
    );
    assert!(!running(first), "the recycled process {first} still runs");
    echoes(&host, &vault, "fresh");
    let fresh = status(&host);
    assert_eq!(fresh.state, OrganState::Warm);
    assert_ne!(fresh.pid, Some(first), "a fresh process answers");
    assert_eq!(
        (fresh.spawns, fresh.recent_crashes),
        (2, 0),
        "no backoff, no crash"
    );
}

#[test]
fn a_call_in_flight_on_a_recycled_process_ends_as_the_organ_answers_it() {
    let (_dir, vault) = vault();
    let host = host();
    host.warm("probe").expect("warm");
    let first = status(&host).pid.expect("a live process");
    let (asked, was_asked) = mpsc::sync_channel(1);
    let (release, let_go) = mpsc::channel();
    let hold = Hold {
        asked,
        release: Mutex::new(let_go),
    };
    let asks = AskHandlers::none().with(HOLD, &hold);
    // Nothing in the scope asserts before the held call is let go, so a
    // red run fails instead of waiting on the hold.
    let (failed, recycled, still_running, in_flight) = thread::scope(|scope| {
        let holder = scope.spawn(|| host.call_with(&vault, held(), Vec::new(), &asks));
        let in_flight = was_asked.recv_timeout(Duration::from_secs(10)).is_ok();
        let failed: Vec<_> = (0..3).map(|_| host.call(&vault, failing())).collect();
        let recycled = status(&host);
        let still_running = running(first);
        let _ = release.send(());
        assert!(in_flight, "the held call reached its ask");
        (
            failed,
            recycled,
            still_running,
            holder.join().expect("join"),
        )
    });
    for answer in failed {
        assert!(
            matches!(&answer, Err(HostError::Organ(error)) if error.code == ErrorCode::Internal),
            "{answer:?}",
        );
    }
    assert_eq!(
        (recycled.state, recycled.pid),
        (OrganState::Cold, None),
        "the third internal in a row recycles the live process",
    );
    assert!(
        still_running,
        "a recycle waits for the call still in flight"
    );
    in_flight.expect("the call in flight is answered, not killed");
    echoes(&host, &vault, "fresh");
    assert!(
        !running(first),
        "the recycled process {first} outlived its last call"
    );
    let fresh = status(&host);
    assert_ne!(fresh.pid, Some(first));
    assert_eq!((fresh.spawns, fresh.recent_crashes), (2, 0));
}

/// A recycled process that dies on its own counts its crash when the sweep
/// lets it go, as the live process's death counts at the next call. Here it
/// dies once its last call has ended; a sweep that comes between a dying
/// call's freed seat and that call's crash bookkeeping takes the same branch.
#[test]
fn a_recycled_process_that_dies_on_its_own_counts_a_crash() {
    let (_dir, vault) = vault();
    let host = host();
    host.warm("probe").expect("warm");
    let first = status(&host).pid.expect("a live process");
    let (asked, was_asked) = mpsc::sync_channel(1);
    let (release, let_go) = mpsc::channel();
    let hold = Hold {
        asked,
        release: Mutex::new(let_go),
    };
    let asks = AskHandlers::none().with(HOLD, &hold);
    let (recycled, in_flight) = thread::scope(|scope| {
        let holder = scope.spawn(|| host.call_with(&vault, held(), Vec::new(), &asks));
        let in_flight = was_asked.recv_timeout(Duration::from_secs(10)).is_ok();
        for _ in 0..3 {
            let _ = host.call(&vault, failing());
        }
        let recycled = status(&host);
        let _ = release.send(());
        assert!(in_flight, "the held call reached its ask");
        (recycled, holder.join().expect("join"))
    });
    assert_eq!(
        (recycled.state, recycled.pid),
        (OrganState::Cold, None),
        "the third internal in a row recycles the live process",
    );
    in_flight.expect("the call in flight is answered");
    // No call has started since the held one ended, so no sweep has
    // stopped the recycled process.
    assert!(running(first), "the recycled process {first} still runs");
    let pid = i32::try_from(first).expect("pid");
    // SAFETY: kill(2) on the organ this test started, which still runs, so
    // the host has not reaped it and its pid is not reused.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    assert!(reaped(first), "the host reaps the organ that died");
    host.unload_idle();
    let after = status(&host);
    assert_eq!(
        (after.spawns, after.recent_crashes),
        (1, 1),
        "a recycled process that died on its own counts its crash",
    );
}

#[test]
fn another_answer_ends_the_internal_run() {
    let (_dir, vault) = vault();
    let host = host();
    host.warm("probe").expect("warm");
    let first = status(&host).pid.expect("a live process");
    answers_internal(&host, &vault);
    answers_internal(&host, &vault);
    echoes(&host, &vault, "between");
    answers_internal(&host, &vault);
    answers_internal(&host, &vault);
    let kept = status(&host);
    assert_eq!(
        (kept.state, kept.pid, kept.spawns),
        (OrganState::Warm, Some(first), 1),
        "two internals, an answer, two internals: no three in a row",
    );
}
