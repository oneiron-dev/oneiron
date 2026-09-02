//! ONE-1579 / ONE-1963 ready-child regressions: the readiness boundary, the
//! bounded shutdown path, and the digest and refusal that make a full run's
//! ready child the artifact it was built from.

use std::sync::{Arc, Mutex};

use super::*;

fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

/// A program that stays up until it is killed, for the bounded-shutdown
/// regression. `None` only where the platform ships no such program.
fn long_lived_program() -> Option<PathBuf> {
    first_existing(&["/bin/sleep", "/usr/bin/sleep"])
}

fn immediate_program() -> Option<PathBuf> {
    first_existing(&["/bin/true", "/usr/bin/true"])
}

/// Readiness must be the completed TCP accept and nothing else. The
/// stand-in child emits a stream of convincing "ready" log lines well
/// before it connects; a probe that watched log text would return early,
/// and a probe that waited on the accept cannot.
#[test]
fn wake_probe_waits_for_tcp_accept_not_log_text() {
    let probe = WakeProbe::bind().expect("probe binds");
    let addr = probe.addr().expect("probe has an address");
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let log_writer = Arc::clone(&log);
    let quiet_for = Duration::from_millis(120);

    let started = Instant::now();
    let child = std::thread::spawn(move || {
        // Everything a log-text wait would have tripped on, emitted first.
        for line in ["listening", "READY", "server ready", "startup complete"] {
            log_writer
                .lock()
                .expect("log lock")
                .push(String::from(line));
            std::thread::sleep(quiet_for / 4);
        }
        TcpStream::connect(addr).expect("stand-in child connects")
    });

    let ready = probe
        .wait_ready(started, Duration::from_secs(20))
        .expect("the probe accepts the child");
    let connection = child.join().expect("stand-in child thread");

    assert_eq!(ready.signal, ReadinessSignal::TcpAccept);
    assert!(
        ready.elapsed_ms >= quiet_for.as_secs_f64() * 1e3 * 0.8,
        "readiness must not fire before the connect; got {}ms while the child spent {}ms only \
         writing log text",
        ready.elapsed_ms,
        quiet_for.as_secs_f64() * 1e3
    );
    let emitted = log.lock().expect("log lock").clone();
    assert!(
        emitted.iter().any(|line| line.contains("READY")),
        "the fixture must actually have emitted ready-looking log text"
    );
    assert_eq!(emitted.len(), 4, "all four log lines landed before ready");
    drop(connection);
    drop(ready.stream);
}

/// A caller-supplied child is not required to exit when the parent closes
/// the readiness socket. An unconditional `wait()` on such a child would
/// block the whole benchmark forever, so the parent bounds the wait and
/// then terminates and reaps it.
#[test]
fn a_child_that_outlives_its_release_is_terminated_within_the_budget() {
    let Some(program) = long_lived_program() else {
        if cfg!(target_os = "linux") {
            panic!("a linux host must provide `sleep` for the bounded-shutdown regression");
        }
        return;
    };
    let mut child = spawn_child(&program, &["300".to_owned()]).expect("the stand-in child spawns");

    let started = Instant::now();
    let outcome = wait_bounded(&mut child, Duration::from_millis(150));
    let elapsed = started.elapsed();

    assert_eq!(
        outcome,
        ChildExit::TerminatedAfterBudget,
        "a child that ignores its release must be terminated, not waited on forever"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the bounded wait must return promptly, took {elapsed:?}"
    );
    assert!(
        matches!(child.try_wait(), Ok(Some(_))),
        "the terminated child must be reaped, not left as a zombie"
    );
}

/// A child that DOES exit on its own is reported as having exited, and is
/// never killed.
#[test]
fn a_child_that_exits_on_its_own_is_reported_as_exited() {
    let Some(program) = immediate_program() else {
        if cfg!(target_os = "linux") {
            panic!("a linux host must provide `true` for the shutdown regression");
        }
        return;
    };
    let mut child = spawn_child(&program, &[]).expect("the stand-in child spawns");
    assert_eq!(
        wait_bounded(&mut child, child_shutdown_budget()),
        ChildExit::Exited
    );
}

/// The hold a child arms at connect time must cover the parent's whole
/// spawn, accept and sample phase — otherwise the FIRST child can expire
/// while the parent is still accepting the tenth.
#[test]
fn the_minimum_child_hold_covers_the_whole_accept_and_sample_phase() {
    assert_eq!(
        minimum_child_hold_ms(20_000),
        20_000 + READY_CHILD_SAMPLING_MARGIN_MS
    );
    assert!(
        minimum_child_hold_ms(20_000) > 20_000,
        "a hold equal to the accept timeout leaves no room to sample RSS"
    );
    assert_eq!(
        minimum_child_hold_ms(u64::MAX),
        u64::MAX,
        "the floor saturates rather than wrapping to a tiny hold"
    );
}

/// The bundled child is described by the exact command line that was run,
/// and a caller-supplied plan gets its placeholders substituted.
#[test]
fn child_commands_substitute_their_placeholders() {
    let addr: SocketAddr = "127.0.0.1:4242".parse().expect("addr");
    let fallback = Path::new("/opt/oneiron-bench");
    let vault = Path::new("/tmp/ready-3");

    let (program, args) = child_command(None, fallback, addr, vault, 25_000);
    assert_eq!(program, fallback);
    assert_eq!(args[0], "perf");
    assert_eq!(args[1], "wake-child");
    assert!(args.contains(&"127.0.0.1:4242".to_owned()));
    assert!(args.contains(&"25000".to_owned()));
    assert!(describe_child(&program, &args).contains("wake-child"));

    let plan = ChildCommandPlan {
        program: "/usr/bin/service".to_owned(),
        args: vec![
            "--listen={ready_addr}".to_owned(),
            "--data={vault_dir}".to_owned(),
            "--linger={hold_ms}".to_owned(),
        ],
    };
    let (program, args) = child_command(Some(&plan), fallback, addr, vault, 25_000);
    assert_eq!(program, Path::new("/usr/bin/service"));
    assert_eq!(
        args,
        vec![
            "--listen=127.0.0.1:4242".to_owned(),
            "--data=/tmp/ready-3".to_owned(),
            "--linger=25000".to_owned(),
        ]
    );
}

/// Only the harness's OWN child opens its vault before connecting, so only
/// it can carry vault residency. A program named by the environment
/// override is an arbitrary executable the harness never argued with, and
/// the resolver must say so rather than letting the ready-children axis
/// call ten opaque processes ten active vaults.
#[test]
fn an_environment_overridden_child_program_is_never_harness_owned() {
    let pinned = std::env::var(CHILD_PROGRAM_ENV)
        .ok()
        .map(|raw| raw.trim().to_owned())
        .filter(|raw| !raw.is_empty());
    match resolve_child_program() {
        Ok(resolved) => {
            if let Some(pinned) = pinned {
                assert!(
                    !resolved.harness_owned,
                    "an overridden child program is opaque, whatever it points at"
                );
                assert_eq!(
                    resolved.path,
                    PathBuf::from(pinned),
                    "the override is spawned verbatim"
                );
            } else {
                assert!(
                    resolved.harness_owned,
                    "the running oneiron-bench binary IS the harness-owned child"
                );
                assert_eq!(
                    resolved.path,
                    std::env::current_exe().expect("the test executable resolves")
                );
            }
        }
        Err(reason) => assert!(
            reason.contains(CHILD_PROGRAM_ENV),
            "an unresolvable child program must name the override: {reason}"
        ),
    }
}

/// ONE-1963: a FULL run refuses an operator-chosen ready child outright.
/// Every combination is exercised as a decision, so the refusal is proven
/// without this test mutating the process environment other tests read.
#[test]
fn a_full_run_refuses_an_environment_pinned_child_program() {
    let refusal = refuse_full_run_child_override(RunMode::Full, Some("/usr/bin/other-bench"))
        .expect_err("a full run must refuse an operator-chosen child program");
    assert!(refusal.contains(CHILD_PROGRAM_ENV), "{refusal}");
    assert!(refusal.contains("/usr/bin/other-bench"), "{refusal}");
    assert!(
        refusal.contains("before any axis runs"),
        "the refusal must happen before measurement, not after: {refusal}"
    );

    // A full run with no override is admissible, and a smoke may compare
    // against a separate binary — that is what the smoke contract is for.
    refuse_full_run_child_override(RunMode::Full, None).expect("no override, no refusal");
    refuse_full_run_child_override(RunMode::SyntheticSmoke, Some("/usr/bin/other-bench"))
        .expect("a synthetic smoke may point at another binary");
    refuse_full_run_child_override(RunMode::SyntheticSmoke, None).expect("nothing to refuse");
}

/// The program that will actually be spawned is hashed BEFORE any spawn,
/// including a plan-supplied one — otherwise the ready-children axis could
/// not say which binary held the ten vaults.
#[test]
fn the_program_that_will_be_spawned_is_hashed_before_the_first_spawn() {
    let Some(program) = immediate_program() else {
        if cfg!(target_os = "linux") {
            panic!("a linux host must provide `true` for the child-digest regression");
        }
        return;
    };
    let plan = ChildCommandPlan {
        program: program.display().to_string(),
        args: Vec::new(),
    };
    let resolved = resolve_and_hash_child_program(RunMode::SyntheticSmoke, Some(&plan))
        .expect("a smoke may name its own child program");

    assert_eq!(resolved.path.as_deref(), Some(program.as_path()));
    assert!(
        !resolved.harness_owned,
        "a plan-supplied program is not the harness's own child"
    );
    let digest = resolved
        .blake3
        .value()
        .expect("the resolved program is hashed");
    assert_eq!(digest.len(), 64, "blake3 renders as 64 hex characters");
    assert_eq!(
        digest,
        &super::super::git_sha::hash_file_blake3(&program).expect("the program hashes"),
        "the certificate digest must be blake3 over the program's exact bytes"
    );

    // An unresolvable program is `not_ready` with its reason, never a
    // silently absent digest.
    let missing = ChildCommandPlan {
        program: "/nonexistent/oneiron-bench-child".to_owned(),
        args: Vec::new(),
    };
    let resolved = resolve_and_hash_child_program(RunMode::SyntheticSmoke, Some(&missing))
        .expect("resolution itself still succeeds");
    assert!(!resolved.blake3.is_measured());
    assert!(matches!(resolved.blake3, Cell::NotReady { .. }));
}

#[test]
fn wake_child_arguments_are_validated() {
    assert!(run_wake_child(&["--ready-addr".to_owned()]).is_err());
    assert!(run_wake_child(&[]).is_err());
    assert!(run_wake_child(&["--ready-addr".to_owned(), "not-an-addr".to_owned()]).is_err());
    assert!(run_wake_child(&["--unknown".to_owned(), "value".to_owned()]).is_err());
}
