//! Slice 5b.1 (the SandboxBackends inversion): a sandbox run selects its
//! backend through the `SandboxBackends` trait, and the build's one
//! implementation answers what the selection answered before the inversion.
//!
//! `selection_outcomes_of_the_compiled_backends` prints one line per tier for
//! the finite-run and the session selection on this host. Its twin on main
//! (the same test calling the old `select_backend_for_tier(tier)` and
//! `select_backend_for_session(tier, ..)`) prints the same lines on the same
//! host: the inversion is a refactor, so a red run before it is not possible.
//! `selection_routes_through_the_trait` checks the routing law against a
//! recording implementation.

use std::path::PathBuf;
use std::sync::Mutex;

use oneiron::ErrorKind;
use oneiron::code_sandbox::SANDBOX_BACKENDS;
use oneiron::code_sandbox::SandboxGuestTier;
use oneiron::code_sandbox::microvm::{
    MicroVmBackend, SandboxBackends, select_backend_for_session, select_backend_for_tier,
};

const TIERS: [SandboxGuestTier; 3] = [
    SandboxGuestTier::FirstPartyDreamer,
    SandboxGuestTier::Foreign,
    SandboxGuestTier::Untrusted,
];

/// An OCI runtime path and image no host has, so a session container on
/// this host, if the build carries one, fails the same way at both heads.
const SESSION_RUNTIME: &str = "/nonexistent/oneiron-test/oci-runtime";
const SESSION_IMAGE: &str = "registry.invalid/oneiron/none@sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn finite_outcome(selected: oneiron::Result<Option<Box<dyn MicroVmBackend>>>) -> String {
    match selected {
        Ok(None) => "in-process".to_owned(),
        Ok(Some(backend)) => format!("backend {}", backend.name()),
        Err(error) => format!("refused {:?}: {error}", error.kind()),
    }
}

fn session_outcome(selected: oneiron::Result<Box<dyn MicroVmBackend>>) -> String {
    match selected {
        Ok(backend) => format!("backend {}", backend.name()),
        Err(error) => format!("refused {:?}: {error}", error.kind()),
    }
}

/// An outcome without its message, which names the tier: `in-process`,
/// `backend <name>` or `refused <kind>`.
fn outcome_shape(line: &str) -> &str {
    line.split(':').next().unwrap_or(line)
}

#[test]
fn selection_outcomes_of_the_compiled_backends() {
    let mut finite = Vec::new();
    for tier in TIERS {
        let line = finite_outcome(select_backend_for_tier(&SANDBOX_BACKENDS, tier));
        println!("SELECT-FINITE tier={} -> {line}", tier.as_str());
        finite.push(line);
    }
    for tier in TIERS {
        let line = session_outcome(select_backend_for_session(
            &SANDBOX_BACKENDS,
            tier,
            PathBuf::from(SESSION_RUNTIME),
            SESSION_IMAGE,
        ));
        println!("SELECT-SESSION tier={} -> {line}", tier.as_str());
    }
    assert_eq!(finite[0], "in-process", "first-party code takes no microVM");
    assert_eq!(
        outcome_shape(&finite[1]),
        outcome_shape(&finite[2]),
        "Foreign and Untrusted take the same isolating backend, or both fail closed"
    );
    assert_ne!(
        finite[1], "in-process",
        "an isolating tier never runs in-process"
    );
}

/// Records which backend the selection asked for, and answers with the
/// backends it was built with.
struct RecordingBackends {
    asked: Mutex<Vec<&'static str>>,
    container: bool,
}

impl RecordingBackends {
    fn new(container: bool) -> Self {
        Self {
            asked: Mutex::new(Vec::new()),
            container,
        }
    }

    fn asked(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.asked.lock().expect("lock"))
    }

    fn ask(&self, backend: &'static str) {
        self.asked.lock().expect("lock").push(backend);
    }

    fn dev_backend(&self) -> Option<Box<dyn MicroVmBackend>> {
        self.container.then(|| {
            Box::new(oneiron::code_sandbox::microvm::DevProcessBackend::in_temp_root())
                as Box<dyn MicroVmBackend>
        })
    }
}

impl SandboxBackends for RecordingBackends {
    fn firecracker(&self) -> Option<Box<dyn MicroVmBackend>> {
        self.ask("firecracker");
        None
    }

    fn container(&self) -> Option<Box<dyn MicroVmBackend>> {
        self.ask("container");
        self.dev_backend()
    }

    fn session_container(
        &self,
        _runtime: PathBuf,
        _image: &str,
    ) -> Option<oneiron::Result<Box<dyn MicroVmBackend>>> {
        self.ask("session_container");
        self.dev_backend().map(Ok)
    }
}

/// The selection asks for Firecracker only on a host with KVM, as before.
fn kvm_available() -> bool {
    cfg!(target_os = "linux")
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok()
}

#[test]
fn selection_routes_through_the_trait() {
    let firecracker_first: Vec<&str> = if kvm_available() {
        vec!["firecracker"]
    } else {
        Vec::new()
    };
    let then = |next: &'static str| {
        let mut asked = firecracker_first.clone();
        asked.push(next);
        asked
    };

    // A build that carries a container backend.
    let backends = RecordingBackends::new(true);
    let first_party = select_backend_for_tier(&backends, SandboxGuestTier::FirstPartyDreamer)
        .expect("first-party selection");
    assert!(first_party.is_none(), "first-party code takes no microVM");
    assert!(
        backends.asked().is_empty(),
        "first-party code asks no backend"
    );
    for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
        let selected = select_backend_for_tier(&backends, tier)
            .expect("an isolating tier with a container backend selects it")
            .expect("an isolating tier never routes to `None`");
        assert_eq!(
            selected.name(),
            oneiron::code_sandbox::microvm::DEV_BACKEND_NAME
        );
        assert_eq!(backends.asked(), then("container"));
        let session = select_backend_for_session(
            &backends,
            tier,
            PathBuf::from(SESSION_RUNTIME),
            SESSION_IMAGE,
        )
        .expect("a session with a container backend selects it");
        assert_eq!(
            session.name(),
            oneiron::code_sandbox::microvm::DEV_BACKEND_NAME
        );
        assert_eq!(backends.asked(), then("session_container"));
    }
    let refused = select_backend_for_session(
        &backends,
        SandboxGuestTier::FirstPartyDreamer,
        PathBuf::from(SESSION_RUNTIME),
        SESSION_IMAGE,
    )
    .err()
    .expect("a first-party session is refused");
    assert_eq!(refused.kind(), ErrorKind::MicroVmBackendUnavailable);
    assert!(
        backends.asked().is_empty(),
        "a refused session asks no backend"
    );

    // A build that carries none: every isolating tier fails closed.
    let none = RecordingBackends::new(false);
    for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
        let refused = select_backend_for_tier(&none, tier)
            .err()
            .expect("no backend fails closed");
        assert_eq!(refused.kind(), ErrorKind::MicroVmBackendUnavailable);
        assert_eq!(none.asked(), then("container"));
        let refused =
            select_backend_for_session(&none, tier, PathBuf::from(SESSION_RUNTIME), SESSION_IMAGE)
                .err()
                .expect("no session backend fails closed");
        assert_eq!(refused.kind(), ErrorKind::MicroVmBackendUnavailable);
        assert_eq!(none.asked(), then("session_container"));
    }
}
