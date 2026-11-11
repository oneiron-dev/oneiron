//! F1-6 (lead, Tue 10 Nov 06:5x): the isolating backends ride on the vault,
//! read through its `RuntimeHandle`, and the binary that builds the vault
//! installs them. No process global names them, so two vaults of one process
//! can carry different sets, and each selection reaches only its own vault's.
//!
//! Every reader of the backends (the server's seven sandbox doors, and the
//! code-mode runtime's isolated lane through `bind_isolated_lane`) takes them
//! from `vault.runtime().sandbox_backends()`, the call this test drives.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::code_sandbox::SandboxGuestTier;
use oneiron::code_sandbox::microvm::{
    DEV_BACKEND_NAME, DevProcessBackend, MicroVmBackend, SandboxBackends,
    select_backend_for_session, select_backend_for_tier,
};
use oneiron::{ErrorKind, Vault, VaultConfig};

/// An OCI runtime path and image no host has.
const SESSION_RUNTIME: &str = "/nonexistent/oneiron-test/oci-runtime";
const SESSION_IMAGE: &str = "registry.invalid/oneiron/none@sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// One vault's backend set: it counts each time a selection asks it for a
/// backend, and carries the dev reference backend as its container when
/// `carries` is set.
struct CountedBackends {
    asked: AtomicUsize,
    carries: bool,
}

impl CountedBackends {
    fn new(carries: bool) -> Arc<Self> {
        Arc::new(Self {
            asked: AtomicUsize::new(0),
            carries,
        })
    }

    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }

    fn answer(&self) -> Option<Box<dyn MicroVmBackend>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.carries
            .then(|| Box::new(DevProcessBackend::in_temp_root()) as Box<dyn MicroVmBackend>)
    }
}

impl SandboxBackends for CountedBackends {
    fn firecracker(&self) -> Option<Box<dyn MicroVmBackend>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        None
    }

    fn container(&self) -> Option<Box<dyn MicroVmBackend>> {
        self.answer()
    }

    fn session_container(
        &self,
        _runtime: PathBuf,
        _image: &str,
    ) -> Option<oneiron::Result<Box<dyn MicroVmBackend>>> {
        self.answer().map(Ok)
    }
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

/// What one vault's selection gives a Foreign guest: `backend <name>` or
/// `refused <kind>`.
fn foreign_outcome(vault: &Vault) -> String {
    match select_backend_for_tier(
        &*vault.runtime().sandbox_backends(),
        SandboxGuestTier::Foreign,
    ) {
        Ok(Some(backend)) => format!("backend {}", backend.name()),
        Ok(None) => "in-process".to_owned(),
        Err(error) => format!("refused {:?}", error.kind()),
    }
}

fn session_outcome(vault: &Vault) -> String {
    match select_backend_for_session(
        &*vault.runtime().sandbox_backends(),
        SandboxGuestTier::Untrusted,
        PathBuf::from(SESSION_RUNTIME),
        SESSION_IMAGE,
    ) {
        Ok(backend) => format!("backend {}", backend.name()),
        Err(error) => format!("refused {:?}", error.kind()),
    }
}

#[test]
fn two_vaults_in_one_process_each_select_from_their_own_backends() {
    let (_dir_a, carrying) = open_vault();
    let (_dir_b, empty) = open_vault();
    let carrying_set = CountedBackends::new(true);
    let empty_set = CountedBackends::new(false);
    assert!(
        carrying
            .install_sandbox_backends(carrying_set.clone())
            .is_ok(),
        "the first install on a vault holds"
    );
    assert!(
        empty.install_sandbox_backends(empty_set.clone()).is_ok(),
        "a second vault of the same process takes its own install"
    );

    let dev = format!("backend {DEV_BACKEND_NAME}");
    let refused = format!("refused {:?}", ErrorKind::MicroVmBackendUnavailable);
    let carrying_foreign = foreign_outcome(&carrying);
    let empty_foreign = foreign_outcome(&empty);
    let carrying_session = session_outcome(&carrying);
    let empty_session = session_outcome(&empty);
    println!("PER-VAULT carrying foreign -> {carrying_foreign}; session -> {carrying_session}");
    println!("PER-VAULT empty foreign -> {empty_foreign}; session -> {empty_session}");
    assert_eq!(
        carrying_foreign, dev,
        "the carrying vault's set answers its run"
    );
    assert_eq!(carrying_session, dev, "and its session");
    assert_eq!(
        empty_foreign, refused,
        "the empty vault's set answers its run"
    );
    assert_eq!(empty_session, refused, "and its session");

    // Each selection asked only its own vault's set: Firecracker first on a
    // KVM host, then the container.
    let per_selection = carrying_set.asked() / 2;
    assert!(per_selection >= 1, "the carrying set was asked");
    assert_eq!(
        carrying_set.asked(),
        empty_set.asked(),
        "each vault's two selections asked its own set, the same number of times"
    );

    // A later install does not replace a vault's set.
    assert!(
        carrying
            .install_sandbox_backends(CountedBackends::new(false))
            .is_err(),
        "a second install on one vault is refused"
    );
    assert_eq!(
        foreign_outcome(&carrying),
        dev,
        "the first install still holds"
    );
}

#[test]
fn a_vault_with_no_installed_backends_refuses_every_isolating_tier() {
    let (_dir, vault) = open_vault();
    let backends = vault.runtime().sandbox_backends();
    let first_party = select_backend_for_tier(&*backends, SandboxGuestTier::FirstPartyDreamer)
        .expect("first-party selection");
    assert!(
        first_party.is_none(),
        "first-party code still runs in-process"
    );
    for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
        let refused = select_backend_for_tier(&*backends, tier)
            .err()
            .expect("an isolating tier with no installed backends fails closed");
        assert_eq!(refused.kind(), ErrorKind::MicroVmBackendUnavailable);
        let refused = select_backend_for_session(
            &*backends,
            tier,
            PathBuf::from(SESSION_RUNTIME),
            SESSION_IMAGE,
        )
        .err()
        .expect("a session with no installed backends fails closed");
        assert_eq!(refused.kind(), ErrorKind::MicroVmBackendUnavailable);
    }
}
