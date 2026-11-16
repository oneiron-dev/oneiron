//! FIX RESIDENCE-SWITCH-STALE-HOME: an owner's residence switch reads the
//! elected home once to plan, and a switch to sync opened then waits on the
//! home to grant its held windows again, seconds of network. An election
//! that moves the home in that gap decides the mode the switch records and
//! publishes, and so this install's full-copy mark (L7-47):
//!
//! - a machine elected home while it switches to sync opened stays sync all
//!   and keeps its mark, since the elected home always runs sync all;
//! - a home that loses the election while its owner switches it to sync
//!   opened runs that choice and withdraws its mark.
//!
//! Either way the mode the connection runs afterwards is the mode the
//! owner's stored choice and the committed home resolve to.
//!
//! The election lands at the switch's race point, between its planning read
//! and its recording transaction, where the grants' network wait ends
//! (`oneiron::test_doors::full_copy_mark::elect_home_at_next_residence_switch`).
//! The fixture is one owned vault with this install profiled as the owner's
//! own machine and its home unreachable; the connection's loop never runs,
//! so the switch alone decides. It runs only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test residence_switch_rechecks_home`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::future::Future;
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::dreamer_runner::{DreamerHomeNodeCandidate, DreamerRunnerStore};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::residence::{
    discover_local_window_keys, local_is_elected_home, resolve_residence_mode,
    set_device_sync_preference,
};
use oneiron::sync::{SyncClientConfig, SyncResidenceMode};
use oneiron::test_doors::full_copy_mark::{elect_home_at_next_residence_switch, holds_full_copy};
use oneiron::{EntityId, Vault, VaultConfig};

/// A home no connect reaches: a closed loopback port refuses at once.
const UNREACHABLE_HOME: &str = "ws://127.0.0.1:9/ws";
/// The node id of the machine elected home in this install's place.
const ANOTHER_HOME_NODE: u64 = 7;

/// One owned vault with this install profiled as the owner's own machine.
struct Machine {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    local: EntityId,
}

fn machine() -> Machine {
    let dir = tempfile::tempdir().expect("FIXTURE: a scratch directory");
    let vault =
        Vault::open_owned(dir.path(), VaultConfig::default()).expect("FIXTURE: a fresh vault");
    vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner actor");
    let issuer = HostSlipIssuer::from_secret(b"residence switch rechecks home test host")
        .expect("FIXTURE: the fixture host issuer");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .ensure_host_root_slip(&issuer)
        .expect("FIXTURE: the host root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
        .expect("FIXTURE: this install's serving profile");
    let local = vault
        .local_machine()
        .expect("FIXTURE: this install's machine reads")
        .expect("FIXTURE: this install has a machine once it is profiled")
        .id;
    Machine {
        _dir: dir,
        vault: Arc::new(vault),
        local,
    }
}

impl Machine {
    /// This install's own home candidate, always on and attached.
    fn own_candidate(&self) -> DreamerHomeNodeCandidate {
        DreamerRunnerStore::new(&self.vault)
            .local_home_node_candidate(true, true, false)
            .expect("FIXTURE: this install's home candidate")
    }

    /// Elects this install the MACRO home.
    fn elect_home_here(&self) {
        DreamerRunnerStore::new(&self.vault)
            .elect_home_node(&[self.own_candidate()], now_secs())
            .expect("FIXTURE: the election");
        assert!(
            self.is_home(),
            "FIXTURE: the election names this install home"
        );
    }

    fn is_home(&self) -> bool {
        local_is_elected_home(&self.vault).expect("FIXTURE: the election reads")
    }

    /// Writes this install's held mark, as a first round under sync all
    /// once wrote it.
    fn mark_held(&self) {
        assert!(
            self.vault
                .declare_full_copy(true)
                .expect("FIXTURE: this install's held mark")
                .is_some(),
            "FIXTURE: this install's held mark is written"
        );
        assert!(
            self.holds(),
            "FIXTURE: this install holds a full copy once its held mark lands"
        );
    }

    /// Marks every window this install holds as promoted (`rp:w:`), as a
    /// home that granted them again leaves them: a switch to sync opened
    /// then keeps each without asking the home, and the race point stands in
    /// for that network wait. Without it the switch asks the home for the
    /// seeded windows and refuses, this connection having no selector.
    fn mark_windows_granted(&self) {
        let windows =
            discover_local_window_keys(&self.vault).expect("FIXTURE: the held windows read");
        assert!(!windows.is_empty(), "FIXTURE: this install holds windows");
        for window in windows {
            self.vault
                .sync_state_put(&format!("rp:w:{window}"), &[1])
                .expect("FIXTURE: the window's promotion row");
        }
    }

    fn holds(&self) -> bool {
        holds_full_copy(&self.vault, self.local).expect("the full-copy mark reads")
    }

    /// The mode the owner's stored choice and the committed home resolve to.
    fn resolved_mode(&self) -> SyncResidenceMode {
        resolve_residence_mode(&self.vault, SyncClientConfig::default().residence_mode)
            .expect("the residence mode resolves")
    }

    /// This machine's own-device connection, its home unreachable.
    fn connection(&self) -> SyncConnection {
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&self.vault),
            Arc::new(Materializer::new()),
            "residence-switch-rechecks-home",
        ));
        SyncConnection::new(
            manager,
            ConnectionConfig {
                client_config: SyncClientConfig {
                    server_url: UNREACHABLE_HOME.to_owned(),
                    reconnect_initial_ms: 60_000,
                    reconnect_backoff_max_ms: 60_000,
                    ..SyncClientConfig::default()
                },
                auto_reconnect: true,
            },
        )
        .expect("FIXTURE: this machine's own-device connection")
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("FIXTURE: the clock reads after the epoch")
        .as_secs()
}

/// Runs `test` on its own thread with a deep stack, on a current-thread
/// runtime: the switch and the race point it reaches run on that thread.
fn on_test_runtime<F: Future<Output = ()>>(name: &str, test: impl FnOnce() -> F + Send + 'static) {
    let run = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("FIXTURE: the test runtime")
                .block_on(test());
        })
        .expect("FIXTURE: the test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn a_machine_elected_home_during_a_switch_to_sync_opened_stays_sync_all_with_its_mark() {
    on_test_runtime(
        "a_machine_elected_home_during_a_switch_to_sync_opened_stays_sync_all_with_its_mark",
        || async {
            let machine = machine();
            // The owner chose sync all on a machine that is not the home.
            set_device_sync_preference(&machine.vault, SyncResidenceMode::All)
                .expect("FIXTURE: the owner's stored sync-all choice");
            machine.mark_held();
            machine.mark_windows_granted();
            let connection = machine.connection();
            assert_eq!(
                connection.residence_mode(),
                SyncResidenceMode::All,
                "FIXTURE: a machine that is not the home runs its owner's sync-all choice"
            );
            assert!(
                !machine.is_home(),
                "FIXTURE: no election names this install"
            );
            // The switch plans sync opened; the election lands while it waits
            // on the home to grant its held windows again.
            elect_home_at_next_residence_switch(machine.own_candidate(), now_secs());
            let change = connection
                .set_residence_mode(SyncResidenceMode::Opened)
                .await
                .expect("the switch answers");
            assert!(
                machine.is_home(),
                "FIXTURE: the election raced into the switch names this install home"
            );
            assert_eq!(
                change.mode,
                SyncResidenceMode::All,
                "a machine elected home during its switch to sync opened reports sync all"
            );
            assert_eq!(
                connection.residence_mode(),
                SyncResidenceMode::All,
                "a machine elected home during its switch to sync opened runs sync all"
            );
            assert!(
                change.retained.is_empty() && change.unsynced.is_empty(),
                "every window syncs under sync all, so the switch reports none retained or \
                 unsynced: {change:?}"
            );
            assert!(
                machine.holds(),
                "a machine elected home during its switch to sync opened keeps its full-copy mark"
            );
            assert_eq!(
                connection.residence_mode(),
                machine.resolved_mode(),
                "the mode the connection runs is the mode the store resolves to"
            );
        },
    );
}

#[test]
fn a_home_that_loses_the_election_during_a_switch_to_sync_opened_runs_it() {
    on_test_runtime(
        "a_home_that_loses_the_election_during_a_switch_to_sync_opened_runs_it",
        || async {
            let machine = machine();
            machine.elect_home_here();
            machine.mark_held();
            let connection = machine.connection();
            assert_eq!(
                connection.residence_mode(),
                SyncResidenceMode::All,
                "FIXTURE: the elected home runs sync all"
            );
            // The switch plans sync all, the home's mode; another machine is
            // elected home before it records the owner's sync-opened choice.
            elect_home_at_next_residence_switch(
                DreamerHomeNodeCandidate::always_on_local(ANOTHER_HOME_NODE),
                now_secs(),
            );
            let change = connection
                .set_residence_mode(SyncResidenceMode::Opened)
                .await
                .expect("the switch answers");
            assert!(
                !machine.is_home(),
                "FIXTURE: the election raced into the switch names another machine home"
            );
            assert_eq!(
                change.mode,
                SyncResidenceMode::Opened,
                "a home that loses the election during its switch to sync opened reports sync opened"
            );
            assert_eq!(
                connection.residence_mode(),
                SyncResidenceMode::Opened,
                "a home that loses the election during its switch to sync opened runs sync opened"
            );
            assert!(
                !machine.holds(),
                "a machine that runs sync opened after its switch holds no full-copy mark"
            );
            assert_eq!(
                connection.residence_mode(),
                machine.resolved_mode(),
                "the mode the connection runs is the mode the store resolves to"
            );
        },
    );
}
