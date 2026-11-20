//! FIX RESIDENCE-REFRESH-LOST-HOME-WINDOWS-UNGRANTED: under sync opened a
//! window syncs only once the home granted it (`rp:w:`), and the residence
//! upkeep asks the home to retain only the windows marked `rr:w:`. A former
//! home holds every window in full with none granted, so when the residence
//! refresh, not an owner's switch, brings it to its owner's sync-opened
//! choice, it marks each held window for the upkeep's grants before it
//! publishes the mode and withdraws its full-copy mark (L7-47):
//!
//! - a home that loses the election while it runs;
//! - a home that lost it while it was down and starts under sync opened
//!   with its held mark kept.
//!
//! The fixture is one owned vault with this install profiled as the owner's
//! own machine; its own-device connection runs with its home unreachable,
//! so the refresh runs beside the connects that fail. It reaches the
//! full-copy fold read through `oneiron::test_doors::full_copy_mark`, so it
//! runs only under `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test residence_refresh_marks_ungranted_windows`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use oneiron::authority::{HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::dreamer_runner::{DreamerHomeNodeCandidate, DreamerRunnerStore};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::residence::{
    discover_local_window_keys, local_is_elected_home, set_device_sync_preference,
};
use oneiron::sync::{SyncClientConfig, SyncResidenceMode, WindowKey};
use oneiron::test_doors::full_copy_mark::holds_full_copy;
use oneiron::{EntityId, Vault, VaultConfig};

/// A home no connect reaches: a closed loopback port refuses at once.
const UNREACHABLE_HOME: &str = "ws://127.0.0.1:9/ws";
/// The node id of the machine elected home in this install's place.
const ANOTHER_HOME_NODE: u64 = 7;
/// How long a test waits for the residence refresh to act.
const REFRESH_WAIT: Duration = Duration::from_secs(10);

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
    let issuer =
        HostSlipIssuer::from_secret(b"residence refresh marks ungranted windows test host")
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
    /// Elects this install the MACRO home when `here`, else another node.
    fn elect_home(&self, here: bool) {
        let store = DreamerRunnerStore::new(&self.vault);
        let candidate = if here {
            store
                .local_home_node_candidate(true, true, false)
                .expect("FIXTURE: this install's home candidate")
        } else {
            DreamerHomeNodeCandidate::always_on_local(ANOTHER_HOME_NODE)
        };
        store
            .elect_home_node(&[candidate], now_secs())
            .expect("FIXTURE: the election");
        assert_eq!(
            local_is_elected_home(&self.vault).expect("FIXTURE: the election reads"),
            here,
            "FIXTURE: the election names the intended home"
        );
    }

    /// Stores the owner's sync-opened choice for this machine, as a switch
    /// to sync opened records it.
    fn choose_sync_opened(&self) {
        set_device_sync_preference(&self.vault, SyncResidenceMode::Opened)
            .expect("FIXTURE: the owner's stored sync-opened choice");
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

    fn holds(&self) -> bool {
        holds_full_copy(&self.vault, self.local).expect("the full-copy mark reads")
    }

    /// The windows this install holds, none of them granted by a home.
    fn held_windows(&self) -> Vec<WindowKey> {
        let held = discover_local_window_keys(&self.vault).expect("FIXTURE: the held windows read");
        assert!(!held.is_empty(), "FIXTURE: this install holds windows");
        for window in &held {
            assert!(
                self.vault
                    .sync_state_get(&format!("rp:w:{window}"))
                    .expect("FIXTURE: the window's promotion row reads")
                    .is_none(),
                "FIXTURE: no home granted the held window {window}"
            );
        }
        held
    }

    /// The held windows not marked for the residence upkeep's grants
    /// (`rr:w:`).
    fn unmarked(&self, held: &[WindowKey]) -> Vec<WindowKey> {
        held.iter()
            .filter(|window| {
                self.vault
                    .sync_state_get(&format!("rr:w:{window}"))
                    .expect("the window's retain row reads")
                    .is_none()
            })
            .cloned()
            .collect()
    }

    /// This machine's own-device connection, its home unreachable and its
    /// reconnects a minute apart.
    fn connection(&self) -> SyncConnection {
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&self.vault),
            Arc::new(Materializer::new()),
            "residence-refresh-marks-ungranted-windows",
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
/// runtime.
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

/// Runs `connection`'s loop beside `script` until `script` ends; the loop
/// never ends first, its home being unreachable.
async fn beside_running_connection(connection: &SyncConnection, script: impl Future<Output = ()>) {
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let run = connection.run(shutdown_rx);
    tokio::pin!(run);
    tokio::select! {
        _ = &mut run => panic!("FIXTURE: the connection loop ended before the test"),
        () = script => {}
    }
    let _ = shutdown.send(());
}

#[test]
fn a_home_that_loses_the_election_marks_its_held_windows_for_grants() {
    on_test_runtime(
        "a_home_that_loses_the_election_marks_its_held_windows_for_grants",
        || async {
            let machine = machine();
            machine.elect_home(true);
            // The owner chose sync opened while this machine was the home: no
            // switch, since the elected home runs sync all whatever was chosen.
            // No held mark either: the refresh hands the windows over because
            // the machine ran sync all.
            machine.choose_sync_opened();
            let held = machine.held_windows();
            let connection = machine.connection();
            assert_eq!(
                connection.residence_mode(),
                SyncResidenceMode::All,
                "FIXTURE: the elected home runs sync all"
            );
            beside_running_connection(&connection, async {
                machine.elect_home(false);
                let deadline = tokio::time::Instant::now() + REFRESH_WAIT;
                while connection.residence_mode() != SyncResidenceMode::Opened {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "FIXTURE: the machine that lost the home runs its owner's sync-opened \
                         choice"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert_eq!(
                    machine.unmarked(&held),
                    Vec::<WindowKey>::new(),
                    "a home that loses the election and runs its owner's sync-opened choice marks \
                     each held window for the residence upkeep to ask the home to retain"
                );
            })
            .await;
        },
    );
}

#[test]
fn a_former_home_that_starts_under_sync_opened_marks_its_held_windows_for_grants() {
    on_test_runtime(
        "a_former_home_that_starts_under_sync_opened_marks_its_held_windows_for_grants",
        || async {
            let machine = machine();
            // It held a full copy as the home and lost the election while it
            // was down: it starts under its owner's sync-opened choice.
            machine.choose_sync_opened();
            machine.mark_held();
            let held = machine.held_windows();
            let connection = machine.connection();
            assert_eq!(
                connection.residence_mode(),
                SyncResidenceMode::Opened,
                "FIXTURE: a machine that is not the home runs its owner's choice"
            );
            beside_running_connection(&connection, async {
                let deadline = tokio::time::Instant::now() + REFRESH_WAIT;
                while machine.holds() {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "FIXTURE: a machine that starts under sync opened withdraws the held \
                         mark it kept at its first residence refresh"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert_eq!(
                    machine.unmarked(&held),
                    Vec::<WindowKey>::new(),
                    "a former home that starts under sync opened with its held mark kept marks \
                     each held window for the residence upkeep to ask the home to retain"
                );
            })
            .await;
        },
    );
}
