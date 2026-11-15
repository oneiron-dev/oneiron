//! L7-47 (CROSS-ARCH-0024 `#my-network` item 04: "A full copy earns
//! roles. It is a live backup and a standby home."): a machine's full-copy
//! mark follows the residence mode the owner's stored choice and the
//! committed home resolve to, never a mode the connection ran before.
//!
//! - A machine that loses the home election and falls back to its owner's
//!   stored sync-opened choice withdraws its mark
//!   (FIX FULL-COPY-MARK-ELECTION-OPENED).
//! - A machine that starts under sync opened withdraws a held mark it kept.
//! - A first round that ran sync all writes no mark once the owner's switch
//!   to sync opened has landed (FIX FULL-COPY-MARK-FIRST-ROUND-RACE); the
//!   elected home's first round still marks it held, whatever its owner
//!   chose, because the home always runs sync all.
//!
//! The fixture is one owned vault with this install profiled as the owner's
//! own machine. The connection tests run the machine's own-device connection
//! with its home unreachable: its residence refresh runs beside the connects
//! that fail. It reaches the crate-private doors through
//! `oneiron::test_doors::full_copy_mark`, so it runs only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test full_copy_mark_follows_mode`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use oneiron::authority::{HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::dreamer_runner::{DreamerHomeNodeCandidate, DreamerRunnerStore};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::residence::{local_is_elected_home, set_device_sync_preference};
use oneiron::sync::{SyncClientConfig, SyncResidenceMode};
use oneiron::test_doors::full_copy_mark::{holds_full_copy, mark_first_round_full_copy};
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
    let issuer = HostSlipIssuer::from_secret(b"full copy mark follows mode test host")
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

    /// This machine's own-device connection, its home unreachable and its
    /// reconnects a minute apart.
    fn connection(&self) -> SyncConnection {
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&self.vault),
            Arc::new(Materializer::new()),
            "full-copy-mark-follows-mode",
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
fn a_machine_that_loses_the_home_withdraws_its_mark() {
    on_test_runtime(
        "a_machine_that_loses_the_home_withdraws_its_mark",
        || async {
            let machine = machine();
            machine.elect_home(true);
            // The owner chose sync opened while this machine was the home: no
            // switch, since the elected home runs sync all whatever was chosen.
            machine.choose_sync_opened();
            machine.mark_held();
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
                    "FIXTURE: the machine that lost the home runs its owner's sync-opened choice"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                !machine.holds(),
                "a machine that lost the home and runs its owner's sync-opened choice holds \
                 no full-copy mark"
            );
        })
        .await;
        },
    );
}

#[test]
fn a_machine_that_starts_under_sync_opened_withdraws_a_kept_mark() {
    on_test_runtime(
        "a_machine_that_starts_under_sync_opened_withdraws_a_kept_mark",
        || async {
            let machine = machine();
            machine.choose_sync_opened();
            machine.mark_held();
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
                        "a machine that starts under sync opened withdraws the held mark it \
                         kept at its first residence refresh"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await;
        },
    );
}

#[test]
fn a_first_round_writes_no_mark_after_a_switch_to_sync_opened() {
    let machine = machine();
    // The round ran sync all, the mode its connect took; the owner's switch
    // to sync opened landed while it ran.
    machine.choose_sync_opened();
    assert!(
        mark_first_round_full_copy(&machine.vault, SyncResidenceMode::Opened)
            .expect("the first round's mark write answers")
            .is_none(),
        "a first round that ran sync all writes no mark once the owner's switch to sync \
         opened has landed"
    );
    assert!(
        !machine.holds(),
        "the machine runs sync opened and holds no full-copy mark"
    );
}

#[test]
fn the_homes_first_round_marks_it_held_whatever_its_owner_chose() {
    let machine = machine();
    machine.elect_home(true);
    machine.choose_sync_opened();
    assert!(
        mark_first_round_full_copy(&machine.vault, SyncResidenceMode::Opened)
            .expect("the first round's mark write answers")
            .is_some(),
        "the elected home runs sync all, so its first round writes its held mark"
    );
    assert!(
        machine.holds(),
        "the elected home holds a full copy once its first round completes"
    );
}
