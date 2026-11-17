#![cfg(all(unix, oneiron_test_support))]
//! The managed node follows the owner's kit-only fact (Engine RULING
//! WAYBACK-BOX-HOLD-FROM-DEVICE-SWITCH = A, 17 Nov 01:49; FIX
//! RECOVERY-BOX-HOLD-CLIENT-NOT-WIRED). A hosted vault's preset switch runs
//! on the owner's device, so the node reads the owner-signed fact the switch
//! appends and sends the matching hold through the supervisor relay: a new
//! fact once, an acknowledged fact never again in the process, a failed
//! hold again at the next look, nothing without a fact or while the vault
//! is paused, nothing once stopped, and every hold after the boot heal. The
//! boot heal sends the fact's choice over this install's own preset, and the
//! preset switch holds the box through the hosted client when it runs here,
//! but a `Standard` call on a vault already on `Standard` sends no release.
//! The same cadence reports the vault's recovery wait: once, again after a
//! refused report, never again while it is unchanged. A failed hold or
//! report forgets what the box acknowledged before it, so the earlier value
//! is sent again when the vault returns to it.
//!
//! Most tests pick the fact reader; one mints the owner-signed fact in a
//! real fold (OPUS-WAYBACK's #9270 door) and reads it with managed boot's
//! reader.
//!
//! Needs the doors (`--features oneiron/test-support` is for the steward
//! fixture, as in `recovery_box_boot_heal.rs`):
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test recovery_box_kit_only_watch`.

use std::collections::BTreeSet;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, CheckpointRootSigner, MachineRole, OwnerKeyEnrollment,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{CodeKeeping, KitIssue, PassphraseCost, PieceHome};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::recovery_box_kit_only_fact::append_recovery_box_kit_only_fact;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::{NoRecoveryBox, RecoveryBoxCanceller, RecoveryBoxHold, RecoveryPreset};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::test_doors::recovery_box_hold::{
    KitOnlyFact, KitOnlyFactRead, KitOnlyLook, WaitReport, close_heal_gate,
    fold_kit_only_fact_read, follow_kit_only_fact, heal_at_boot_reading, hold_client,
    kit_only_watch,
};

const VAULT: &str = "vault-7";
const BOUND: Duration = Duration::from_secs(5);
/// How long the test waits for a line the supervisor read: past `BOUND`, so
/// a look that sends nothing fails the test instead of hanging it.
const ANSWER: Duration = Duration::from_secs(15);

fn token() -> String {
    "c3".repeat(32)
}

/// An owner's vault with its data key held on this install's keystore, as in
/// `recovery_preset_nobody_but_me.rs`.
fn keyed_vault(path: &Path) -> Arc<Vault> {
    let vault = open_owner_carrier_vault(path).expect("owner vault");
    vault.ensure_vault_key().expect("mint the vault data key");
    Arc::new(vault)
}

fn fact(kit_only: bool, entry: u8) -> KitOnlyFact {
    KitOnlyFact {
        kit_only,
        entry: [entry; 32],
    }
}

/// What the test's fold answers.
#[derive(Clone, Copy)]
enum Fold {
    NoFact,
    Fact(KitOnlyFact),
    Unreadable,
}

/// A fact reader that answers what the test last set, and counts its reads.
struct TestFold {
    answer: Mutex<Fold>,
    reads: Mutex<usize>,
}

impl TestFold {
    fn new(answer: Fold) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(answer),
            reads: Mutex::new(0),
        })
    }

    fn set(&self, answer: Fold) {
        *self.answer.lock().expect("answer") = answer;
    }

    fn reads(&self) -> usize {
        *self.reads.lock().expect("reads")
    }

    fn reader(self: &Arc<Self>) -> KitOnlyFactRead {
        let fold = Arc::clone(self);
        Arc::new(
            move |_vault: &Vault| -> oneiron::Result<Option<KitOnlyFact>> {
                *fold.reads.lock().expect("reads") += 1;
                match *fold.answer.lock().expect("answer") {
                    Fold::NoFact => Ok(None),
                    Fold::Fact(fact) => Ok(Some(fact)),
                    Fold::Unreadable => Err(oneiron::Error::Io(std::io::Error::other(
                        "the fold did not read",
                    ))),
                }
            },
        )
    }
}

/// What the stub answers one connection with.
enum Script {
    /// `{"held":true}` at once.
    Held,
    /// The refusal line a supervisor answers a stale choice with.
    Refused,
}

/// A supervisor on a fresh socket that takes one connection per script
/// entry and serves each on its own thread: each reads one line, sends it
/// to the test, and answers as told. It ends once every entry is answered,
/// and its socket then reaches no one.
fn stub(
    script: Vec<Script>,
) -> (
    tempfile::TempDir,
    PathBuf,
    mpsc::Receiver<String>,
    JoinHandle<()>,
) {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("hypnos.sock");
    let listener = UnixListener::bind(&socket).expect("bind the supervisor socket");
    let (lines, incoming) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let mut served = Vec::new();
        for entry in script {
            let (stream, _) = listener.accept().expect("accept the vault");
            let lines = lines.clone();
            served.push(std::thread::spawn(move || serve(stream, entry, &lines)));
        }
        for connection in served {
            connection.join().expect("serve one connection");
        }
    });
    (dir, socket, incoming, handle)
}

/// One connection of the stub: its line to the test, then the answer.
fn serve(mut stream: UnixStream, entry: Script, lines: &mpsc::Sender<String>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone the stream"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("read the request");
    drop(reader);
    lines.send(line).expect("the test reads each line");
    let answer: &[u8] = match entry {
        Script::Held => br#"{"held":true}"#,
        Script::Refused => br#"{"held":false,"error":"stale_generation"}"#,
    };
    stream.write_all(answer).ok();
    stream.write_all(b"\n").ok();
}

fn expected_line(kit_only: bool) -> String {
    format!(
        "{{\"op\":\"recovery_box_kit_only\",\"vault\":\"{VAULT}\",\"token\":\"{}\",\"kit_only\":{kit_only}}}\n",
        token()
    )
}

/// The wait report's line: `recovery.wait` reads its 24-hour default until
/// the Setting lands.
fn expected_wait_line() -> String {
    format!(
        "{{\"op\":\"recovery_box_wait\",\"vault\":\"{VAULT}\",\"token\":\"{}\",\"wait_secs\":86400}}\n",
        token()
    )
}

/// A supervisor socket whose listener answers no call, nonblocking, so the
/// test can tell that nothing reached it.
fn silent_supervisor() -> (tempfile::TempDir, PathBuf, UnixListener) {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("hypnos.sock");
    let listener = UnixListener::bind(&socket).expect("bind the supervisor socket");
    listener.set_nonblocking(true).expect("nonblocking");
    (dir, socket, listener)
}

/// A nonblocking listener no call reached.
fn assert_no_call(listener: &UnixListener) {
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("no call reaches the supervisor, got {other:?}"),
    }
}

/// Binds a silent, nonblocking listener on `socket` again once the stub that
/// held it has ended, so the test can tell that no later call reached it.
fn rebind_silent(socket: &Path) -> UnixListener {
    std::fs::remove_file(socket).expect("remove the ended stub's socket");
    let listener = UnixListener::bind(socket).expect("bind the supervisor socket again");
    listener.set_nonblocking(true).expect("nonblocking");
    listener
}

#[test]
fn a_new_kit_only_fact_holds_the_box_once() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::Fact(fact(true, 1)));
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), true, fold.reader());

    assert_eq!(watch.look(), KitOnlyLook::Held { kit_only: true });
    assert_eq!(
        lines.recv_timeout(ANSWER).expect("the hold's line"),
        expected_line(true)
    );
    supervisor.join().expect("supervisor");
    // the stub took its one connection, so a second send could not reach it
    assert_eq!(watch.look(), KitOnlyLook::Acknowledged);
    assert_eq!(watch.look(), KitOnlyLook::Acknowledged);
    assert_eq!(fold.reads(), 3, "each look reads the fact");
}

#[test]
fn a_fact_leaving_kit_only_releases_the_box() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::Fact(fact(true, 1)));
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held, Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), true, fold.reader());

    assert_eq!(watch.look(), KitOnlyLook::Held { kit_only: true });
    assert_eq!(
        lines.recv_timeout(ANSWER).expect("the hold's line"),
        expected_line(true)
    );
    fold.set(Fold::Fact(fact(false, 2)));
    assert_eq!(watch.look(), KitOnlyLook::Held { kit_only: false });
    assert_eq!(
        lines.recv_timeout(ANSWER).expect("the release's line"),
        expected_line(false)
    );
    supervisor.join().expect("supervisor");
    assert_eq!(watch.look(), KitOnlyLook::Acknowledged);
}

#[test]
fn a_new_entry_with_the_same_choice_is_sent_again() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::Fact(fact(true, 1)));
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held, Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), true, fold.reader());

    assert_eq!(watch.look(), KitOnlyLook::Held { kit_only: true });
    // a later switch into "Nobody but me" again (an any-two turn-on, a
    // re-entry): the box may have been released in between, so it is held
    // again
    fold.set(Fold::Fact(fact(true, 3)));
    assert_eq!(watch.look(), KitOnlyLook::Held { kit_only: true });
    for _ in 0..2 {
        assert_eq!(
            lines.recv_timeout(ANSWER).expect("the hold's line"),
            expected_line(true)
        );
    }
    supervisor.join().expect("supervisor");
}

#[test]
fn a_failed_hold_is_sent_again_at_the_next_look() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::Fact(fact(true, 1)));
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Refused, Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), true, fold.reader());

    assert_eq!(watch.look(), KitOnlyLook::Failed);
    assert_eq!(watch.look(), KitOnlyLook::Held { kit_only: true });
    for _ in 0..2 {
        assert_eq!(
            lines.recv_timeout(ANSWER).expect("the hold's line"),
            expected_line(true)
        );
    }
    supervisor.join().expect("supervisor");
    assert_eq!(watch.look(), KitOnlyLook::Acknowledged);
}

#[test]
fn a_failed_hold_forgets_the_acknowledged_fact() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::Fact(fact(true, 1)));
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held, Script::Refused, Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), true, fold.reader());

    assert_eq!(watch.look(), KitOnlyLook::Held { kit_only: true });
    // a release whose answer never came back: the box may have released
    fold.set(Fold::Fact(fact(false, 2)));
    assert_eq!(watch.look(), KitOnlyLook::Failed);
    // the act in force moves back to the fact the box acknowledged first
    fold.set(Fold::Fact(fact(true, 1)));
    assert_eq!(
        watch.look(),
        KitOnlyLook::Held { kit_only: true },
        "a failed hold may have reached the box, so the earlier fact is sent again"
    );
    for kit_only in [true, false, true] {
        assert_eq!(
            lines.recv_timeout(ANSWER).expect("the hold's line"),
            expected_line(kit_only)
        );
    }
    supervisor.join().expect("supervisor");
    assert_eq!(watch.look(), KitOnlyLook::Acknowledged);
}

#[test]
fn with_no_fact_the_watch_makes_no_call() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::NoFact);
    let (_dir, socket, listener) = silent_supervisor();
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), true, fold.reader());

    assert_eq!(watch.look(), KitOnlyLook::NoFact);
    assert_eq!(watch.look(), KitOnlyLook::NoFact);
    assert_no_call(&listener);
}

#[test]
fn a_paused_vault_reads_nothing_and_makes_no_call() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::Fact(fact(true, 1)));
    let (_dir, socket, listener) = silent_supervisor();
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), false, fold.reader());

    assert_eq!(watch.look(), KitOnlyLook::NotAdmitted);
    assert_eq!(fold.reads(), 0, "a paused vault is not read");
    assert_no_call(&listener);
}

#[test]
fn an_unreadable_fact_makes_no_call_and_is_read_again() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::Unreadable);
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), true, fold.reader());

    assert_eq!(watch.look(), KitOnlyLook::Unreadable);
    assert!(
        matches!(
            lines.recv_timeout(Duration::from_millis(500)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "an unreadable fact sends nothing"
    );
    fold.set(Fold::Fact(fact(false, 1)));
    assert_eq!(watch.look(), KitOnlyLook::Held { kit_only: false });
    assert_eq!(
        lines.recv_timeout(ANSWER).expect("the hold's line"),
        expected_line(false)
    );
    supervisor.join().expect("supervisor");
}

#[test]
fn a_look_waits_for_the_boot_heal_and_sends_nothing_past_its_bound() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::Fact(fact(true, 1)));
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), Duration::from_secs(1));
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), true, fold.reader());

    let gate = close_heal_gate(&client);
    assert_eq!(
        watch.look(),
        KitOnlyLook::Failed,
        "a look the heal holds past its bound fails"
    );
    assert!(
        matches!(
            lines.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "nothing was sent while the heal held the gate"
    );
    drop(gate);
    assert_eq!(watch.look(), KitOnlyLook::Held { kit_only: true });
    assert_eq!(
        lines.recv_timeout(ANSWER).expect("the hold's line"),
        expected_line(true)
    );
    supervisor.join().expect("supervisor");
}

#[test]
fn the_boot_heal_sends_the_facts_choice_over_this_installs_preset() {
    struct FailsToRelease;
    impl RecoveryBoxHold for FailsToRelease {
        fn hold_kit_only(&self, kit_only: bool) -> oneiron::Result<()> {
            if kit_only {
                Ok(())
            } else {
                Err(oneiron::Error::Io(std::io::Error::other(
                    "the box is unreachable",
                )))
            }
        }

        fn report_recovery_wait(&self, _wait: Duration) -> oneiron::Result<()> {
            Ok(())
        }

        fn cancel_pending_box_release(
            &self,
            _cancelled_by: &RecoveryBoxCanceller,
            _release_receipt: Option<u64>,
        ) -> oneiron::Result<bool> {
            Ok(false)
        }
    }

    // this install's preset reads `Standard` with a marker left, as on a
    // managed node, whose own preset never leaves `Standard`
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    vault
        .set_recovery_preset_as(
            &owner_proof,
            RecoveryPreset::NobodyButMe,
            |_| Ok(()),
            &NoRecoveryBox,
        )
        .expect("enter the preset");
    vault
        .set_recovery_preset_as(
            &owner_proof,
            RecoveryPreset::Standard,
            |_| panic!("leaving the preset draws no sheet"),
            &FailsToRelease,
        )
        .expect("leaving answers");
    assert!(
        vault.recovery_box_hold_pending().expect("marker").is_some(),
        "the failed release leaves the marker"
    );
    assert_eq!(
        vault.recovery_preset().expect("preset"),
        RecoveryPreset::Standard
    );

    // the owner's fact says kit-only: the heal holds, where the preset alone
    // would release
    let fold = TestFold::new(Fold::Fact(fact(true, 1)));
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let heal = heal_at_boot_reading(&client, Arc::clone(&vault), true, fold.reader())
        .expect("the boot starts the heal");
    assert_eq!(
        lines.recv_timeout(ANSWER).expect("the heal's line"),
        expected_line(true)
    );
    heal.join().expect("the heal ends");
    supervisor.join().expect("supervisor");
    assert_eq!(vault.recovery_box_hold_pending().expect("marker"), None);
}

#[test]
fn the_preset_switch_holds_and_releases_the_box_through_the_hosted_client() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held, Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    // what the preset route passes on a hosted vault
    let box_hold: &dyn RecoveryBoxHold = &client;

    vault
        .set_recovery_preset_as(
            &owner_proof,
            RecoveryPreset::NobodyButMe,
            |_| Ok(()),
            box_hold,
        )
        .expect("enter the preset");
    assert_eq!(
        lines.recv_timeout(ANSWER).expect("the hold's line"),
        expected_line(true)
    );
    assert_eq!(
        vault.recovery_preset().expect("preset"),
        RecoveryPreset::NobodyButMe
    );

    let left = vault
        .set_recovery_preset_as(
            &owner_proof,
            RecoveryPreset::Standard,
            |_| panic!("leaving the preset draws no sheet"),
            box_hold,
        )
        .expect("leave the preset");
    assert!(!left.box_release_pending, "the box released");
    assert_eq!(
        lines.recv_timeout(ANSWER).expect("the release's line"),
        expected_line(false)
    );
    supervisor.join().expect("supervisor");
    assert_eq!(vault.recovery_box_hold_pending().expect("marker"), None);
}

#[test]
fn the_cadence_looks_at_once_follows_a_new_fact_and_ends_at_shutdown() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::Fact(fact(true, 1)));
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held, Script::Held, Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let watch = {
        let _entered = runtime.enter();
        follow_kit_only_fact(
            &client,
            Arc::clone(&vault),
            fold.reader(),
            Duration::from_millis(100),
            async move {
                let _ = stopped.await;
            },
        )
    };

    assert_eq!(
        lines.recv_timeout(ANSWER).expect("the first look's line"),
        expected_line(true)
    );
    fold.set(Fold::Fact(fact(false, 2)));
    assert_eq!(
        lines
            .recv_timeout(ANSWER)
            .expect("the first look's wait report"),
        expected_wait_line()
    );
    assert_eq!(
        lines.recv_timeout(ANSWER).expect("a later look's line"),
        expected_line(false)
    );
    supervisor.join().expect("supervisor");
    // The acknowledged fact and the wait the box took are never sent again:
    // no call over three more looks.
    let silent = rebind_silent(&socket);
    std::thread::sleep(Duration::from_millis(350));
    assert_no_call(&silent);
    stop.send(()).expect("stop the watch");
    runtime
        .block_on(async { tokio::time::timeout(ANSWER, watch).await })
        .expect("the watch ends at shutdown")
        .expect("the watch task ends cleanly");
}

#[test]
fn a_watch_stopped_before_its_first_look_reads_and_sends_nothing() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::Fact(fact(true, 1)));
    let (_dir, socket, listener) = silent_supervisor();
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let watch = {
        let _entered = runtime.enter();
        follow_kit_only_fact(
            &client,
            Arc::clone(&vault),
            fold.reader(),
            Duration::from_millis(100),
            std::future::ready(()),
        )
    };

    runtime
        .block_on(async { tokio::time::timeout(ANSWER, watch).await })
        .expect("the watch ends")
        .expect("the watch task ends cleanly");
    assert_eq!(fold.reads(), 0, "a stopped watch reads no fact");
    assert_no_call(&listener);
}

#[test]
fn a_standard_call_on_a_standard_vault_sends_no_release_through_the_hosted_client() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    let (_dir, socket, listener) = silent_supervisor();
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    // what the preset route passes on a hosted vault, whose own preset
    // always reads Standard
    let box_hold: &dyn RecoveryBoxHold = &client;
    assert_eq!(
        vault.recovery_preset().expect("preset"),
        RecoveryPreset::Standard
    );

    let change = vault
        .set_recovery_preset_as(
            &owner_proof,
            RecoveryPreset::Standard,
            |_| panic!("staying on Standard draws no sheet"),
            box_hold,
        )
        .expect("staying on Standard");
    assert!(
        !change.box_release_pending,
        "no release was asked, so none is pending"
    );
    assert_no_call(&listener);
    assert_eq!(vault.recovery_box_hold_pending().expect("marker"), None);
}

#[test]
fn the_wait_report_goes_once_again_after_a_refusal_and_never_while_unchanged() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::NoFact);
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Refused, Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), true, fold.reader());

    assert_eq!(watch.report_wait(), WaitReport::Failed);
    assert_eq!(
        watch.report_wait(),
        WaitReport::Reported { wait_secs: 86_400 },
        "a refused report goes again"
    );
    for _ in 0..2 {
        assert_eq!(
            lines.recv_timeout(ANSWER).expect("the report's line"),
            expected_wait_line()
        );
    }
    supervisor.join().expect("supervisor");
    let silent = rebind_silent(&socket);
    assert_eq!(watch.report_wait(), WaitReport::Unchanged);
    assert_eq!(watch.report_wait(), WaitReport::Unchanged);
    assert_no_call(&silent);
}

#[test]
fn a_failed_wait_report_forgets_the_wait_the_box_took() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::NoFact);
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Refused, Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), true, fold.reader());
    // the box took a one-hour wait earlier in this process, and the vault's
    // wait changed since
    let earlier = Duration::from_secs(3_600);
    watch.set_reported_wait(earlier);

    assert_eq!(watch.report_wait(), WaitReport::Failed);
    assert_eq!(
        watch.reported_wait(),
        None,
        "a failed report may have reached the box, so the watch no longer holds the earlier wait as the box's"
    );
    assert_eq!(
        watch.report_wait(),
        WaitReport::Reported { wait_secs: 86_400 }
    );
    for _ in 0..2 {
        assert_eq!(
            lines.recv_timeout(ANSWER).expect("the report's line"),
            expected_wait_line()
        );
    }
    supervisor.join().expect("supervisor");
    assert_eq!(watch.reported_wait(), Some(Duration::from_secs(86_400)));
}

#[test]
fn a_paused_vault_reports_no_wait() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let fold = TestFold::new(Fold::NoFact);
    let (_dir, socket, listener) = silent_supervisor();
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), false, fold.reader());

    assert_eq!(watch.report_wait(), WaitReport::NotAdmitted);
    assert_no_call(&listener);
}

// The owner-signed fact in a real fold (#9270): minted as oneiron's
// `tests/kit_only_authority_rotation.rs` mints it, read with managed boot's
// reader.

/// Seed of the owner device key the vault handle holds to prove the fact.
const PROVING_KEY_SEED: u8 = 61;

/// An owner device key held on the vault handle: what an owner act's proof
/// is signed with, as on the owner's device.
struct KeySigner(SigningKey);

impl CheckpointRootSigner for KeySigner {
    fn root(&self) -> AuthorityKey {
        AuthorityKey::Ed25519(self.0.verifying_key().to_bytes())
    }

    fn sign_checkpoint_statement(&self, statement: &[u8]) -> oneiron::Result<Vec<u8>> {
        Ok(self.0.sign(statement).to_bytes().to_vec())
    }

    fn sign_owner_proof(&self, transcript: &[u8]) -> oneiron::Result<Vec<u8>> {
        Ok(self.0.sign(transcript).to_bytes().to_vec())
    }
}

fn owner_proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// A vault whose fold can hold the owner's kit-only fact: rooted under a host
/// root with its world kit confirmed, and an owner device key enrolled and
/// held on this handle, as oneiron's `tests/kit_only_authority_rotation.rs`
/// builds it. Answers the vault and its owner.
fn vault_proving_owner_acts(path: &Path) -> (Arc<Vault>, EntityId) {
    let vault = Vault::open(path, VaultConfig::device()).expect("the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("the host seed");
    vault.ensure_host_root_slip(&issuer).expect("the host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machines");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    vault.ensure_vault_key().expect("the data key");
    let machine = vault
        .prepare_install_signing()
        .expect("this install's machine");
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    let issued = vault
        .issue_world_kit(
            &owner_proof(&vault, person),
            &KitIssue {
                vault_id,
                homes: [
                    PieceHome::RecoveryCode(CodeKeeping::Paper),
                    PieceHome::TrustedPerson,
                    PieceHome::SecurityKey,
                ],
                passphrase: None,
                cost: PassphraseCost::FLOOR,
                only_machine: false,
            },
        )
        .expect("a kit");
    let refs: Vec<_> = issued.pieces.iter().take(2).collect();
    vault
        .confirm_world_kit(&owner_proof(&vault, person), &refs, None, &BTreeSet::new())
        .expect("the kit confirms");
    let key = SigningKey::from_bytes(&[PROVING_KEY_SEED; 32]);
    let authority = ActAuthority::Owner(owner_proof(&vault, person), ActSurface::ThisInstall);
    let public_key = key.verifying_key().to_bytes();
    let challenge = vault
        .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
        .expect("the challenge");
    vault
        .enrol_owner_signing_key_as_host(
            &authority,
            OwnerKeyEnrollment {
                machine,
                public_key,
                proof: key.sign(&challenge).to_bytes().to_vec(),
            },
            &issuer,
        )
        .expect("the owner enrols a device key");
    vault.hold_checkpoint_root_signer(Arc::new(KeySigner(key)));
    (Arc::new(vault), person)
}

#[test]
fn the_folds_kit_only_fact_holds_and_releases_the_box() {
    let directory = tempfile::tempdir().expect("temp dir");
    let (vault, person) = vault_proving_owner_acts(directory.path());
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held, Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let mut watch = kit_only_watch(&client, Arc::clone(&vault), true, fold_kit_only_fact_read());

    assert_eq!(
        watch.look(),
        KitOnlyLook::NoFact,
        "a vault whose owner never switched holds no fact"
    );
    append_recovery_box_kit_only_fact(&vault, &owner_proof(&vault, person), true)
        .expect("the owner's device signs kit-only on");
    assert_eq!(watch.look(), KitOnlyLook::Held { kit_only: true });
    assert_eq!(
        lines.recv_timeout(ANSWER).expect("the hold's line"),
        expected_line(true)
    );
    assert_eq!(watch.look(), KitOnlyLook::Acknowledged);
    append_recovery_box_kit_only_fact(&vault, &owner_proof(&vault, person), false)
        .expect("the owner's device signs kit-only off");
    assert_eq!(watch.look(), KitOnlyLook::Held { kit_only: false });
    assert_eq!(
        lines.recv_timeout(ANSWER).expect("the release's line"),
        expected_line(false)
    );
    supervisor.join().expect("supervisor");
}
