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
//!
//! The fact reader is the test's: the fold's reader comes with the switch's
//! fact (OPUS-WAYBACK's fact PR).
//!
//! Needs the doors (`--features oneiron/test-support` is for the steward
//! fixture, as in `recovery_box_boot_heal.rs`):
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test recovery_box_kit_only_watch`.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use oneiron::Vault;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::world_keys::{NoRecoveryBox, RecoveryBoxHold, RecoveryPreset};
use oneiron_server::test_doors::recovery_box_hold::{
    KitOnlyFact, KitOnlyFactRead, KitOnlyLook, close_heal_gate, follow_kit_only_fact,
    heal_at_boot_reading, hold_client, kit_only_watch,
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
    }

        fn report_recovery_wait(&self, _wait: Duration) -> oneiron::Result<()> {
            Ok(())
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
    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held, Script::Held]);
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
        lines.recv_timeout(ANSWER).expect("a later look's line"),
        expected_line(false)
    );
    supervisor.join().expect("supervisor");
    // The acknowledged fact is never sent again: no call over three more looks.
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
