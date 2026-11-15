#![cfg(all(unix, oneiron_test_support))]
//! The recovery box's boot heal (Engine RULING WAYBACK-BOX-HOLD-BOOT-HEAL = D,
//! 16 Nov 01:42): a switch the last run did not finish leaves the
//! box-hold-pending marker, and the next boot resends the hold matching the
//! CURRENT preset, once, on its own thread; the heal clears the marker only
//! for the attempt it read, and a switch's hold waits for the heal within
//! the same bound. A death between `hold(true)` and the commit heals to the
//! preset in force, a failed `hold(false)` heals too, and no marker means
//! no call.
//!
//! Needs the doors (`--features oneiron/test-support` is for the steward
//! fixture, as in `hosted_import_verbs.rs`):
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test recovery_box_boot_heal`.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::world_keys::{NoRecoveryBox, RecoveryBoxHold, RecoveryBoxHoldPending, RecoveryPreset};
use oneiron_server::test_doors::recovery_box_hold::{close_heal_gate, heal_at_boot, hold_client};

const VAULT: &str = "vault-7";
const BOUND: Duration = Duration::from_secs(5);

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

/// A vault on `Standard` whose last switch's release failed: the marker is
/// `{false, _}` and the box still holds kit-only.
fn failed_release(path: &Path) -> (Arc<Vault>, AuthenticatedOwner, RecoveryBoxHoldPending) {
    let vault = keyed_vault(path);
    let owner_proof = owner(&vault).expect("owner proof");
    vault
        .set_recovery_preset_as(
            &owner_proof,
            RecoveryPreset::NobodyButMe,
            |_| Ok(()),
            &NoRecoveryBox,
        )
        .expect("enter the preset");
    let left = vault
        .set_recovery_preset_as(
            &owner_proof,
            RecoveryPreset::Standard,
            |_| panic!("leaving the preset draws no sheet"),
            &FailsToRelease,
        )
        .expect("leaving answers");
    assert!(left.box_release_pending, "the failed release is pending");
    let marker = vault
        .recovery_box_hold_pending()
        .expect("read the marker")
        .expect("the marker stays");
    assert!(!marker.target_kit_only, "{marker:?}");
    (vault, owner_proof, marker)
}

/// The box holds, then the process dies before the switch commits.
struct DiesAfterHolding {
    calls: Mutex<Vec<bool>>,
}

impl RecoveryBoxHold for DiesAfterHolding {
    fn hold_kit_only(&self, kit_only: bool) -> oneiron::Result<()> {
        self.calls.lock().expect("calls").push(kit_only);
        panic!("the process dies after the box held");
    }
}

/// The box holds but never releases.
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

/// The box refuses a new hold but releases.
struct RefusesToHold;

impl RecoveryBoxHold for RefusesToHold {
    fn hold_kit_only(&self, kit_only: bool) -> oneiron::Result<()> {
        if kit_only {
            Err(oneiron::Error::Io(std::io::Error::other(
                "the box refused the hold",
            )))
        } else {
            Ok(())
        }
    }
}

/// What the stub answers one connection with.
enum Script {
    /// `{"held":true}` at once.
    Held,
    /// The refusal line a supervisor answers a stale choice with.
    Refused,
    /// Held, but only after the test sends the go signal.
    HeldAfter(mpsc::Receiver<()>),
}

/// A supervisor on a fresh socket that takes one connection per script
/// entry, reads one line from each, sends each line to the test, and
/// answers as told; it ends after the last entry.
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
        for entry in script {
            let (stream, _) = listener.accept().expect("accept the vault");
            let mut reader = BufReader::new(stream.try_clone().expect("clone the stream"));
            let mut line = String::new();
            reader.read_line(&mut line).expect("read the request");
            // the clone holds the connection open too: dropping it leaves
            // the answer's stream the only one open
            drop(reader);
            lines.send(line).expect("the test reads each line");
            let mut stream = stream;
            match entry {
                Script::Held => {
                    stream.write_all(br#"{"held":true}"#).ok();
                    stream.write_all(b"\n").ok();
                }
                Script::Refused => {
                    stream
                        .write_all(br#"{"held":false,"error":"stale_generation"}"#)
                        .ok();
                    stream.write_all(b"\n").ok();
                }
                Script::HeldAfter(go) => {
                    go.recv().expect("the test sends go");
                    stream.write_all(br#"{"held":true}"#).ok();
                    stream.write_all(b"\n").ok();
                }
            }
        }
    });
    (dir, socket, incoming, handle)
}

fn expected_line(kit_only: bool) -> String {
    format!(
        "{{\"op\":\"recovery_box_kit_only\",\"vault\":\"{VAULT}\",\"token\":\"{}\",\"kit_only\":{kit_only}}}\n",
        token()
    )
}

/// A nonblocking listener no call reached.
fn assert_no_call(listener: &UnixListener) {
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("no call reaches the supervisor, got {other:?}"),
    }
}

#[test]
fn a_death_after_the_box_held_heals_to_the_standard_preset_at_the_next_boot() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    let held = DiesAfterHolding {
        calls: Mutex::new(Vec::new()),
    };
    let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vault.set_recovery_preset_as(&owner_proof, RecoveryPreset::NobodyButMe, |_| Ok(()), &held)
    }));
    assert!(died.is_err(), "the switch dies after the box held");
    assert_eq!(*held.calls.lock().expect("calls"), [true]);
    let marker = vault.recovery_box_hold_pending().expect("read the marker");
    assert!(
        matches!(marker, Some(pending) if pending.target_kit_only),
        "{marker:?}"
    );
    assert_eq!(
        vault.recovery_preset().expect("preset"),
        RecoveryPreset::Standard
    );

    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let heal = heal_at_boot(&client, Arc::clone(&vault), true);
    assert!(heal.is_some(), "the boot starts the heal");
    // the CURRENT preset, not the marker's target
    assert_eq!(lines.recv().expect("the heal's line"), expected_line(false));
    heal.expect("heal").join().expect("the heal ends");
    supervisor.join().expect("supervisor");
    assert_eq!(vault.recovery_box_hold_pending().expect("marker"), None);
}

#[test]
fn a_failed_release_heals_at_the_next_boot() {
    let directory = tempfile::tempdir().expect("temp dir");
    let (vault, _owner, marker) = failed_release(&directory.path().join("vault"));
    assert!(!marker.target_kit_only, "{marker:?}");

    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let heal = heal_at_boot(&client, Arc::clone(&vault), true);
    assert!(heal.is_some(), "the boot starts the heal");
    assert_eq!(lines.recv().expect("the heal's line"), expected_line(false));
    heal.expect("heal").join().expect("the heal ends");
    supervisor.join().expect("supervisor");
    assert_eq!(vault.recovery_box_hold_pending().expect("marker"), None);
}

#[test]
fn a_death_under_nobody_but_me_holds_the_box_again_at_the_next_boot() {
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
    let held = DiesAfterHolding {
        calls: Mutex::new(Vec::new()),
    };
    let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vault.set_recovery_preset_as(
            &owner_proof,
            RecoveryPreset::NobodyButMe,
            |_| panic!("the preset in force draws no sheet to keep"),
            &held,
        )
    }));
    assert!(died.is_err(), "the switch dies after the box held");
    assert_eq!(*held.calls.lock().expect("calls"), [true]);
    let marker = vault.recovery_box_hold_pending().expect("read the marker");
    assert!(
        matches!(marker, Some(pending) if pending.target_kit_only),
        "{marker:?}"
    );
    assert_eq!(
        vault.recovery_preset().expect("preset"),
        RecoveryPreset::NobodyButMe
    );

    let (_dir, socket, lines, supervisor) = stub(vec![Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let heal = heal_at_boot(&client, Arc::clone(&vault), true);
    assert!(heal.is_some(), "the boot starts the heal");
    assert_eq!(lines.recv().expect("the heal's line"), expected_line(true));
    heal.expect("heal").join().expect("the heal ends");
    supervisor.join().expect("supervisor");
    assert_eq!(vault.recovery_box_hold_pending().expect("marker"), None);
}

#[test]
fn with_no_marker_the_boot_makes_no_call() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = keyed_vault(&directory.path().join("vault"));
    assert_eq!(vault.recovery_box_hold_pending().expect("marker"), None);
    let socket_dir = tempfile::tempdir().expect("temp dir");
    let socket = socket_dir.path().join("hypnos.sock");
    let listener = UnixListener::bind(&socket).expect("bind the supervisor socket");
    listener.set_nonblocking(true).expect("nonblocking");
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    assert!(
        heal_at_boot(&client, Arc::clone(&vault), true).is_none(),
        "no marker starts no heal"
    );
    assert_no_call(&listener);
}

#[test]
fn a_failed_heal_keeps_the_marker() {
    let directory = tempfile::tempdir().expect("temp dir");
    let (vault, _owner, before) = failed_release(&directory.path().join("vault"));

    let (_dir, socket, lines, supervisor) = stub(vec![Script::Refused]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let heal = heal_at_boot(&client, Arc::clone(&vault), true);
    assert!(heal.is_some(), "the boot starts the heal");
    assert_eq!(lines.recv().expect("the heal's line"), expected_line(false));
    heal.expect("heal").join().expect("the heal ends");
    supervisor.join().expect("supervisor");
    assert_eq!(
        vault.recovery_box_hold_pending().expect("marker"),
        Some(before)
    );
}

#[test]
fn a_heal_never_clears_a_newer_switchs_marker() {
    let directory = tempfile::tempdir().expect("temp dir");
    let (vault, owner_proof, before) = failed_release(&directory.path().join("vault"));
    let (go, wait) = mpsc::channel::<()>();
    let (_dir, socket, lines, supervisor) = stub(vec![Script::HeldAfter(wait)]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let heal = heal_at_boot(&client, Arc::clone(&vault), true).expect("the boot starts the heal");
    // the heal sent, so it read `before`
    assert_eq!(lines.recv().expect("the heal's line"), expected_line(false));
    // a newer switch overwrites the marker, then fails its own hold
    let refused = vault
        .set_recovery_preset_as(
            &owner_proof,
            RecoveryPreset::NobodyButMe,
            |_| Ok(()),
            &RefusesToHold,
        )
        .expect_err("the newer switch is refused")
        .to_string();
    assert!(refused.contains("the box refused the hold"), "{refused}");
    let newer = vault.recovery_box_hold_pending().expect("read the marker");
    assert!(
        matches!(newer, Some(pending) if pending.target_kit_only && pending.attempt != before.attempt),
        "{newer:?}"
    );
    go.send(()).expect("go");
    heal.join().expect("the heal ends");
    supervisor.join().expect("supervisor");
    assert_eq!(vault.recovery_box_hold_pending().expect("marker"), newer);
}

#[test]
fn a_switch_hold_waits_for_the_boot_heal() {
    let directory = tempfile::tempdir().expect("temp dir");
    let (vault, _owner, _marker) = failed_release(&directory.path().join("vault"));
    let (go, wait) = mpsc::channel::<()>();
    let (_dir, socket, lines, supervisor) = stub(vec![Script::HeldAfter(wait), Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let heal = heal_at_boot(&client, Arc::clone(&vault), true).expect("the boot starts the heal");
    let first = lines.recv().expect("the heal's line");
    let held = std::thread::spawn(move || client.hold_kit_only(true));
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        matches!(lines.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "the switch sends nothing while the heal is in flight"
    );
    assert!(!held.is_finished(), "the switch waits for the heal");
    go.send(()).expect("go");
    let second = lines
        .recv_timeout(Duration::from_secs(15))
        .expect("the switch's line");
    assert_eq!(second, expected_line(true));
    held.join()
        .expect("the switch ends")
        .expect("the switch holds after the heal");
    assert_eq!(first, expected_line(false));
    heal.join().expect("the heal ends");
    supervisor.join().expect("supervisor");
    assert_eq!(vault.recovery_box_hold_pending().expect("marker"), None);
}

#[test]
fn a_hold_that_waits_past_its_bound_for_the_heal_fails_with_nothing_sent() {
    let directory = tempfile::tempdir().expect("temp dir");
    let socket = directory.path().join("hypnos.sock");
    let listener = UnixListener::bind(&socket).expect("bind the supervisor socket");
    listener.set_nonblocking(true).expect("nonblocking");
    let client = hold_client(&socket, VAULT, &token(), Duration::from_millis(300));
    let gate = close_heal_gate(&client);
    let error = client
        .hold_kit_only(true)
        .expect_err("a hold past its bound fails")
        .to_string();
    assert!(error.contains("boot heal"), "{error}");
    assert_no_call(&listener);
    drop(gate);
    // the gate open again, a held answer is Ok
    let (_dir, socket, _lines, supervisor) = stub(vec![Script::Held]);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    client.hold_kit_only(false).expect("a held answer is Ok");
    supervisor.join().expect("supervisor");
}

#[test]
fn under_the_reap_pause_the_boot_sends_nothing_and_keeps_the_marker() {
    let directory = tempfile::tempdir().expect("temp dir");
    let (vault, _owner, marker) = failed_release(&directory.path().join("vault"));
    let socket_dir = tempfile::tempdir().expect("temp dir");
    let socket = socket_dir.path().join("hypnos.sock");
    let listener = UnixListener::bind(&socket).expect("bind the supervisor socket");
    listener.set_nonblocking(true).expect("nonblocking");
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    assert!(
        heal_at_boot(&client, Arc::clone(&vault), false).is_none(),
        "a refused admission starts no heal"
    );
    assert_no_call(&listener);
    assert_eq!(
        vault.recovery_box_hold_pending().expect("marker"),
        Some(marker)
    );
}
