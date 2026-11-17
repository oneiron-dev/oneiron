//! A flip back and a close drain a base write that passed its last route check.
//! ARCH-0052 #d5-proof-open.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, TryLockError, mpsc};
use std::time::{Duration, Instant};

use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::off_record::{OffRecordBackendClass, OffRecordMode, OffRecordSession};
use crate::{EdgeActorClass, Vault, VaultConfig};

fn base_entity_count(vault: &Vault) -> u64 {
    let rtxn = vault.store.env.read_txn().expect("read base entities");
    vault.store.entities.len(&rtxn).expect("base entity count")
}

fn witness(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    proof: &AuthenticatedOwner,
    content: &str,
    occurred_at: u64,
) -> std::result::Result<(), String> {
    vault
        .memory(proof.actor(), EdgeActorClass::Human)
        .witness_into_session_as(
            proof,
            session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                thread_audience: None,
                messages: vec![WitnessMessage {
                    id: None,
                    author: WitnessAuthor::User,
                    message_type: "text".to_owned(),
                    content: content.to_owned(),
                    parts: None,
                    metadata: None,
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at,
                assertions: Default::default(),
            },
            None,
            None,
        )
        .map(|_| ())
        .map_err(|error| format!("{error:?}"))
}

fn with_on_record_session<T>(
    run: impl FnOnce(&Vault, &OffRecordSession<'_>, &AuthenticatedOwner) -> T,
) -> T {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let proof = crate::test_util::embedded_owner_proof(&vault);
    let session = vault
        .off_record_session_vault()
        .enter("flip-drain-session", OffRecordBackendClass::Local)
        .expect("enter the stretch");
    session.flip_on_record_as(&proof).expect("put on record");

    // Allocate the continuation shell before arming the hook. The next
    // witness then reaches the hook in the write that carries its turn.
    let before = base_entity_count(&vault);
    witness(&vault, &session, &proof, "The first observation.", 100).expect("warm-up witness");
    assert!(
        base_entity_count(&vault) > before,
        "the warm-up lands in base"
    );
    run(&vault, &session, &proof)
}

#[derive(Clone, Copy)]
enum Act {
    FlipBack,
    Close,
    /// The flip back, run inside a write on another vault.
    FlipBackInsideAnotherVaultsWrite,
    /// A second flip back, run once a first one has published `OffRecord`
    /// and waits for the held write.
    RepeatFlipBack,
    /// The close, run once a flip back has published `OffRecord` and waits
    /// for the held write.
    CloseDuringFlipBack,
}

impl Act {
    fn run(self, vault: &Vault, other: &Vault, session_ref: &str) -> Result<()> {
        match self {
            Self::FlipBack | Self::RepeatFlipBack => vault
                .set_off_record_session_mode(session_ref, OffRecordMode::OffRecord)
                .map(|_| ()),
            Self::Close | Self::CloseDuringFlipBack => vault
                .close_off_record_session(session_ref, vault.off_record_receipt_log(session_ref)?)
                .map(|_| ()),
            Self::FlipBackInsideAnotherVaultsWrite => other.with_write_txn(|_| {
                vault.set_off_record_session_mode(session_ref, OffRecordMode::OffRecord)?;
                Ok(())
            }),
        }
    }
}

/// How long a race gives its act to return before it releases the held
/// commit.
const ACT_WINDOW: Duration = Duration::from_secs(15);

struct RaceOutcome {
    witness: std::result::Result<(), String>,
    act_ok: bool,
    landed_when_the_act_returned: bool,
}

fn race(act: Act) -> RaceOutcome {
    let (done_tx, done_rx) = mpsc::channel();
    // A deadlock inside a scope also blocks its implicit joins while
    // unwinding. Keep the watchdog outside a detached driver instead.
    std::thread::spawn(move || {
        let (_other_dir, other) = crate::test_util::open_test_vault_with(VaultConfig::default());
        let other = &other;
        let outcome = with_on_record_session(|vault, session, proof| {
            let before = base_entity_count(vault);
            let (checked_tx, checked_rx) = mpsc::channel();
            let (go_tx, go_rx) = mpsc::channel();
            let go_rx = Mutex::new(go_rx);
            let armed = Arc::new(AtomicBool::new(true));
            vault
                .store
                .group_commit
                .hooks
                .on_before_commit(move |_ran: usize| {
                    if armed.swap(false, Ordering::SeqCst) {
                        checked_tx.send(()).expect("announce the checked witness");
                        go_rx
                            .lock()
                            .expect("commit release receiver")
                            .recv_timeout(Duration::from_secs(60))
                            .expect("release the witness commit");
                    }
                });

            std::thread::scope(|scope| {
                let writer =
                    scope.spawn(|| witness(vault, session, proof, "The second observation.", 101));
                checked_rx
                    .recv_timeout(Duration::from_secs(30))
                    .expect("the witness reached its commit");
                // The repeat and the close run once a first flip has
                // published and let go of the stretch's state lock.
                let first_flip = matches!(act, Act::RepeatFlipBack | Act::CloseDuringFlipBack)
                    .then(|| {
                        let flip = scope.spawn(|| {
                            vault
                                .set_off_record_session_mode(
                                    session.session_ref(),
                                    OffRecordMode::OffRecord,
                                )
                                .map(|_| ())
                        });
                        wait_for_the_published_flip_back(vault, session.session_ref());
                        flip
                    });
                let (act_tx, act_rx) = mpsc::channel();
                let acting = scope.spawn(move || {
                    let act_ok = act.run(vault, other, session.session_ref()).is_ok();
                    let count_when_the_act_returned = base_entity_count(vault);
                    act_tx
                        .send((act_ok, count_when_the_act_returned))
                        .expect("report the act's return");
                });
                // Main can return before the held commit. The head's drain
                // waits for it; release it after giving the act time to run.
                // The window is wide, so a slow host cannot turn a red green.
                let early = match act_rx.recv_timeout(ACT_WINDOW) {
                    Ok(outcome) => Some(outcome),
                    Err(mpsc::RecvTimeoutError::Timeout) => None,
                    Err(mpsc::RecvTimeoutError::Disconnected) => panic!("the act panicked"),
                };
                go_tx.send(()).expect("release the commit");
                let witness = writer.join().expect("the witness must not panic");
                acting.join().expect("the act must not panic");
                if let Some(flip) = first_flip {
                    flip.join()
                        .expect("the first flip back must not panic")
                        .expect("the first flip back returns");
                }
                let (act_ok, count_when_the_act_returned) =
                    early.unwrap_or_else(|| act_rx.recv().expect("the act returned"));
                RaceOutcome {
                    witness,
                    act_ok,
                    landed_when_the_act_returned: count_when_the_act_returned > before,
                }
            })
        });
        let _ = done_tx.send(outcome);
    });
    done_rx
        .recv_timeout(Duration::from_secs(180))
        .expect("the race stood still: a deadlock")
}

#[test]
fn a_flip_back_returns_only_after_a_base_write_that_passed_its_route_check_commits() {
    let outcome = race(Act::FlipBack);
    assert!(outcome.witness.is_ok(), "witness: {:?}", outcome.witness);
    assert!(outcome.act_ok, "the flip back failed");
    assert!(
        outcome.landed_when_the_act_returned,
        "the flip back returned before a base write that passed its route check committed"
    );
}

#[test]
fn a_close_on_record_returns_only_after_a_base_write_that_passed_its_route_check_commits() {
    let outcome = race(Act::Close);
    assert!(outcome.witness.is_ok(), "witness: {:?}", outcome.witness);
    assert!(outcome.act_ok, "the close failed");
    assert!(
        outcome.landed_when_the_act_returned,
        "the close returned before a base write that passed its route check committed"
    );
}

#[test]
fn a_flip_back_inside_another_vaults_write_waits_for_a_base_write_that_passed_its_route_check() {
    let outcome = race(Act::FlipBackInsideAnotherVaultsWrite);
    assert!(outcome.witness.is_ok(), "witness: {:?}", outcome.witness);
    assert!(
        outcome.act_ok,
        "the flip back inside another vault's write failed"
    );
    assert!(
        outcome.landed_when_the_act_returned,
        "the flip back inside another vault's write returned before a base write that passed its route check committed"
    );
}

/// Returns once a flip back has published `OffRecord` and let go of the
/// stretch's state lock.
fn wait_for_the_published_flip_back(vault: &Vault, session_ref: &str) {
    let entry = super::registry::live_session_entry(&vault.store, session_ref)
        .expect("the stretch is live");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match entry.state.try_lock() {
            Ok(state) if state.record.mode == OffRecordMode::OffRecord => return,
            Ok(_) | Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Poisoned(_)) => panic!("the stretch's state lock is poisoned"),
        }
        assert!(
            Instant::now() < deadline,
            "the first flip back never published"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn a_close_during_a_flip_back_returns_only_after_a_base_write_that_passed_its_route_check_commits()
{
    let outcome = race(Act::CloseDuringFlipBack);
    assert!(outcome.witness.is_ok(), "witness: {:?}", outcome.witness);
    assert!(outcome.act_ok, "the close failed");
    assert!(
        outcome.landed_when_the_act_returned,
        "the close during a flip back returned before a base write that passed its route check committed"
    );
}

#[test]
fn a_repeat_flip_back_returns_only_after_a_base_write_that_passed_its_route_check_commits() {
    let outcome = race(Act::RepeatFlipBack);
    assert!(outcome.witness.is_ok(), "witness: {:?}", outcome.witness);
    assert!(outcome.act_ok, "the repeat flip back failed");
    assert!(
        outcome.landed_when_the_act_returned,
        "the repeat flip back returned before a base write that passed its route check committed"
    );
}

/// Returns once a flip outside the write holds the stretch's state lock, or
/// has published its flip and let the lock go.
fn wait_for_the_flip_outside_the_write(vault: &Vault, session_ref: &str) {
    let entry = super::registry::live_session_entry(&vault.store, session_ref)
        .expect("the stretch is live");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match entry.state.try_lock() {
            Err(TryLockError::WouldBlock) => return,
            Ok(state) if state.record.mode == OffRecordMode::OffRecord => return,
            Ok(_) => {}
            Err(TryLockError::Poisoned(_)) => panic!("the stretch's state lock is poisoned"),
        }
        assert!(
            Instant::now() < deadline,
            "the flip outside the write never took the stretch's state lock"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn a_flip_back_inside_a_write_returns_while_another_flip_back_waits_for_that_writer() {
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let outcome = with_on_record_session(|vault, session, _proof| {
            let (in_write_tx, in_write_rx) = mpsc::channel();
            let (go_tx, go_rx) = mpsc::channel::<()>();
            std::thread::scope(|scope| {
                // This one holds the vault's writer, then flips the stretch
                // back inside that write.
                let inside = scope.spawn(move || {
                    vault.with_write_txn(|_| {
                        in_write_tx.send(()).expect("announce the open write");
                        go_rx
                            .recv_timeout(Duration::from_secs(60))
                            .expect("release the write");
                        session.flip_off_record()
                    })
                });
                in_write_rx
                    .recv_timeout(Duration::from_secs(30))
                    .expect("the write opened");
                // This one flips back outside any write, so it waits for the
                // writer the first one holds.
                let outside = scope.spawn(move || session.flip_off_record());
                wait_for_the_flip_outside_the_write(vault, session.session_ref());
                go_tx.send(()).expect("release the write");
                let inside = inside
                    .join()
                    .expect("the flip inside a write must not panic");
                let outside = outside.join().expect("the flip outside must not panic");
                (inside, outside)
            })
        });
        let _ = done_tx.send(outcome);
    });
    let (inside, outside) = done_rx
        .recv_timeout(Duration::from_secs(120))
        .expect("the two flips stood still: a deadlock");
    inside.expect("the flip back inside a write returns");
    outside.expect("the flip back outside a write returns");
}

#[test]
fn a_witness_after_a_flip_back_lands_nothing_in_base() {
    with_on_record_session(|vault, session, proof| {
        vault
            .set_off_record_session_mode(session.session_ref(), OffRecordMode::OffRecord)
            .expect("flip back off record");
        let before = base_entity_count(vault);
        witness(vault, session, proof, "The private observation.", 102)
            .expect("the overlay witness lands");
        assert_eq!(
            base_entity_count(vault),
            before,
            "a witness after the flip back adds no base entities"
        );
    });
}

#[test]
fn a_flip_back_inside_a_write_does_not_wait_for_its_own_writer() {
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let outcome = with_on_record_session(|vault, session, _proof| {
            vault.with_write_txn(|_| {
                vault
                    .set_off_record_session_mode(session.session_ref(), OffRecordMode::OffRecord)?;
                Ok(())
            })
        });
        let _ = done_tx.send(outcome);
    });
    done_rx
        .recv_timeout(Duration::from_secs(180))
        .expect("the race stood still: a deadlock")
        .expect("the flip back inside a write returns");
}
