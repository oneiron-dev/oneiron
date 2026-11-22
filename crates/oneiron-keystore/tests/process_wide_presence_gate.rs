//! Row OWNER-CONFIRM-SHEET, PR 4b-5: a process holds one gate over the
//! platform's prompt. Every vault handle a host opens takes that gate, so
//! one confirm serves them all and one screen-lock watch runs.

use std::sync::Arc;
use std::thread;

use oneiron_keystore::PresenceGate;

#[test]
fn every_call_answers_the_same_gate() {
    let first = PresenceGate::process_wide();
    let second = PresenceGate::process_wide();
    assert!(Arc::ptr_eq(&first, &second));
}

/// Four other threads call, each started before any is joined. This thread
/// made the gate first, so the test holds the lookup across threads, not a
/// race of first calls.
#[test]
fn calls_on_other_threads_answer_the_same_gate() {
    let here = PresenceGate::process_wide();
    let calls: [thread::JoinHandle<Arc<PresenceGate>>; 4] =
        std::array::from_fn(|_| thread::spawn(PresenceGate::process_wide));
    for call in calls {
        let there = call.join().expect("the call ends");
        assert!(Arc::ptr_eq(&there, &here));
    }
}

/// A platform with no prompt of its own answers as a device that cannot
/// ask, through the process's gate as through a gate made for one call.
#[cfg(not(any(target_os = "macos", windows)))]
#[test]
fn the_gate_of_a_platform_without_a_prompt_cannot_ask() {
    use oneiron_keystore::{PresenceCapability, PresenceError};

    let gate = PresenceGate::process_wide();
    assert!(matches!(gate.capability(), PresenceCapability::NoPrompt(_)));
    assert!(matches!(
        gate.confirm("confirm a change to your vault"),
        Err(PresenceError::NoPrompt(_))
    ));
    assert!(!gate.window_is_open());
}
