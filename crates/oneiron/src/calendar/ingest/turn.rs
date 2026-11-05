//! The vault's one calendar admission turn (FIX 4797).
//!
//! An inbound admission reads before it writes: the UID diff resolves the
//! vault-wide UID index and the `(system × UID)` passport, and only then mints
//! an EVENT, indexes its UID, admits its properties and passport, sweeps the
//! absent sources and writes the cursor, each in its own writer. Two admissions
//! that ran at once could both read "no EVENT" for one UID and mint two, or
//! interleave one feed's absence sweep with another's passports. The UID index
//! spans every system, so two feeds that share a UID race too.
//!
//! So every door that admits inbound calendar state holds this process's turn
//! at the vault across its whole diff: the ICS poll once its fetch answered,
//! the owner's import and instance move, a queued property continuation, and
//! one connector change. The turn is a lock per vault, by canonical root, kept
//! for the process's life as the writer-spend locks are. The serving process
//! is the vault's only writer, so the turn is the whole boundary. A door
//! reached while its thread already holds the turn passes through.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use crate::vault::Vault;

/// The turn lock of each vault this process ever admitted calendar state into.
static TURNS: LazyLock<Mutex<HashMap<PathBuf, &'static Mutex<()>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

thread_local! {
    /// The turn locks this thread holds now.
    static HELD: RefCell<Vec<&'static Mutex<()>>> = const { RefCell::new(Vec::new()) };
}

/// This thread's turn at one vault's calendar admission, held until it drops.
pub(in crate::calendar) struct AdmissionTurn {
    held: Option<(&'static Mutex<()>, MutexGuard<'static, ()>)>,
}

impl Drop for AdmissionTurn {
    fn drop(&mut self) {
        if let Some((lock, guard)) = self.held.take() {
            drop(guard);
            HELD.with(|held| {
                held.borrow_mut()
                    .retain(|other| !std::ptr::eq(*other, lock));
            });
        }
    }
}

/// Waits for, then holds, this process's turn at `vault`'s calendar
/// admission. A thread that already holds it gets a turn that holds nothing.
pub(in crate::calendar) fn admission_turn(vault: &Vault) -> AdmissionTurn {
    let lock = {
        let mut turns = TURNS.lock().unwrap_or_else(PoisonError::into_inner);
        *turns
            .entry(vault.store.canonical_root().to_path_buf())
            .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))))
    };
    if HELD.with(|held| held.borrow().iter().any(|other| std::ptr::eq(*other, lock))) {
        return AdmissionTurn { held: None };
    }
    let guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
    HELD.with(|held| held.borrow_mut().push(lock));
    AdmissionTurn {
        held: Some((lock, guard)),
    }
}
