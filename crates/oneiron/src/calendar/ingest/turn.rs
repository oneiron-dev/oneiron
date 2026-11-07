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
//! the owner's import and instance move, a queued property continuation, one
//! connector change, and an outbound connector write's local completion,
//! which can turn an inbound passport two-way. The turn is a lock per vault,
//! by canonical root, kept for the process's life as the writer-spend locks
//! are. The serving process is the vault's only writer, so the turn is the
//! whole boundary.
//!
//! A door entered again on a thread that already holds a turn (a host
//! screener that runs a poll, say) is refused: passing it through would let
//! the inner admission mint a UID the outer one already decided to mint, and
//! waiting would never end. A door is never entered inside a writer: it takes
//! the turn first and its writers after, so no writer waits on the turn.

use std::cell::Cell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use crate::calendar::CalendarError;
use crate::vault::Vault;

/// The turn lock of each vault this process ever admitted calendar state into.
static TURNS: LazyLock<Mutex<HashMap<PathBuf, &'static Mutex<()>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

thread_local! {
    /// Whether this thread holds a calendar admission turn now.
    static HOLDING: Cell<bool> = const { Cell::new(false) };
}

/// This thread's turn at one vault's calendar admission, held until it drops.
pub(in crate::calendar) struct AdmissionTurn {
    _guard: MutexGuard<'static, ()>,
}

impl Drop for AdmissionTurn {
    fn drop(&mut self) {
        HOLDING.with(|holding| holding.set(false));
    }
}

/// Waits for, then holds, this process's turn at `vault`'s calendar
/// admission.
///
/// # Errors
/// [`CalendarError::IcsIngest`] when this thread already holds a turn.
pub(in crate::calendar) fn admission_turn(vault: &Vault) -> Result<AdmissionTurn, CalendarError> {
    if HOLDING.with(Cell::get) {
        return Err(super::ingest(
            "a calendar admission was entered again on a thread that holds an admission turn",
        ));
    }
    let lock = {
        let mut turns = TURNS.lock().unwrap_or_else(PoisonError::into_inner);
        *turns
            .entry(vault.store.canonical_root().to_path_buf())
            .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))))
    };
    let guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
    HOLDING.with(|holding| holding.set(true));
    Ok(AdmissionTurn { _guard: guard })
}
