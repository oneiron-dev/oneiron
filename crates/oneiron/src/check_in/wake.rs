//! The host that wakes a due check-in (ARCH-0082 #waits and "When nobody
//! answers"; ROLES-CHECKIN P2.3, piece 2e).
//!
//! The engine keeps no timer of its own (`housekeeping`): each housekeeping
//! pass advances the pending check-ins whose next due time has come, in due
//! order, one transition each ([`advance_pending_check_in_in_txn`]). The
//! asker's `until` lets the ask go, a delay window's end settles it, and a
//! rung whose wait is over climbs, or past the last rung canon's table "When
//! nobody answers" settles it. Each open row's next due time is its `DUE`
//! index entry, so a stopped vault wakes then
//! ([`Vault::housekeeping_wake_at`]).
//!
//! The rows are durable and every pass reads them afresh, so a restart loses
//! nothing. A late pass delays a climb and never skips a rung: each rung's
//! wait starts when the ask enters it. A rung whose pinned people have all
//! lost the power ends early only when a call reads it (an answer, or the
//! inquiry's repeat); the pass reaches it at its due time.
//!
//! Each row advances in its own write, so one row's error leaves the others
//! to advance and the row is tried again on the next pass. An agent holder's
//! verdict has no producer yet: [`NoAgentVerdict`] passes the ask up, which
//! fails closed (canon #modes: "Unsure, refusal or error: ask").

use super::chain::{NoAgentVerdict, VerifiedChain};
use super::pending::{DUE, pending_check_in_in_txn};
use super::waits::advance_pending_check_in_in_txn;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The most rows one pass advances; the rest wait for the next pass, which
/// the host's tick runs a minute later.
const DUE_ROWS_PER_PASS: usize = 64;

impl Vault {
    /// Advances the pending check-ins due by now, one transition each, in
    /// due order, at most [`DUE_ROWS_PER_PASS`] of them. A row whose advance
    /// fails is logged and stays due. Returns how many rows moved.
    ///
    /// # Errors
    ///
    /// Storage errors reading the due index.
    pub(crate) fn advance_due_check_ins(&self) -> Result<usize> {
        let now = self.store.clock.now_recorded_at();
        let due = {
            let rtxn = self.store.env.read_txn()?;
            let mut due = Vec::new();
            for row in DUE.iter_from(&self.store, &rtxn, &[])? {
                let ((due_at, id), ()) = row?;
                if due_at > now || due.len() == DUE_ROWS_PER_PASS {
                    break;
                }
                due.push((due_at, id));
            }
            due
        };
        let chain = VerifiedChain::new(&NoAgentVerdict);
        let mut moved = 0;
        for (due_at, id) in due {
            let advanced = self.with_write_txn(|txn| {
                let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                if !still_due_in_txn(self, txn, due_at, &id, now)? {
                    return Ok(false);
                }
                Ok(advance_pending_check_in_in_txn(self, txn, &id, &chain, now)?.is_some())
            });
            match advanced {
                Ok(true) => moved += 1,
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(
                        %error,
                        check_in = %id.to_hex(),
                        "housekeeping: a due check-in waits for the next pass"
                    );
                }
            }
        }
        Ok(moved)
    }
}

/// Whether the row `id` the index holds at `due_at` is due at `now`. An
/// index entry that no longer matches its row (the row gone, final, or due
/// at another time) is put right here, so the pass and the wake never spin
/// on it.
fn still_due_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    due_at: u64,
    id: &EntityId,
    now: u64,
) -> Result<bool> {
    let due = pending_check_in_in_txn(&vault.store, txn, id)?.and_then(|row| row.next_due_at());
    if due != Some(due_at) {
        DUE.delete(&vault.store, txn, &(due_at, *id))?;
        if let Some(at) = due {
            DUE.put(&vault.store, txn, &(at, *id), &())?;
        }
    }
    Ok(due.is_some_and(|at| at <= now))
}

/// The first due time of an open pending check-in on this vault, for
/// [`Vault::housekeeping_wake_at`]: one index row.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn next_check_in_due_at(vault: &Vault) -> Result<Option<u64>> {
    let rtxn = vault.store.env.read_txn()?;
    let first = DUE.iter_from(&vault.store, &rtxn, &[])?.next().transpose()?;
    Ok(first.map(|((due_at, _), ())| due_at))
}
