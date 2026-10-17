//! Carrier scrubs plus test injection hook.

use super::UPDATE_PREFIX;
use super::codec::{decode_update_key, decode_update_value_parts};
use super::seq::delete_bearing_seqs_in_txn;
use crate::Vault;
use crate::error::Result;
use crate::sync::window_rows::WINDOW_FULL_RESYNC_MARKER;

#[cfg(test)]
use super::INJECT_RECEIVER_SCRUB_FAILURES;
#[cfg(test)]
use crate::error::Error;

/// ARCH-0038 carrier 15 ("Pending sync ops in the outgoing queue: drop ops
/// within the redacted span before transmission"), fail-closed
/// simplification (ONE-1135 OWNER-DECISION): drop EVERY pending `q:` row
/// addressed to `window_key` — plus any malformed `q:` row, which cannot be
/// proven payload-free — rather than inspecting opaque Loro update bytes
/// for the redacted span. Over-dropping is healed by the window's
/// full-resync marker (`fr:w:{key}`); leaking is not healable.
///
/// Delete-bearing rows are NEVER scrubbed: their payload is a
/// tombstone-commit delta (tombstone value + key-delete ops — opaque ids
/// only, no entity payload), and dropping one would lose a prior
/// unconfirmed delete. `e:` / `h:` / `m:` and unknown key families are
/// untouched.
pub(crate) fn scrub_window_updates_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
) -> Result<u32> {
    let delete_bearing = delete_bearing_seqs_in_txn(vault, wtxn)?;
    let mut doomed = Vec::new();
    for row in vault.store.sync_queue.prefix_iter(&*wtxn, UPDATE_PREFIX)? {
        let (key, value) = row?;
        let Ok(seq) = decode_update_key(&key) else {
            doomed.push(key.to_vec());
            continue;
        };
        if delete_bearing.contains(&seq) {
            continue;
        }
        match decode_update_value_parts(&value) {
            Ok((row_window, _)) if row_window == window_key => doomed.push(key.to_vec()),
            Ok(_) => {}
            // Fail-closed: a row that cannot prove which window it belongs
            // to cannot prove it is payload-free either.
            Err(_) => doomed.push(key.to_vec()),
        }
    }
    for key in &doomed {
        vault.store.sync_queue.delete(wtxn, key)?;
    }
    Ok(u32::try_from(doomed.len()).unwrap_or(u32::MAX))
}

/// Every queued send addressed to `window_key`, as `(seq, update bytes)`.
pub(crate) fn queued_window_updates(
    vault: &Vault,
    window_key: &str,
) -> Result<Vec<(u64, Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut queued = Vec::new();
    for row in vault.store.sync_queue.prefix_iter(&rtxn, UPDATE_PREFIX)? {
        let (key, value) = row?;
        if let (Ok(seq), Ok((row_window, update))) =
            (decode_update_key(&key), decode_update_value_parts(&value))
            && row_window == window_key
        {
            queued.push((seq, update.to_vec()));
        }
    }
    Ok(queued)
}

/// How many queued sends name `window_key`, read in the caller's transaction.
/// Rows [`queued_window_updates`] would skip are not counted.
pub(crate) fn queued_window_update_count_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    window_key: &str,
) -> Result<usize> {
    let mut count = 0;
    for row in store.sync_queue.prefix_iter(txn, UPDATE_PREFIX)? {
        let (key, value) = row?;
        if let (Ok(_), Ok((row_window, _))) =
            (decode_update_key(&key), decode_update_value_parts(&value))
            && row_window == window_key
        {
            count += 1;
        }
    }
    Ok(count)
}

/// Discards every queued window update, delete-bearing rows and their `d:` sidecars included,
/// for a device that left the shared vault this env holds (OF-158). Returns how many `q:` rows
/// went; `e:`, `h:` and `m:` rows stay.
pub(crate) fn discard_updates_for_leave_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    let mut keys = Vec::new();
    let mut updates = 0_u64;
    for row in vault.store.sync_queue.iter(wtxn)? {
        let (key, _) = row?;
        if key.starts_with(UPDATE_PREFIX) {
            updates += 1;
            keys.push(key.to_vec());
        } else if key.starts_with(super::DELETE_BEARING_PREFIX) {
            keys.push(key.to_vec());
        }
    }
    for key in &keys {
        vault.store.sync_queue.delete(wtxn, key)?;
    }
    Ok(updates)
}

/// Retires the queued sends `seqs`, delete-bearing rows and their `d:` sidecars included, in the
/// transaction that installs a window's replacement. Their operations depend on history the
/// replacement does not hold, and the replacement carries their effects as its own operations,
/// which sync by version vector like any other.
pub(crate) fn retire_queued_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    seqs: &[u64],
) -> Result<()> {
    for seq in seqs {
        vault
            .store
            .sync_queue
            .delete(wtxn, &super::codec::encode_update_key(*seq))?;
        vault
            .store
            .sync_queue
            .delete(wtxn, &super::codec::encode_delete_bearing_key(*seq))?;
    }
    Ok(())
}

/// Receiver-side carrier-15 scrub (ONE-1165): on a remote HARD delete applied
/// via live replay (Observer B) or recovery (forward_rematerialize), the
/// receiver's own `q:` outbox may carry the now-deleted payload. Mirror the
/// origin scrub: drop the window's pending `q:` rows (delete-bearing rows
/// preserved by the inner scrub) and set `fr:w:{key}` so any over-dropped
/// non-deleted op is re-sent on next connect.
///
/// Window-granular by design: Loro update bytes are opaque, so per-entity
/// filtering is impossible; over-drop is healed by full-resync, leak is not
/// healable.
pub(in crate::sync) fn scrub_receiver_outbox_on_remote_hard_delete_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
) -> Result<u32> {
    #[cfg(test)]
    maybe_inject_receiver_scrub_failure()?;

    let dropped = scrub_window_updates_in_txn(vault, wtxn, window_key)?;
    WINDOW_FULL_RESYNC_MARKER.put(&vault.store, wtxn, &window_key.to_owned(), &[1_u8])?;
    Ok(dropped)
}

#[cfg(test)]
fn maybe_inject_receiver_scrub_failure() -> Result<()> {
    let inject = INJECT_RECEIVER_SCRUB_FAILURES.with(|cell| {
        let remaining = cell.get();
        if remaining > 0 {
            cell.set(remaining - 1);
            true
        } else {
            false
        }
    });
    if inject {
        return Err(Error::Io(std::io::Error::other(
            "injected receiver outbox scrub failure (test hook)",
        )));
    }
    Ok(())
}
