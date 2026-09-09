//! Carrier scrubs plus test injection hook.

use super::UPDATE_PREFIX;
use super::codec::{decode_update_key, decode_update_value_parts};
use super::seq::delete_bearing_seqs_in_txn;
use crate::Vault;
use crate::error::Result;

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
    let fr_key = format!("fr:w:{window_key}");
    vault.store.sync_state.put(wtxn, &fr_key, &[1_u8])?;
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
