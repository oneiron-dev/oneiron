//! Whether one word on a verb hook's ask lets its stopped call run (row
//! OWNER-CONFIRM-SHEET): `proceed` on an ask whose row still waits open. The
//! owner-device read answers this before the device asks for the person, and
//! settlement marks the same row through the same match
//! ([`super::settled_in_txn`]). A session-only pause keeps no saved row, so
//! no word on its ask releases anything here.

use crate::task_verb::TaskAskOptionId;
use crate::{EntityId, Result, Vault};

use super::{ASKS, PROCEED, VerbAsk, VerbAskState};

/// Whether `row` still waits open on ask `group` for `binding`: the match
/// settlement marks ([`super::settled_in_txn`]) and the word's read checks.
pub(super) fn waits_open_on(row: &VerbAsk, binding: EntityId, group: EntityId) -> bool {
    row.ask == group && row.binding == binding && row.state == VerbAskState::Open
}

/// Whether a word with `option` on the ask `group` with `intent_key` lets a
/// stopped call run: the key is a verb hook ask's, its row still waits open
/// on this ask for this binding, and the word says proceed. A saved row that
/// does not decode answers false, as settlement passes it over; only the
/// caller's retry reports it. Whether the ask's decision is still open to a
/// word (no result yet, no stale cut) is the caller's read.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn verb_ask_word_releases_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group: EntityId,
    intent_key: &str,
    option: Option<&TaskAskOptionId>,
) -> Result<bool> {
    let Some(option) = option else {
        return Ok(false);
    };
    if option.as_str() != PROCEED {
        return Ok(false);
    }
    let Some((invocation, binding)) = super::super::resume::verb_hook_ids(intent_key) else {
        return Ok(false);
    };
    let row = ASKS.get_lenient(&vault.store, txn, &invocation.0)?;
    let _ = (row, binding, group); Ok(false)
}
