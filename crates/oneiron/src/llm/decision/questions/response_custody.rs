//! A judgment answer's typed-question copies under body custody (FIX 11236, 11237).
//!
//! An answer row, its outcome labels and its closed window copy the bound
//! `judgment.answer` claim FIX 9918 erases them with: the claim's erase
//! deletes every one of those rows live, at both delete doors. A checkpoint
//! carries each as a row-held response. At first bind, a decoded answer
//! names its claim, unit and receipt principal; a decoded label or window
//! joins those owners from its answer in the same transaction. An opaque
//! copy or one without a decodable answer keeps its claim owner alone.
//! Existing unchanged bindings keep their prior owners. An owner's erase
//! retires the instances bound to it; a retired copy leaves nothing. The
//! question's own rows (its versions, head, backfills and ask-history mark)
//! hold no answer copy and travel as they are. The live erase scrub remains
//! beside this custody handling.

use super::store::{AnswerKey, LabelKey, QUESTION_ANSWER, QUESTION_LABEL};
use super::windows::{QUESTION_WINDOW, WindowKey};
use crate::entity_id::EntityId;
use crate::side_table::{self, SideKey};
use crate::store::{ResponseCarriage, ResponseScan, Store};

/// The answer claim the copy row `key` holds a copy of, by its key alone:
/// an answer row's, a label's or a closed window's claim; `None` for any
/// other row of the table, which holds no answer copy.
fn copy_claim(key: &[u8]) -> Option<EntityId> {
    let rest = key.strip_prefix(side_table::TYPED_QUESTION.prefix)?;
    if let Some(answer) = AnswerKey::decode_key(rest) {
        return Some(answer.claim);
    }
    if let Some(label) = LabelKey::decode_key(rest) {
        return Some(label.claim);
    }
    WindowKey::decode_key(rest).map(|window| window.claim)
}

/// Whether the copy row `key` holding `value` decodes as its own family.
fn copy_decodes(key: &[u8], value: &[u8]) -> bool {
    let Some(rest) = key.strip_prefix(side_table::TYPED_QUESTION.prefix) else {
        return false;
    };
    if AnswerKey::decode_key(rest).is_some() {
        QUESTION_ANSWER.decode_value(value).is_ok()
    } else if LabelKey::decode_key(rest).is_some() {
        QUESTION_LABEL.decode_value(value).is_ok()
    } else {
        QUESTION_WINDOW.decode_value(value).is_ok()
    }
}

/// What a checkpoint carries of the typed-question row `key`: an answer
/// copy whole, nothing once retired, as a captured request is carried (its
/// retirement drops the row, in images and live alike). Any other row of
/// the table holds no response. A copy that does not decode is carried
/// whole as an opaque response (FIX 6227).
pub(crate) fn typed_question_carriage(key: &[u8], value: &[u8]) -> ResponseScan {
    if copy_claim(key).is_none() {
        return ResponseScan::NotResponse;
    }
    if !copy_decodes(key, value) {
        return ResponseScan::opaque_row();
    }
    ResponseScan::Decoded(ResponseCarriage {
        keep: 0,
        stub: Vec::new(),
        retired: 0,
    })
}

/// Owners proved by the copy's own key and value: an answer's claim, unit
/// and receipt principal, or a label's or closed window's claim alone.
/// Other rows have none. An undecodable answer keeps its claim owner, as
/// its opaque carriage does. Decoded labels and windows join their answer
/// owners through `typed_question_copy_owners_in_txn` at binding time.
pub(crate) fn typed_question_owners(key: &[u8], value: &[u8]) -> Vec<EntityId> {
    let Some(rest) = key.strip_prefix(side_table::TYPED_QUESTION.prefix) else {
        return Vec::new();
    };
    if let Some(answer) = AnswerKey::decode_key(rest) {
        let mut owners = vec![answer.claim];
        if let Ok(record) = QUESTION_ANSWER.decode_value(value) {
            if record.unit != answer.claim {
                owners.push(record.unit);
            }
            let principal = record.decision.receipt.principal;
            if principal != answer.claim && principal != record.unit {
                owners.push(principal);
            }
        }
        return owners;
    }
    copy_claim(key).into_iter().collect()
}

/// Owners of a copy at bind time, including a decoded label's or window's
/// answer unit and receipt principal (FIX 11237). Opaque copies and copies
/// without a decodable answer keep their key-proved owners alone.
///
/// # Errors
///
/// Storage errors while reading the answer in the binding transaction.
pub(crate) fn typed_question_copy_owners_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> crate::Result<Vec<EntityId>> {
    let mut owners = typed_question_owners(key, value);
    let Some(rest) = key.strip_prefix(side_table::TYPED_QUESTION.prefix) else {
        return Ok(owners);
    };
    if AnswerKey::decode_key(rest).is_some() || !copy_decodes(key, value) {
        return Ok(owners);
    }
    let (question, claim) = if let Some(label) = LabelKey::decode_key(rest) {
        (label.question, label.claim)
    } else if let Some(window) = WindowKey::decode_key(rest) {
        (window.question, window.claim)
    } else {
        return Ok(owners);
    };
    let Some(answer) = QUESTION_ANSWER.get_lenient(store, txn, &AnswerKey { question, claim })?
    else {
        return Ok(owners);
    };
    if !owners.contains(&answer.unit) {
        owners.push(answer.unit);
    }
    let principal = answer.decision.receipt.principal;
    if !owners.contains(&principal) {
        owners.push(principal);
    }
    Ok(owners)
}
