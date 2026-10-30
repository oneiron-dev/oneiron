//! A judgment answer's typed-question copies under body custody (FIX 11236).
//!
//! An answer row, its outcome labels and its closed window copy the bound
//! `judgment.answer` claim FIX 9918 erases them with: the claim's erase
//! deletes every one of those rows live, at both delete doors. A checkpoint
//! carries each as a row-held response owned by the answer claim alone, so
//! the claim's erase retires every image's copy too; a retired copy leaves
//! nothing, as the live row goes. The question's own rows (its versions,
//! head, backfills and ask-history mark) hold no answer copy and travel as
//! they are. Erasing by unit or by principal is the FIX's open second half.

use super::store::{AnswerKey, LabelKey, QUESTION_ANSWER, QUESTION_LABEL};
use super::windows::{QUESTION_WINDOW, WindowKey};
use crate::entity_id::EntityId;
use crate::side_table::{self, SideKey};
use crate::store::{ResponseCarriage, ResponseScan};

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

/// Who owns the typed-question row `key`'s copies: the answer claim it
/// copies, by its key alone, as FIX 9918's eraser deletes it by; none for
/// any other row of the table, or one whose key does not decode.
pub(crate) fn typed_question_owners(key: &[u8]) -> Vec<EntityId> {
    copy_claim(key).into_iter().collect()
}
