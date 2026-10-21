//! A blocked report's captured requests in checkpoint images (FIX 6708, KEY
//! STORE = A): each receipt row and each durable step's row of the
//! replay-source table is a row-held response of its own (KS-2B1), sealed
//! whole under a body instance its owners' erase retires in every older
//! image.
//!
//! An image carries nothing in the row's place: a live instance lands the
//! exact row, and a retired one's row goes, as an erase of its owner takes
//! it live. So no image lands a requestless step source or a replay its
//! owner's erase took. A receipt row with no request is carried too. A row
//! that decodes as neither kind travels as it is.

use super::{SOURCE, STEPS, StepSourceKey};
use crate::EntityId;
use crate::side_table::SideKey;

/// The owners a replay-source row stamps, when it decodes: a receipt row's
/// reporter, or a step row's actor, subject and terminal claim.
fn owners_of(key: &[u8], value: &[u8]) -> Option<Vec<EntityId>> {
    let rest = key.strip_prefix(SOURCE.decl().prefix)?;
    if StepSourceKey::decode_key(rest).is_some() {
        let mut owners = STEPS.decode_value(value).ok()?.owners();
        owners.sort_unstable();
        owners.dedup();
        return Some(owners);
    }
    EntityId::decode_key(rest)?;
    Some(vec![SOURCE.decode_value(value).ok()?.reporter])
}

/// What an image holds in a replay-source row's place: nothing, the whole
/// row carried. `None` for a row that decodes as neither kind.
pub(crate) fn blocked_capture_stub(key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
    owners_of(key, value).map(|_| Vec::new())
}

/// Who owns a replay-source row's request: a receipt row's reporter, or a
/// step row's actor, subject and terminal claim; never a payer, the
/// receipt or the run. None for a row that does not decode.
pub(crate) fn blocked_capture_owners(key: &[u8], value: &[u8]) -> Vec<EntityId> {
    owners_of(key, value).unwrap_or_default()
}
