//! A custody carrier in a checkpoint (KS7-3a): a custody transition, a
//! protected input and a witness part (FIX 8088) are secret custody's
//! (KS-6), handed to it as they stand, never ordinary payload. Each is read with its own codec and filed under
//! its own key; the live admission door, which judges signers in a txn of
//! its own, is not run.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::INPUT_ROW_PREFIX;
use super::witness::WITNESS_ROW_PREFIX;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::secret_custody::{CustodyTransition, RelayedInput, WitnessPart};
use crate::store::checkpoint_payload::rows::OtherClient;
use crate::sync::checkpoint_payload::{KeyClass, Placement, SyncUnclassified};

/// Where the value under `key` in the custody map goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    let filed = match (
        key.strip_prefix(INPUT_ROW_PREFIX),
        key.strip_prefix(WITNESS_ROW_PREFIX),
    ) {
        (Some(row_key), _) => RelayedInput::decode(value)
            .is_some_and(|input| bytes_to_hex_lower(&input.row_key()) == row_key),
        (None, Some(row_key)) => WitnessPart::decode(value)
            .is_some_and(|part| bytes_to_hex_lower(&part.row_key()) == row_key),
        (None, None) => {
            CustodyTransition::decode(value).is_ok_and(|transition| transition.row_key() == key)
        }
    };
    if filed {
        Placement::Dispatched(OtherClient::Credential)
    } else {
        Placement::unclassified(None, SyncUnclassified::Undecodable)
    }
}

/// What a custody map key spells: a transition's record id and the place
/// of its piece, a protected input's digest, or a witness part's key.
pub(in crate::sync) fn key_class(key: &str) -> KeyClass {
    if key.starts_with(INPUT_ROW_PREFIX) || key.starts_with(WITNESS_ROW_PREFIX) {
        return KeyClass::Digest;
    }
    let (id, piece) = match key.split_once('.') {
        Some((id, piece)) => (id, Some(piece)),
        None => (key, None),
    };
    let named = EntityId::from_hex(id).is_ok_and(|parsed| parsed.to_hex() == id);
    let placed = piece.is_none_or(|piece| {
        piece.len() == 8
            && piece
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if named && placed {
        KeyClass::Opaque
    } else {
        KeyClass::Payload
    }
}
