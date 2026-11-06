//! A source audience carrier in a checkpoint (SYNC-3 §5): a binding and a
//! withholding marker ride with the row their key names; a policy revision
//! names the people who read under it, and a change receipt who made the
//! change and whom it named, and neither is an entity of its own. None is
//! split here, so each stays unclassified under the vault-wide seal, named
//! as such.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::{Carrier, carrier, parse_key};
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::checkpoint_payload::{KeyClass, Placement, SyncUnclassified};

/// A binding is not split from the policy it names yet.
const BINDING_UNSPLIT: &str = "a source audience binding is not split from its policy";
/// A policy revision names its readers, its shares and its creator.
const POLICY_ACTORS: &str = "a source audience policy names the people who read under it";
/// A withholding marker names the machine that withheld its row.
const MARKER_UNSPLIT: &str = "a source audience withholding marker names the machine that set it";
/// A change receipt names who made the change and the person it named.
const RECEIPT_ACTORS: &str = "a source audience change receipt names who made the change";

/// Where the carrier under `key` goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    match carrier(key, value) {
        Ok(Carrier::Record { row, .. }) => Placement::unclassified(
            Some(OwnerRef::entity(&row)),
            SyncUnclassified::ActorSplit(BINDING_UNSPLIT),
        ),
        Ok(Carrier::Policy { .. }) => {
            Placement::unclassified(None, SyncUnclassified::ActorSplit(POLICY_ACTORS))
        }
        Ok(Carrier::Event { .. }) => {
            Placement::unclassified(None, SyncUnclassified::ActorSplit(RECEIPT_ACTORS))
        }
        Ok(Carrier::Withheld { row, .. }) => Placement::unclassified(
            Some(OwnerRef::entity(&row)),
            SyncUnclassified::ActorSplit(MARKER_UNSPLIT),
        ),
        Err(_) => Placement::unclassified(None, SyncUnclassified::Undecodable),
    }
}

/// What a key spells: a row's id, or a policy's id and a revision (a
/// revision's key and a receipt's), both opaque; any other spelling is
/// payload.
pub(in crate::sync) fn key_class(key: &str) -> KeyClass {
    if parse_key(key).is_some() {
        KeyClass::Opaque
    } else {
        KeyClass::Payload
    }
}
