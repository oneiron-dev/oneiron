//! An office proposal in a checkpoint (KS7-3a), read with the proposal codec
//! and filed under its own key. The artifact it rides with is named, but a
//! proposal names its opener and each answer's person and caller, which no
//! split here takes out, so each stays unclassified, named with it.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::{artifact_of, carrier_key, decode};
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::checkpoint_payload::{KeyClass, Placement, SyncUnclassified};

/// A proposal's actors.
const PROPOSAL_ACTORS: &str = "an office proposal names its opener and its answerers";

/// Where the proposal under `key` goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    match decode(value) {
        Ok(record) if carrier_key(&record) == key => Placement::unclassified(
            Some(OwnerRef::entity(&record.header.artifact)),
            SyncUnclassified::ActorSplit(PROPOSAL_ACTORS),
        ),
        _ => Placement::unclassified(None, SyncUnclassified::Undecodable),
    }
}

/// What a proposal map key spells: its artifact's id and its own.
pub(in crate::sync) fn key_class(key: &str) -> KeyClass {
    if artifact_of(key).is_some() {
        KeyClass::Opaque
    } else {
        KeyClass::Payload
    }
}
