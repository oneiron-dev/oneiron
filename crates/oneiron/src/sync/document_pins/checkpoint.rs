//! A document pin in a checkpoint (KS7-3a), read with the pin codec and
//! filed under its own key: a whole pin is its citing record's, held only
//! while the message it quotes is, and one naming a live actor stays
//! unclassified. A parted pin is a manifest its citer holds; its parts are
//! held through it ([`crate::sync::checkpoint_payload::PartHolders`]), but
//! only once the joined pin shows whether it names an actor (KS7-3b).
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::{Carried, carrier_key, decode_carried, key_ids};
use crate::entity_doc::DocActor;
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::carrier_parts::is_part_key;
use crate::sync::checkpoint_payload::{Holder, Placement, SyncUnclassified};

/// A whole pin naming its actor.
const PIN_ACTOR: &str = "a document pin names its actor";

/// A parted pin, whose actor shows only once its parts join.
const PARTED_PIN: &str = "a parted document pin, read only once its parts join";

/// Where the value under `key` in the pin map goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    let undecodable = || Placement::unclassified(None, SyncUnclassified::Undecodable);
    if is_part_key(key) {
        return Placement::Part;
    }
    match decode_carried(value) {
        Ok(Carried::Whole(pin, message, citation))
            if carrier_key(message, citation, &pin).is_ok_and(|filed| filed == key) =>
        {
            let owner = OwnerRef::entity(&citation);
            match pin.actor {
                DocActor::Erased => Placement::owned(owner, vec![OwnerRef::entity(&message)]),
                DocActor::Actor(_) => {
                    Placement::unclassified(Some(owner), SyncUnclassified::ActorSplit(PIN_ACTOR))
                }
            }
        }
        Ok(Carried::Parted(parts)) => match key_ids(key) {
            Some((message, citation)) => Placement::Manifest {
                holders: vec![Holder::new(
                    OwnerRef::entity(&citation),
                    vec![OwnerRef::entity(&message)],
                )],
                parts,
                joined: Some(SyncUnclassified::ActorSplit(PARTED_PIN)),
            },
            None => undecodable(),
        },
        _ => undecodable(),
    }
}
