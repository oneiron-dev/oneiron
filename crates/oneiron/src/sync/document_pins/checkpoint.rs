//! A document pin in a checkpoint (KS7-3a, KS7-3b), read with the pin codec
//! and filed under its own key: a whole pin is its citing record's, held
//! only while the message it quotes is. Its actor is split out (FIX 9127):
//! the copy keeps the pin naming no one, under the key its erased twin
//! already rides under, and an actor that does not open leaves it so. A
//! parted pin is a manifest its citer holds; its parts are held through it
//! ([`crate::sync::checkpoint_payload::PartHolders`]), but only once the
//! joined pin shows whether it names an actor. A pin's key holds a digest
//! of the pin, and so does a part's.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::{Carried, carrier_key, decode_carried, decode_pin, key_ids};
use crate::entity_doc::DocActor;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::checkpoint_payload::rows::{OwnerRef, bad_part};
use crate::sync::carrier_parts::is_part_key;
use crate::sync::checkpoint_payload::{Holder, KeyClass, Placement, SyncUnclassified, ValueSplit};

/// A whole pin that does not encode once its actor is out.
const PIN_ACTOR: &str = "a document pin names its actor";

/// A parted pin, whose actor shows only once its parts join.
const PARTED_PIN: &str = "a parted document pin, read only once its parts join";

/// The field a pin's actor fills.
const ACTOR: &str = "actor";

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
            let holders = vec![Holder::new(owner, vec![OwnerRef::entity(&message)])];
            let actors = match pin.actor {
                DocActor::Actor(actor) => vec![(ACTOR.to_owned(), actor)],
                DocActor::Erased => Vec::new(),
            };
            match rmp_serde::to_vec_named(&pin.actor_erased()) {
                Ok(no_one) => Placement::split(holders, ValueSplit { no_one, actors }),
                Err(_) => {
                    Placement::unclassified(Some(owner), SyncUnclassified::ActorSplit(PIN_ACTOR))
                }
            }
        }
        Ok(Carried::Parted(parted)) => match key_ids(key) {
            Some((message, citation)) => Placement::Manifest {
                holders: vec![Holder::new(
                    OwnerRef::entity(&citation),
                    vec![OwnerRef::entity(&message)],
                )],
                parts: parted.parts,
                joined: Some(SyncUnclassified::ActorSplit(PARTED_PIN)),
            },
            None => undecodable(),
        },
        _ => undecodable(),
    }
}

/// What a pin map key spells: a pin's ids and a digest of the pin naming
/// no one, or a part's digest.
pub(in crate::sync) fn key_class(key: &str) -> KeyClass {
    if is_part_key(key) || key_ids(key).is_some() {
        KeyClass::Digest
    } else {
        KeyClass::Payload
    }
}

/// The pin `no_one` with its actor back, when it opened.
pub(in crate::sync) fn fill(no_one: &[u8], opened: &[(&str, EntityId)]) -> Result<Option<Vec<u8>>> {
    let (mut pin, _, _) = decode_pin(no_one).map_err(|_| bad_part())?;
    if pin.actor != DocActor::Erased {
        return Err(bad_part());
    }
    for (field, actor) in opened {
        if *field != ACTOR || pin.actor != DocActor::Erased {
            return Err(bad_part());
        }
        pin.actor = DocActor::Actor(*actor);
    }
    rmp_serde::to_vec_named(&pin)
        .map(Some)
        .map_err(|_| bad_part())
}
