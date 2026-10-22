//! A row birth in a checkpoint (KS7-3b, FIX 9127), read with the birth
//! codec and filed under its born row: the birth is that row's, and its
//! process's actor is split out. A birth is immutable and has no erased
//! form, so the copy holds its born row's own id in the actor's place, a
//! placeholder only, and a birth whose actor does not open goes, never that
//! stand-in, as the vault's own birth rows go (`provenance::birth`).
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::{decode, encode, owner};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::checkpoint_payload::rows::{OwnerRef, bad_part};
use crate::sync::checkpoint_payload::{Holder, Placement, SyncUnclassified, ValueSplit};

/// The field the birth's process's actor fills.
const PROCESS: &str = "made_by.process.actor";

/// Where the birth under `key` goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    let Some(born) = owner(key) else {
        return Placement::unclassified(None, SyncUnclassified::Undecodable);
    };
    let holder = OwnerRef::entity(&born);
    let Some(mut birth) = decode(value) else {
        return Placement::unclassified(Some(holder), SyncUnclassified::Undecodable);
    };
    let actor = std::mem::replace(&mut birth.made_by.process.actor, born);
    let Ok(no_one) = encode(&birth) else {
        return Placement::unclassified(Some(holder), SyncUnclassified::Undecodable);
    };
    Placement::Split {
        holders: vec![Holder::new(holder, Vec::new())],
        split: ValueSplit {
            no_one,
            actors: vec![(PROCESS.to_owned(), actor)],
        },
    }
}

/// The birth `placeholder` of the row `key` names with its actor back;
/// `None` when the actor did not open.
pub(in crate::sync) fn fill(
    key: &str,
    placeholder: &[u8],
    opened: &[(&str, EntityId)],
) -> Result<Option<Vec<u8>>> {
    let born = owner(key).ok_or_else(bad_part)?;
    let mut birth = decode(placeholder).ok_or_else(bad_part)?;
    if birth.made_by.process.actor != born {
        return Err(bad_part());
    }
    match opened {
        [] => Ok(None),
        [(field, actor)] if *field == PROCESS => {
            birth.made_by.process.actor = *actor;
            encode(&birth).map(Some)
        }
        _ => Err(bad_part()),
    }
}
