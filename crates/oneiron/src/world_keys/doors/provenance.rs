//! A key record's provenance, under its signature (CALLS
//! WORLD_KEY_WRAP_AUTH): the owner work request it does, if any, which its
//! entry names among its parents, and the recipients its signer permits,
//! exactly the ones it seals to.
//!
//! A record with a request is the named executor's work for the owner's act;
//! one without is an eligible reader wrapping on its own (an ensure, a sweep,
//! a pin door). Neither widens who may receive a wrap: the fold holds every
//! recipient to the owner's read choice whoever publishes.

use super::super::{WorldKeyBinding, WrapRecipient};
use crate::EntityId;
use crate::authority::{AuthorityEntryHash, WorldKeyWrapsRecord};

/// `machine`'s record of `binding`'s key sealed to `wraps`, doing `request`
/// when an owner work request names `machine` to do it. `permitted` lists
/// the sealed recipients, ascending.
pub(super) fn wraps_record(
    binding: &WorldKeyBinding,
    machine: EntityId,
    wraps: Vec<(WrapRecipient, Vec<u8>)>,
    request: Option<AuthorityEntryHash>,
) -> WorldKeyWrapsRecord {
    let mut permitted: Vec<WrapRecipient> = wraps.iter().map(|(to, _)| *to).collect();
    permitted.sort_unstable();
    WorldKeyWrapsRecord {
        key: binding.key,
        commitment: binding.commitment,
        owner: binding.owner,
        policy: binding.policy,
        machine,
        wraps,
        request,
        permitted,
    }
}
