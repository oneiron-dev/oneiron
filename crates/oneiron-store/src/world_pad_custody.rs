//! The world key pad's custody client (KS-5, FIX 346; KEY STORE = A): the
//! exterior custody a world key's erasable half moves into.
//!
//! A pad is one subject per key: kind `WorldPad`, item the key's full id
//! (`WorldKeyId::envelope_key_id`: world (16) | generation (8, big-endian) |
//! mint (16); CALLS `FIX 5686 pad custody item codec`), generation 0, the
//! pad's 32 bytes its secret. Every put of a pad row publishes its pad here
//! (KS-5, `world_keys::pad_custody`), the binding pinned in the same
//! transaction, synced and its Mint journaled before the row commits; the
//! row then rests as a reference to its entry with its own pad beside it,
//! which every read takes first. The pad sits in the custody head's
//! host-readable compartment (CALLS WORLD_PAD_HEAD_SCOPE).
//!
//! A world erase stages one erase intent for every pad of the world custody
//! holds here, a row or none, in the purge's own transaction, and the
//! finisher retires them after the commit once the world's destroyed fact
//! stands. A hard erase of one pad row alone stages that key's (FIX 7192).
//! A world delete retires nothing. A restore plans each pad its image names
//! through the restore's one plan ([`plan_world_pad`], FIX 5686 part 2).

pub mod install;

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use crate::key_custody::files::EntryState;
use crate::key_custody::files::custody_present;
use crate::key_custody::fork::Requirement;
use crate::key_custody::identity::CustodyBinding;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySecret;
use crate::key_custody::identity::CustodySubject;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// A pad's custody item: its key's full id, world (16) | generation (8,
/// big-endian) | mint (16).
pub type WorldPadItem = [u8; 40];

/// What current custody holds for one pad item, as the pad client's put door
/// reads it (KS-5, FIX 5686).
pub enum WorldPadCustody {
    /// No pad may be published here: an archived vault, whose custody is its
    /// replacement's.
    Closed,
    /// No entry yet: a publication takes it.
    Missing,
    /// The live entry's pad.
    Live(Zeroizing<[u8; 32]>),
    /// A retirement reached it: it is never published again.
    Retired,
}

/// What a restore's plan finds for a pad its image names (KS-5, FIX 5686
/// part 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlannedPad {
    /// The custody the restore takes holds it: a fork copies it.
    Live,
    /// Destroyed there, or committed to be: the erase stands.
    Retired,
    /// No custody the restore takes holds it.
    Missing,
}

pub fn pad_subject(binding: &CustodyBinding, item: &WorldPadItem) -> Result<CustodySubject> {
    binding.subject(CustodyKind::WorldPad, item)
}

/// A pad's bytes, copied out of a custody secret: exactly 32.
pub fn copy_pad(secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut pad = Zeroizing::new([0; 32]);
    if secret.len() != pad.len() {
        return Err(CustodyKind::WorldPad.corrupt());
    }
    pad.copy_from_slice(secret);
    Ok(pad)
}

/// The world a pad item files under.
pub fn item_world(item: &[u8]) -> Result<EntityId> {
    item.get(..16)
        .and_then(|raw| <[u8; 16]>::try_from(raw).ok())
        .and_then(|raw| EntityId::from_bytes(raw).ok())
        .ok_or_else(|| CustodyKind::WorldPad.corrupt())
}
