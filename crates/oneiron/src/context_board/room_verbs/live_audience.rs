//! What a room's live speakers add to its ceiling (FIX 1388/1389): their
//! entry refs as audience terms beside the members, and an unknown's
//! clearance. Never a world, a peer read or standing: those stay the
//! members' alone, and an entry ref is never proof of membership.

use crate::conversation::RoomLiveSpeakerEntries;
use crate::federation::Scope;
use crate::{EntityId, Vault};

/// `members` with the entry refs of `live`, sorted and unique: the audience
/// every row the room reads must pass. It names who hears the room and is
/// never its membership.
pub(super) fn with_entries(
    mut members: Vec<EntityId>,
    live: &RoomLiveSpeakerEntries,
) -> Vec<EntityId> {
    members.extend_from_slice(live.entry_refs());
    members.sort_unstable();
    members.dedup();
    members
}

impl Vault {
    /// The clearance term `live` adds to its room's meet: an unknown
    /// party's ([`crate::disclosure::RoomParty::Unknown`]) when a live call
    /// brings a listener the members do not cover, else none. A live
    /// speaker's entry is no contact, so it never clears wider than that.
    pub(crate) fn live_speaker_clearance_in(
        &self,
        txn: &heed::RoTxn<'_>,
        live: &RoomLiveSpeakerEntries,
    ) -> crate::Result<Option<Scope>> {
        if !live.reads_unknown() {
            return Ok(None);
        }
        crate::disclosure::RoomParty::Unknown.clearance_in(self, txn)
    }
}
