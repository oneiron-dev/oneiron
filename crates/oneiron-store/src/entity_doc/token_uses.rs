//! The stamp tokens an entity document names, recorded as it is written
//! (FIX 11965): its birth's token and each new commit's stamp, under the
//! document's entity, so an actor erase's hold check finds a held record's
//! tokens without a history walk (`provenance::actor_stamp`).

use heed::RwTxn;
use loro::VersionVector;

use crate::entity_doc::document::Stamped;
use crate::entity_doc::document::parse_stamp;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The token an entity document's engine stamp names (FIX 10930); none for
/// a stamp that names no one, or any other message.
pub fn engine_stamp_token(message: &str) -> Option<EntityId> {
    match parse_stamp(Some(message)) {
        Stamped::Live(stamp) => Some(stamp.token),
        Stamped::Erased | Stamped::NotStamped => None,
    }
}
