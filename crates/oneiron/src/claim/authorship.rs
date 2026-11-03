//! Read the actor stamped in claim evidence.

use rmpv::Value;

use super::ClaimBody;
use crate::entity_id::EntityId;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY;

pub(crate) fn claim_author(body: &ClaimBody) -> Option<EntityId> {
    let Value::Map(entries) = body.evidence.as_ref()? else {
        return None;
    };
    let mut matches = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY));
    let (_, Value::Binary(bytes)) = matches.next()? else {
        return None;
    };
    if matches.next().is_some() {
        return None;
    }
    EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
}
