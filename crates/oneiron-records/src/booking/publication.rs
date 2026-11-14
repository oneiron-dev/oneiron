//! Moved from `crates/oneiron/src/booking/publication.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY;
use oneiron_store::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY;
use oneiron_store::write_envelope::claim_body::ClaimBody;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Cursor;

pub const BOOKING_PUBLIC_PAGE_PREDICATE: &str = "booking.public_page";

pub const BOOKING_PUBLIC_PAGE_SCHEMA_VERSION: u64 = 1;

/// Actor identity comes from the engine's write envelope, never presentation.
pub fn publication_owner(body: &ClaimBody) -> Option<EntityId> {
    let rmpv::Value::Map(evidence) = body.evidence.as_ref()? else {
        return None;
    };
    let field = |key: &str| {
        let mut matches = evidence
            .iter()
            .filter(|(name, _)| name.as_str() == Some(key));
        let (_, value) = matches.next()?;
        matches.next().is_none().then_some(value)
    };
    if field(WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY)?.as_u64()
        != Some(EdgeActorClass::Human as u64)
    {
        return None;
    }
    let rmpv::Value::Binary(bytes) = field(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)? else {
        return None;
    };
    EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
}
