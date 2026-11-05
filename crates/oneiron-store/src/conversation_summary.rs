//! Coverage references encoded in stored conversation summaries.

use oneiron_base::error::{Error, RecordError, Result};
use oneiron_contracts::entity_id::EntityId;

/// The records a persisted `conversation.summary` claim covers, or `None` for
/// any other claim. A value that is not a map with a `covers` array of 16-byte
/// ids is malformed, and a malformed summary is denied like any other.
pub fn conversation_summary_covers(
    claim: &crate::write_envelope::claim_body::ClaimBody,
) -> Result<Option<Vec<EntityId>>> {
    if claim.predicate != "conversation.summary" {
        return Ok(None);
    }
    let malformed = || Error::Record(RecordError::InvalidScopeSummary("summary coverage"));
    let rmpv::Value::Map(entries) = &claim.value else {
        return Err(malformed());
    };
    let Some((_, rmpv::Value::Array(covers))) =
        entries.iter().find(|(k, _)| k.as_str() == Some("covers"))
    else {
        return Err(malformed());
    };
    covers
        .iter()
        .map(|covered| {
            let rmpv::Value::Binary(raw) = covered else {
                return Err(malformed());
            };
            let bytes: [u8; 16] = raw.as_slice().try_into().map_err(|_| malformed())?;
            EntityId::from_bytes(bytes).map_err(|_| malformed())
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}
