//! Live support for typed derived claims, resolved in the caller's read snapshot.

use heed::RoTxn;
use rmpv::Value;

use crate::actor_claims::{actor_archive_references, is_actor_claim_predicate};
use crate::dreamer_consolidation::decode_consolidation_evidence;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

use super::ClaimBody;

/// A derived claim with typed TURN citations is readable while at least one
/// cited turn remains live. This is a read-time test: sync can deliver a claim
/// after the deletion that erased its source. Ordinary claims have no such
/// evidence obligation, and claim history remains available through get_claim.
pub(crate) fn has_live_support_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    body: &ClaimBody,
) -> Result<bool> {
    let refs: Vec<EntityId> = if is_actor_claim_predicate(&body.predicate) {
        let chat_lane = body
            .evidence
            .as_ref()
            .and_then(Value::as_map)
            .is_some_and(|entries| {
                entries.iter().any(|(key, value)| {
                    key.as_str() == Some("lane") && value.as_str() == Some("chat")
                })
            });
        if !chat_lane {
            return Ok(true);
        }
        // The canonical actor codec, not matching map keys alone, determines
        // which refs are evidence. A malformed CHAT row cannot claim support.
        let Some(Some((_, turns))) = actor_archive_references(body).map(|refs| refs.chat) else {
            return Ok(false);
        };
        turns
    } else if let Some(evidence) = &body.evidence {
        match decode_consolidation_evidence(evidence) {
            Ok(Some(envelope)) => envelope.refs,
            Ok(None) => return Ok(true),
            Err(_) => return Ok(false),
        }
    } else {
        return Ok(true);
    };
    for id in refs {
        if crate::vault::live_entity_row_in_txn(store, txn, &id)?.is_live() {
            return Ok(true);
        }
    }
    Ok(false)
}
