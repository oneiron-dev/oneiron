//! Retained courtesy copies stay out of shared retrieval (BIZ-LEGAL-0004 B2,
//! Docs Q09). A non-delete answer keeps the copies the ask covers readable
//! by the owner alone. Other worlds and later deliveries keep their ordinary
//! admission (FIX 1322). The native disclosure predicate owns this rule.

use heed::RoTxn;

use crate::claim::ClaimBody;
use crate::disclosure::DisclosureContext;
use crate::store::Store;
use crate::{EntityId, Result};

/// The pack clamp uses the same admission as other disclosure consumers,
/// including its owner-only exception and retained-copy world/epoch coverage.
pub(crate) fn clamp_admits(
    ctx: &DisclosureContext,
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
) -> Result<bool> {
    ctx.admits(store, rtxn, id, entity_type, claim_body)
}
