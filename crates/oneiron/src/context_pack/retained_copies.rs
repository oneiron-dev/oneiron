//! Retained courtesy copies stay out of shared retrieval (BIZ-LEGAL-0004 B2,
//! Docs Q09). A non-delete answer keeps the copies the ask covers readable
//! by the owner alone. Other worlds and later deliveries keep their ordinary
//! admission (FIX 1322). The native disclosure predicate owns this rule.

use heed::RoTxn;

use crate::claim::ClaimBody;
use crate::disclosure::DisclosureContext;
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// The pack clamp uses the same admission as other disclosure consumers,
/// including its owner-only exception, retained-copy world/epoch coverage
/// and the sources of a summary's words (`DisclosureContext::admits_in`).
pub(crate) fn clamp_admits(
    ctx: &DisclosureContext,
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
) -> Result<bool> {
    ctx.admits_in(vault, rtxn, id, entity_type, claim_body)
}

/// [`clamp_admits`] for a bounded channel's pre-filter, which holds only the
/// store: the row's own test, without the sources of a summary's words
/// (`DisclosureContext::admits`). Every row it keeps meets [`clamp_admits`]
/// in the pack's candidate sweep.
pub(crate) fn clamp_prefilter_admits(
    ctx: &DisclosureContext,
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
) -> Result<bool> {
    ctx.admits(store, rtxn, id, entity_type, claim_body)
}
