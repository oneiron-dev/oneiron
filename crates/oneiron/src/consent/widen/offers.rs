//! Owner-scoped pages of the existing open contact-disclosure offers.

use std::ops::Bound;

use super::{
    AuthenticatedOwner, ContactDisclosureProposal, WIDEN_PROPOSALS, WidenDelta, WidenProposal,
    decode_delta, validate_reference_shape, validate_row,
};
use crate::{Result, Vault};

impl Vault {
    /// Lists this owner's open contact-disclosure offers in proposal-reference order.
    /// Open means unresolved and unexpired, as at the existing confirm door.
    /// The cursor is the last returned reference; other owners' rows and terminal
    /// rows never consume a page slot. Listing answers nothing and grants nothing.
    pub fn contact_disclosure_offers(
        &self,
        owner: &AuthenticatedOwner,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(
        Vec<(WidenProposal, ContactDisclosureProposal)>,
        Option<String>,
    )> {
        let txn = self.store.env.read_txn()?;
        let principal = owner.principal_ref_in_txn(self, &txn)?;
        if let Some(after) = after {
            validate_reference_shape(after)?;
        }
        if limit == 0 {
            return Ok((Vec::new(), None));
        }
        let now = self.store.clock.now_recorded_at();
        let after = after.map(str::to_owned);
        let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
        let mut offers: Vec<(WidenProposal, ContactDisclosureProposal)> = Vec::new();
        for entry in WIDEN_PROPOSALS.iter_range(&self.store, &txn, start, Bound::Unbounded)? {
            let (reference, row) = entry?;
            if row.resolved || row.proposal.owner_ref != principal || row.proposal.expires_at <= now
            {
                continue;
            }
            let Ok(row) = validate_row(row, &reference) else {
                continue;
            };
            let WidenDelta::ContactDisclosure(offer) = decode_delta(&row.proposal.canonical_delta)?
            else {
                continue;
            };
            if offers.len() == limit {
                let next = offers
                    .last()
                    .map(|(proposal, _)| proposal.proposal_ref.clone());
                return Ok((offers, next));
            }
            offers.push((row.proposal, offer));
        }
        Ok((offers, None))
    }
}
