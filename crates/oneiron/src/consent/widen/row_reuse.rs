//! Reuse the admitted row only when the acting writer sees its exact bytes.

use std::io::{self, Write};

use super::{
    AuthenticatedOwner, ConsentReceipt, StoredProposal, StoredSettlement, VerifiedSlip,
    WIDEN_PROPOSALS, WidenDelta, decode_delta, invalid_row, validate_reference_shape,
    validate_row_fields,
};
use crate::error::GateError;
use crate::{Error, Result, Vault};

struct StoredRowComparison<'a> {
    remaining: &'a [u8],
    equal: bool,
}

impl Write for StoredRowComparison<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.equal {
            match self.remaining.strip_prefix(bytes) {
                Some(remaining) => self.remaining = remaining,
                None => self.equal = false,
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn stored_row_matches(row: &StoredProposal, raw: &[u8]) -> bool {
    let mut comparison = StoredRowComparison {
        remaining: raw,
        equal: true,
    };
    serde_json::to_writer(&mut comparison, row).is_ok()
        && comparison.equal
        && comparison.remaining.is_empty()
}

fn validate_owned_row(row: &StoredProposal, reference: &str, principal_ref: &str) -> Result<()> {
    validate_row_fields(row, reference)?;
    if row.proposal.owner_ref != principal_ref {
        return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            "widen proposal belongs to another holder",
        )));
    }
    Ok(())
}

impl Vault {
    pub(super) fn widen_row_for_principal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        principal_ref: &str,
        reference: &str,
    ) -> Result<StoredProposal> {
        let row = WIDEN_PROPOSALS
            .get(&self.store, txn, &reference.to_owned())?
            .ok_or_else(invalid_row)?;
        validate_owned_row(&row, reference, principal_ref)?;
        Ok(row)
    }

    pub(super) fn accept_widen_matching_reusing(
        &self,
        owner: &AuthenticatedOwner,
        credential: Option<&VerifiedSlip>,
        reference: &str,
        reusable: Option<&mut StoredProposal>,
        matches_delta: impl FnOnce(&[u8]) -> bool,
    ) -> Result<ConsentReceipt> {
        validate_reference_shape(reference)?;
        let key = reference.to_owned();
        self.with_write_txn_grouped(|txn| {
            let mut decoded = None;
            let (row, frozen_matches) = match reusable {
                Some(previous) => {
                    let principal_ref =
                        self.widen_answer_principal_in_txn(&*txn, owner, credential)?;
                    let unchanged = {
                        let raw = WIDEN_PROPOSALS
                            .get_borrowed(&self.store, &*txn, &key)?
                            .ok_or_else(invalid_row)?;
                        stored_row_matches(previous, &raw)
                    };
                    if unchanged {
                        validate_owned_row(previous, reference, principal_ref)?;
                        (previous, true)
                    } else {
                        let current =
                            self.widen_row_for_principal_in_txn(&*txn, principal_ref, reference)?;
                        let frozen_matches =
                            current.proposal.canonical_delta == previous.proposal.canonical_delta;
                        (decoded.insert(current), frozen_matches)
                    }
                }
                None => (
                    decoded
                        .insert(self.owned_widen_row_in_txn(&*txn, owner, credential, reference)?),
                    true,
                ),
            };
            let proposal = &row.proposal;
            if row.resolved
                || proposal.expires_at <= self.store.clock.now_recorded_at()
                || !matches_delta(&proposal.canonical_delta)
                || !frozen_matches
            {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "widen proposal is stale, changed, or resolved",
                )));
            }
            let WidenDelta::Bound(bound) = decode_delta(&proposal.canonical_delta)? else {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "a contact-disclosure offer settles through confirm_contact_disclosure",
                )));
            };
            let receipt = self.create_standing_grant_in_txn(txn, owner, bound)?;
            row.resolved = true;
            row.settlement = Some(StoredSettlement {
                verdict: "accepted".to_owned(),
                decision_id: receipt.decision_id().as_bytes(),
            });
            WIDEN_PROPOSALS.put(&self.store, txn, &key, row)?;
            Ok(receipt)
        })
    }
}
