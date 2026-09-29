//! Companion proposal row storage, token hashing, and error constructors.

use crate::Vault;
use crate::booking::BookingError;
use crate::booking::lifecycle::digest_with;
use crate::error::Error;
use crate::side_table::{self, SideTable, VersionedNamed};

use super::ProposalId;
use super::proposal::{CompanionProposalRow, PARTICIPANT_TOKEN_DOMAIN};
// -------------------------------------------------------------------------
// Storage
// -------------------------------------------------------------------------
/// Row-format byte on the companion proposal `vault_meta` value.
const COMPANION_ROW_VERSION: u8 = 1;

/// The persisted row: proposal, tap log, and confirmation. Key: hash32 (the
/// opaque [`ProposalId`]).
pub(super) const PROPOSAL: SideTable<
    [u8; 32],
    CompanionProposalRow,
    VersionedNamed<COMPANION_ROW_VERSION>,
> = SideTable::new(&side_table::BOOKING_COMPANION_PROPOSAL);

/// Reads the row and applies the lazy expiry check.
///
/// The row is not deleted on expiry. A proposal occupies no inventory, and the
/// companion may still want to read a lapsed one to re-propose from it;
/// correctness is this liveness test, never a cleanup that ran.
pub(super) fn load_live_row(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: ProposalId,
    now_utc: u64,
) -> Result<CompanionProposalRow, BookingError> {
    let Some(row) = surface(PROPOSAL.get(&vault.store, rtxn, &id.0))? else {
        return Err(refused("no such proposal"));
    };
    if now_utc >= row.proposal.expires_at {
        return Err(refused("this proposal has expired"));
    }
    Ok(row)
}

/// The persisted hash of one participant's token, bound to its proposal.
///
/// The proposal id is part of the material, so the same raw token presented
/// against a different proposal hashes to something that proposal never issued.
pub(super) fn participant_token_hash(proposal_id: ProposalId, raw_token: &str) -> [u8; 32] {
    let mut material = Vec::with_capacity(proposal_id.0.len() + raw_token.len());
    material.extend_from_slice(&proposal_id.0);
    material.extend_from_slice(raw_token.as_bytes());
    digest_with(PARTICIPANT_TOKEN_DOMAIN, &material)
}
pub(super) fn refused(detail: impl Into<String>) -> BookingError {
    BookingError::InvalidConstraint(detail.into())
}
pub(super) fn surface<T>(result: std::result::Result<T, Error>) -> Result<T, BookingError> {
    result.map_err(|error| BookingError::Surface(error.to_string()))
}
