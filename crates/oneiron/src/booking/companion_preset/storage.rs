//! Companion proposal row storage, token hashing, and error constructors.

use crate::Vault;
use crate::booking::BookingError;
use crate::booking::lifecycle::{digest_with, read_meta_bytes};
use crate::error::Error;

use super::proposal::{CompanionProposalRow, PARTICIPANT_TOKEN_DOMAIN};
use super::{COMPANION_PROPOSAL_META_PREFIX, ProposalId};
// -------------------------------------------------------------------------
// Storage
// -------------------------------------------------------------------------
/// Row-format byte on the companion proposal `vault_meta` value.
const COMPANION_ROW_VERSION: u8 = 1;
/// Reads the row and applies the lazy expiry check.
///
/// The row is not deleted on expiry. A proposal occupies no inventory, and the
/// companion may still want to read a lapsed one to re-propose from it;
/// correctness is this liveness test, never a cleanup that ran.
pub(super) fn load_live_row(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    key: &[u8],
    now_utc: u64,
) -> Result<CompanionProposalRow, BookingError> {
    let Some(raw) = read_meta_bytes(vault, rtxn, key)? else {
        return Err(refused("no such proposal"));
    };
    let row = decode_row(&raw)?;
    if now_utc >= row.proposal.expires_at {
        return Err(refused("this proposal has expired"));
    }
    Ok(row)
}
pub(super) fn proposal_meta_key(proposal_id: ProposalId) -> Vec<u8> {
    let mut key = Vec::with_capacity(COMPANION_PROPOSAL_META_PREFIX.len() + proposal_id.0.len());
    key.extend_from_slice(COMPANION_PROPOSAL_META_PREFIX);
    key.extend_from_slice(&proposal_id.0);
    key
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
pub(super) fn encode_row(row: &CompanionProposalRow) -> Result<Vec<u8>, BookingError> {
    let mut out = vec![COMPANION_ROW_VERSION];
    out.extend(
        rmp_serde::to_vec_named(row)
            .map_err(|error| refused(format!("proposal row does not encode: {error}")))?,
    );
    Ok(out)
}
pub(super) fn decode_row(raw: &[u8]) -> Result<CompanionProposalRow, BookingError> {
    let Some((&version, body)) = raw.split_first() else {
        return Err(refused("proposal row is empty"));
    };
    if version != COMPANION_ROW_VERSION {
        return Err(refused("proposal row version is unsupported"));
    }
    rmp_serde::from_slice(body)
        .map_err(|error| refused(format!("proposal row does not decode: {error}")))
}
pub(super) fn refused(detail: impl Into<String>) -> BookingError {
    BookingError::InvalidConstraint(detail.into())
}
pub(super) fn surface<T>(result: std::result::Result<T, Error>) -> Result<T, BookingError> {
    result.map_err(|error| BookingError::Surface(error.to_string()))
}
