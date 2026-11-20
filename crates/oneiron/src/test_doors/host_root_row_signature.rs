//! Fixture door for the owner reserve's revoked owner key test
//! (OWNER-RESERVE-REVOKED-OWNER-KEY = A): the host root's signature on an
//! authority row the test builds, such as the owner's `RevokeDevice` of an
//! enrolled owner key, which no public door writes.

use crate::Result;
use crate::authority::{AuthorityLogEntry, HostSlipIssuer, authority_transcript};

/// Signs `entry` as `issuer`'s host root: its primary signature over the
/// row's authority transcript, the Ed25519 signature the host root puts on
/// every row it writes.
///
/// # Errors
/// The transcript's.
pub fn sign_authority_row_as_host_root(
    issuer: &HostSlipIssuer,
    entry: &mut AuthorityLogEntry,
) -> Result<()> {
    let transcript = authority_transcript(entry)?;
    entry.signer.signature = issuer.sign_claim_handoff(&transcript).to_vec();
    Ok(())
}

/// Signs the cosign of `entry` that names `issuer`'s key, as an owner key's
/// proof beside the row's carrier (row
/// OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS): the same transcript the
/// carrier signs, since every key is in the entry before either signs.
///
/// # Errors
/// The transcript's; an entry with no cosign naming `issuer`'s key.
pub fn cosign_authority_row_as_host_root(
    issuer: &HostSlipIssuer,
    entry: &mut AuthorityLogEntry,
) -> Result<()> {
    let transcript = authority_transcript(entry)?;
    let key = issuer.public_key();
    let cosign = entry
        .cosigns
        .iter_mut()
        .find(|cosign| cosign.public_key == key)
        .ok_or(crate::error::Error::InvariantViolation(
            "no cosign of the row names the host root",
        ))?;
    cosign.signature = issuer.sign_claim_handoff(&transcript).to_vec();
    Ok(())
}
