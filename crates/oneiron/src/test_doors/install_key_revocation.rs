//! Doors for `tests/owner_enrol.rs` Part 3 (REVIEW-7987): a host-root
//! revocation of this install's own key, signed on the vault's heads and held
//! back, so a test delivers it after rows that key signs meanwhile.

use crate::Vault;
use crate::authority::{
    AuthorityKey, AuthorityOp, HostSlipIssuer, encode_authority_log_entry_body,
};
use crate::error::Result;

/// A `RevokeDevice` of this install's key, signed under the host root
/// `issuer` on the vault's heads now, as the bytes a sync delivers later. It
/// is not stored.
///
/// # Errors
///
/// A storage error, or an install with no key yet.
pub fn withheld_revocation_of_this_install(
    vault: &Vault,
    issuer: &HostSlipIssuer,
) -> Result<Vec<u8>> {
    let key = {
        let txn = vault.store.env.read_txn()?;
        crate::identity::read_machine_signing_key_in_txn(vault, &txn)?
    }
    .ok_or_else(crate::authority::invalid_authority)?;
    let op = AuthorityOp::RevokeDevice {
        revoked_key: AuthorityKey::Ed25519(key.verifying_key().to_bytes()),
    };
    let entry = vault.withheld_host_root_entry_for_test(issuer, op)?;
    Ok(encode_authority_log_entry_body(&entry)?)
}
