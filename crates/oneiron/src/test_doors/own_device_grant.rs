//! Doors for `tests/opened_device_admits_owner_slip.rs` (FIX 23747): an
//! owner's own-device grants retired, as a membership change that ends the
//! member's Owner standing retires them (FIX 3294), and a slip bound to a
//! guest's or a member's grant, as the device's fold holds one.

use std::collections::BTreeSet;

use crate::authority::{HostSlipIssuer, SlipClaims};
use crate::error::{Error, Result};
use crate::federation::Scope;
use crate::{EntityId, Vault};

/// Retires `member`'s live own-device grants in one writer, as a role change
/// that ends their Owner standing does, and returns the grants' ids.
pub fn retire_own_device_grants(vault: &Vault, member: EntityId) -> Result<Vec<EntityId>> {
    vault.with_write_txn(|wtxn| vault.retire_own_device_grants_in_txn(wtxn, member))
}

/// Mints, under the host's `issuer`, a live slip for `holder` (PERSON) that
/// names `grant_ref`, in the signed shape a guest's slip takes
/// (`actor_class` `None`, `Vault::mint_guest_slip`) or a member's invitee
/// slip (`Some("human")`, FIX 12441): the host's plain mint, with no parent,
/// share, delegation or approving member, at top scope for `lifetime_secs`,
/// bound to `binding_key`. The guest and member doors' checks on the grant
/// itself are not run here: a device judges only the signed mint its
/// authority history brings. Returns the slip's id.
///
/// # Errors
///
/// A vault whose fold names no vault id (`InvalidConfig`), a refused mint,
/// and storage errors.
pub fn mint_grant_bound_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    holder: EntityId,
    grant_ref: EntityId,
    actor_class: Option<&str>,
    binding_key: [u8; 32],
    lifetime_secs: u64,
) -> Result<[u8; 32]> {
    use rand_core::{OsRng, RngCore};
    vault.with_write_txn(|wtxn| {
        let vault_id = vault
            .authority_view_readonly_in_txn(wtxn)?
            .vault_id
            .ok_or_else(|| Error::InvalidConfig("the fold names no vault id".to_owned()))?;
        let now = vault.instant_in_txn(wtxn)?.secs();
        let mut slip_id = [0; 32];
        OsRng.fill_bytes(&mut slip_id);
        let claims = SlipClaims {
            slip_id,
            vault_id,
            parent_id: None,
            holder_ref: holder.to_hex(),
            binding_key,
            scope: Scope::top(),
            issued_at: now,
            expires_at: now.saturating_add(lifetime_secs),
            ttl_secs: lifetime_secs,
            single_use: false,
            records: BTreeSet::new(),
            channels: BTreeSet::new(),
            actor_class: actor_class.map(str::to_owned),
            org_ref: None,
            grant_ref: Some(grant_ref.to_hex()),
            invitation_ref: None,
            share_ref: None,
            delegation: None,
            comm: None,
            trusted_contact: None,
            seat_claim: None,
        };
        Ok(vault.mint_slip_in_txn(wtxn, issuer, claims)?.claims.slip_id)
    })
}
