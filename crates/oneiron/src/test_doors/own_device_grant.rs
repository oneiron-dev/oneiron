//! Doors for `tests/opened_device_admits_owner_slip.rs` (FIX 23747): an
//! owner's own-device grants retired, as a membership change that ends the
//! member's Owner standing retires them (FIX 3294), a slip bound to a
//! guest's or a member's grant, as the device's fold holds one, and a shared
//! vault's membership as a device holds it once a co-owner's demotion
//! reached it.

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

/// Stands on `vault` shared vault `vault_id`'s membership as a device holds
/// it once the vault's membership rows reached it after a co-owner's
/// demotion: the vault's creation record, `owner`'s PERSON and `owner`'s
/// conferring Owner grant over the vault, and no other member. This vault's
/// live-owner census then names `owner` alone. Returns the grant's id.
///
/// # Errors
///
/// The vault's.
pub fn stand_shared_owner_census(
    vault: &Vault,
    vault_id: u64,
    owner: EntityId,
) -> Result<EntityId> {
    use crate::federation::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
        SharedTrainingSetup, SharedVaultCreation, encode_federation_grant_body,
    };
    use crate::side_table::{self, LegacyJson, SideTable};
    const CREATION: SideTable<(), SharedVaultCreation, LegacyJson> =
        SideTable::new(&side_table::SHARED_VAULT_CREATION);
    crate::test_doors::untangle_regressions::seed_named_person(vault, &owner, "co-owner", 1)?;
    let scope = {
        let txn = vault.store.env.read_txn()?;
        vault.grant_default_scope_in_txn(&txn, FederationGrantRole::Owner, vault_id, owner)?
    };
    let mut grant = FederationGrant::new(
        FederationGrantScope::vault(vault_id),
        owner,
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
    );
    grant.authority_scope = scope;
    let id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            None,
            &encode_federation_grant_body(&grant)?,
        )
        .commit()?;
    let creation = SharedVaultCreation {
        vault_id,
        preset: None,
        owner_ref: owner.to_hex(),
        grant_refs: vec![id.to_hex()],
        policy_ref: None,
        training_setup: SharedTrainingSetup::Pending {
            question_ref: [0; 32],
            created_at: 0,
        },
    };
    vault.with_write_txn(|wtxn| CREATION.put(&vault.store, wtxn, &(), &creation))?;
    let txn = vault.store.env.read_txn()?;
    if !crate::policy_model::holds_live_ownership_in_txn(vault, &txn, &owner)? {
        return Err(Error::InvalidConfig(
            "the vault's live-owner census does not name the co-owner".to_owned(),
        ));
    }
    Ok(id)
}
