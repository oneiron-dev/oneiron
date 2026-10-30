//! The owner's kit push (CALLS CUSTODY_KIT_PUSH, Engine ruling 10-19
//! 08:0x): the one transition the recovery kit still signs, from an install
//! with no live machine profile, which carries no owner act. Moved whole out
//! of the parent to make room for FIX 7402: only its paths changed.

use super::super::types::{SecretCustodyRecord, SecretCustodyStatus};
use super::{
    CUSTODY_KIT_PUSH, CUSTODY_ORDINARY_CONTROL_SEED, CustodyKitPush, CustodyOrdinaryControlSeed,
    Enactment, kit_request, refused, remember_custody_pieces_in_txn, sign_custody_transition,
    signed_after_held_in_txn, unsigned,
};
use crate::Vault;
use crate::authority::AuthorityFold;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Whether this install may push with the owner's kit (CALLS
/// CUSTODY_KIT_PUSH): it has no live machine profile in the vault, so it
/// carries no owner act and holds for no request. Ordinary control never
/// reaches the seed (CALLS CUSTODY_ORDINARY_CONTROL_SEED).
fn kit_push_allowed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
) -> Result<bool> {
    match (CUSTODY_ORDINARY_CONTROL_SEED, CUSTODY_KIT_PUSH) {
        (CustodyOrdinaryControlSeed::Never, CustodyKitPush::UnprofiledInstallOnly) => {
            let Some(machine) = crate::identity::read_machine_id_in_txn(vault, txn)? else {
                return Ok(true);
            };
            Ok(fold.machine(machine).is_none_or(|folded| {
                folded.chains().any(|(_, chain)| chain.removed)
                    || !folded.chains().any(|(_, chain)| chain.is_live())
            }))
        }
    }
}

impl Vault {
    /// Pushes the current transition of the portable record `secret_ref`
    /// names, signed with the owner anchor of `seed`, the recovery root this
    /// vault pins, its value sealed to `recipients`, each a live linked
    /// install with an importable key (CALLS CUSTODY_KIT_PUSH): the owner's
    /// kit is his authority; the install carries no act. Only an install with
    /// no live machine profile may push, so ordinary control never signs
    /// with the seed (CALLS CUSTODY_ORDINARY_CONTROL_SEED); any other install
    /// rewraps the record as its own holder ([`Vault::rewrap_secret_as_owner`]).
    /// No origin is asked: the kit is the proof. The record keeps its
    /// generation, status and value.
    ///
    /// # Errors
    /// This install has a live machine profile; a proof that is no longer
    /// the live vault owner's; a seed whose root is not the root this vault
    /// pins; a name no record holds; a recipient that is no live linked
    /// install with an importable key, or none of them; the refusals of
    /// [`sign_custody_transition`]; storage errors.
    pub fn sign_custody_with_anchor(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        seed: &crate::world_keys::RecoveryRootSeed,
        secret_ref: &str,
        recipients: &[EntityId],
        at: u64,
    ) -> Result<bool> {
        let vault_id = {
            let rtxn = self.store.env.read_txn()?;
            self.authority_view_readonly_in_txn(&rtxn)?
                .vault_id
                .ok_or_else(unsigned)?
        };
        // The anchor is derived before the write transaction opens.
        let root = seed.public(&vault_id)?;
        let anchor = seed.anchor();
        let transition = self.with_write_txn(|wtxn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, wtxn)?;
            let fold = self.authority_view_readonly_in_txn(wtxn)?;
            if !kit_push_allowed_in_txn(self, wtxn, &fold)? {
                return Err(Error::InvalidConfig(
                    "this install has a live machine profile, so it carries the owner's act: \
                     rewrap the secret with this install as its holder (`oneiron secrets \
                     rewrap`); the kit pushes only from an install with no profile"
                        .into(),
                ));
            }
            if fold.vault_id != Some(vault_id)
                || fold
                    .pinned_root
                    .as_ref()
                    .is_none_or(|pin| pin.id != root.id || pin.anchor_key != root.anchor_key)
            {
                return Err(Error::InvalidConfig(
                    "the seed's root is not the root this vault pins".into(),
                ));
            }
            let id = super::super::resolve_secret_ref_in_txn(&self.store, wtxn, secret_ref)?
                .ok_or_else(|| {
                    Error::Secret(crate::error::SecretError::SecretRefNotFound {
                        name: secret_ref.to_owned(),
                    })
                })?;
            let Some(record) = super::super::read_secret_custody_in_txn(&self.store, wtxn, &id)?
            else {
                return Ok(None);
            };
            let record = WipedRecord(record);
            let permits = super::super::control::permits::permits_for(&fold, recipients).map_err(
                |machine| {
                    Error::InvalidConfig(format!(
                        "recipient {} is not a linked install with an importable encryption key; \
                     nothing was written",
                        machine.to_hex()
                    ))
                },
            )?;
            let keyed = super::super::control::permits::permitted_keys(&fold, &permits)
                .ok_or_else(|| refused("a recipient's key changed"))?;
            let keyed = if record.0.status == SecretCustodyStatus::Revoked {
                Vec::new()
            } else {
                keyed
            };
            // FIX 6053: the push records the custody request it enacts, under
            // the pinned kit's authority; a fault leaves it as before.
            let request = if keyed.is_empty() {
                [0; 32]
            } else {
                kit_request::record_kit_request_in_txn(
                    self,
                    wtxn,
                    &fold,
                    actor,
                    id,
                    record.0.rotation_generation,
                    &permits,
                    (&anchor, root.id),
                )
            };
            let enactment = Enactment {
                request,
                input: None,
                permits: &keyed,
            };
            let signed_at = signed_after_held_in_txn(self, wtxn, id, &record.0, at)?;
            let pieces =
                sign_custody_transition(&fold, &anchor, id, &record.0, enactment, signed_at)?;
            Ok(remember_custody_pieces_in_txn(self, wtxn, &pieces)?.then_some(pieces))
        })?;
        #[cfg(feature = "sync")]
        if transition.is_some() {
            self.refresh_custody_in_live_windows();
        }
        Ok(transition.is_some())
    }
}

/// A record whose value is wiped when it drops, on every path.
struct WipedRecord(SecretCustodyRecord);

impl Drop for WipedRecord {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0.value_bytes);
    }
}
