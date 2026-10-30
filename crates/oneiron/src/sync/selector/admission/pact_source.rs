//! The source vault a guest's update names outside the peer door (FIX 3663).
//! The entry points are `admit_federated_window_update_under` and
//! `staged_guest_source`.
//! Owned by `super`.
//!
//! A guest's CLAIMs land in the foreign WORLD copies its source vault and the
//! sender's worlds derive (FIX 3497). The peer door reads that source from
//! the authority fold's pact state. The public door reads it the same way,
//! from the grant the update came under; a staged foreign artifact names it
//! by the vault its manifest says exported it.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::sync::types::WindowKey;

use super::{FederationAdmissionRole, ImportGrading, admit_window_update};

/// [`super::admit_federated_window_update`] for an update delivered under the
/// federation grant `grant`, each part with the window it imports into, the
/// update's own first. A guest's CLAIMs land in the foreign WORLD copies the
/// source vault of the grant's one active pact names (FIX 3497, FIX 3663),
/// read from the authority fold, never from the caller; a guest's update
/// whose grant has no such pact has no source and is refused, never landed
/// as this vault's own, as the peer door refuses it. A member's update
/// routes nothing.
///
/// # Errors
///
/// A refusal of the update, or a guest grant with no active pact.
#[cfg(feature = "sync")]
pub fn admit_federated_window_update_under(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    grant: &EntityId,
) -> Result<Vec<(WindowKey, Vec<u8>)>> {
    let source = match role {
        FederationAdmissionRole::Member => None,
        FederationAdmissionRole::Guest => Some(pact_source_vault(vault, grant)?),
    };
    let admitted = admit_window_update(
        vault,
        key,
        update,
        role,
        None,
        ImportGrading::Imported {
            scale: super::super::DEFAULT_FEDERATED_CONFIDENCE_SCALE,
        },
        source.as_ref(),
    )?;
    Ok(admitted
        .parts()
        .map(|part| (part.key().clone(), part.bytes().to_vec()))
        .collect())
}

/// The source vault the fold's state of `grant`'s one active pact names.
#[cfg(feature = "sync")]
fn pact_source_vault(vault: &Vault, grant: &EntityId) -> Result<[u8; 32]> {
    let txn = vault.store.env.read_txn()?;
    vault
        .authority_view_readonly_in_txn(&txn)?
        .active_pact_delivery(grant)
        .map(|delivery| delivery.source_vault)
        .map_err(|_| {
            super::super::codec::selector_err(crate::error::SyncSelectorValidation::GrantInactive)
        })
}

/// The source vault a staged foreign artifact's guest content lands under:
/// the vault its manifest says exported it (`classification`), when that is
/// not this vault. `None` when the manifest names no vault, or names this
/// one, an owner's own export restoring: that content routes nothing.
#[cfg(feature = "sync")]
pub(crate) fn staged_guest_source(
    classification: &crate::batch::export::VaultImportReceipt,
) -> Option<[u8; 32]> {
    classification
        .exported_vault_id
        .filter(|exported| classification.local_vault_id != Some(*exported))
}
