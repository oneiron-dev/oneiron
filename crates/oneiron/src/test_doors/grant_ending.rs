//! Pass 28 R2c ends, for integration tests: a lapsed sign-in's withdrawal of the owner's
//! agent Grant, a batch delete of a Grant row, the install carrier's load, the Grant
//! standing read in any grant family, and a member row's giving that lands with no row.
//!
//! Every door calls only items that also exist at the parent commit, so the red run can lay
//! this file onto it: no R2c ending item (`end_grant_in_txn`, `carry_owed_grant_ends_logged`,
//! `owe_torn_grant_end_in_txn`, ...) is called here.

use crate::authority::{ActSurface, GrantActBy, GrantActChange, GrantFamily};
use crate::batch::{BatchOp, apply_ops};
use crate::error::{Error, Result};
use crate::federation::{FederationGrant, GrantTermsKey, federation_grant_terms};
use crate::{EntityId, Vault};

/// Withdraws the owner's agent Grant `grant` naming `agent` for a sign-in that lapsed before
/// its client held a token: the row half of the owner's revoke, with no act of his. `false`,
/// with nothing written, for an id that names no live agent grant of `agent`.
///
/// # Errors
///
/// A store failure.
pub fn withdraw_lapsed_agent_grant(
    vault: &Vault,
    grant: EntityId,
    agent: EntityId,
) -> Result<bool> {
    vault.with_write_txn(|txn| vault.withdraw_agent_grant_without_act_in_txn(txn, grant, agent))
}

/// Deletes the row `id` through one `BatchOp::Delete`, as a batch delete tears it: below any
/// vault door, so a FEDERATION_GRANT row torn here is owed its counted end.
///
/// # Errors
///
/// A store failure.
pub fn batch_delete_row(vault: &Vault, id: EntityId) -> Result<()> {
    vault.with_write_txn(|txn| {
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![BatchOp::Delete { id }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    })
}

/// Loads this install's key before a Grant writer opens, so the writer can sign its giving
/// or end; a key that loads now carries what the install owes. A key that does not load
/// leaves the debt owed.
pub fn load_install_carrier(vault: &Vault) {
    vault.load_membership_carrier();
}

/// The counted act the Grant row `grant` stands on at `now` in the family `family` names;
/// `None` when the row does not stand in that family.
///
/// # Errors
///
/// An unknown family name; a store or authority-fold read failure.
pub fn standing_grant_in_family(
    vault: &Vault,
    grant: EntityId,
    family: &str,
    now: u64,
) -> Result<Option<[u8; 32]>> {
    let family = GrantFamily::from_name(family)
        .ok_or_else(|| Error::InvalidConfig(format!("unknown grant family: {family}")))?;
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .standing_grant_in_txn(&txn, grant, family, now)?
        .map(|standing| *standing.act()))
}

/// `person`'s giving of the member row `id` with the terms `grant` states under `terms_key`,
/// the act alone, with no row put: a giving that reaches this install after its row did.
/// Returns the act.
///
/// # Errors
///
/// The act's refusal (no carrier, an act the fold did not count) or a store failure; nothing
/// is written then.
pub fn give_member_grant_act_alone(
    vault: &Vault,
    id: EntityId,
    grant: &FederationGrant,
    terms_key: &GrantTermsKey,
    person: EntityId,
) -> Result<[u8; 32]> {
    vault.with_write_txn(|txn| {
        let terms = federation_grant_terms(id, grant, terms_key)?;
        vault.append_grant_act_in_txn(
            txn,
            GrantActBy::Person {
                person,
                surface: ActSurface::ThisInstall,
            },
            id,
            GrantFamily::SharedMember,
            GrantActChange::Give { terms },
        )
    })
}
