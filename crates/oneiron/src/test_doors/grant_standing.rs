//! The fold's grant lines and the Grant standing read (Fable pass 28 R1): what the counted
//! acts say of a FEDERATION_GRANT row, and whether the row stands on them.

use crate::authority::GrantFamily;
use crate::federation::{Scope, ScopeAxis};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Result, Vault};

/// The counted act the owner's agent Grant row `grant` stands on at `now`
/// (`Vault::standing_grant_in_txn`); `None` when the row does not stand as his agent Grant.
///
/// # Errors
///
/// A store or authority-fold read failure.
pub fn standing_grant_act(vault: &Vault, grant: EntityId, now: u64) -> Result<Option<[u8; 32]>> {
    standing_act_in_family(vault, grant, GrantFamily::OwnerAgent, now)
}

/// The counted act the shared vault member row `grant` stands on at `now`; `None` when the
/// row does not stand as a member's Grant.
///
/// # Errors
///
/// A store or authority-fold read failure.
pub fn standing_member_grant_act(
    vault: &Vault,
    grant: EntityId,
    now: u64,
) -> Result<Option<[u8; 32]>> {
    standing_act_in_family(vault, grant, GrantFamily::SharedMember, now)
}

fn standing_act_in_family(
    vault: &Vault,
    grant: EntityId,
    family: GrantFamily,
    now: u64,
) -> Result<Option<[u8; 32]>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .standing_grant_in_txn(&txn, grant, family, now)?
        .map(|standing| *standing.act()))
}

/// What the fold says of `grant` on this install: the act of the one giving that counts here,
/// if any, and whether a counted act ended it. `None` when no counted act names it.
///
/// # Errors
///
/// A store or authority-fold read failure.
pub fn grant_line(vault: &Vault, grant: EntityId) -> Result<Option<(Option<[u8; 32]>, bool)>> {
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    Ok(fold
        .grant_line(grant)
        .map(|line| (line.giving.as_ref().map(|(act, _)| *act), line.ended)))
}

/// The live FEDERATION_GRANT body at `id`; `None` when no live Grant row is there.
///
/// # Errors
///
/// A store read failure.
pub fn grant_row(vault: &Vault, id: EntityId) -> Result<Option<Vec<u8>>> {
    let txn = vault.store.env.read_txn()?;
    Ok(match live_entity_row_in_txn(&vault.store, &txn, &id)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } => Some(body),
        _ => None,
    })
}

/// The verbs the live Grant row `id` confers at the vault clock as this vault's readers read it
/// (`Vault::grant_row_at_in_txn`), sorted, an open verb axis as `*`; `None` when the row stands
/// for nothing (pass 28 R4).
///
/// # Errors
///
/// A store, authority-fold or owner-census read failure.
pub fn grant_row_verbs(vault: &Vault, id: EntityId) -> Result<Option<Vec<String>>> {
    let txn = vault.store.env.read_txn()?;
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(&vault.store, &txn, &id)?
    else {
        return Ok(None);
    };
    let now = vault.store.clock.now_recorded_at();
    Ok(vault.grant_row_at_in_txn(&txn, id, &body, now)?.map(|row| {
        match &row.grant().authority_scope.verbs {
            ScopeAxis::Some(verbs) => verbs.iter().cloned().collect(),
            ScopeAxis::All => vec!["*".to_owned()],
            ScopeAxis::Bottom => Vec::new(),
        }
    }))
}

/// The authority scope the live Grant row `id` confers at the vault clock as this vault's readers
/// read it (`Vault::grant_row_at_in_txn`); `None` when the row stands for nothing (pass 28 R4).
///
/// # Errors
///
/// A store, authority-fold or owner-census read failure.
pub fn grant_row_scope(vault: &Vault, id: EntityId) -> Result<Option<Scope>> {
    let txn = vault.store.env.read_txn()?;
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(&vault.store, &txn, &id)?
    else {
        return Ok(None);
    };
    let now = vault.store.clock.now_recorded_at();
    Ok(vault
        .grant_row_at_in_txn(&txn, id, &body, now)?
        .map(|row| row.grant().authority_scope.clone()))
}

/// The authority scope the sync selector export filters the window by under the live Grant row
/// `id` (`sync::selector::standing_federation_grant`, which `filter_window_doc` reads).
///
/// # Errors
///
/// The export's refusal of a row that backs no selector, or a store or authority-fold read
/// failure.
#[cfg(feature = "sync")]
pub fn selector_export_scope(vault: &Vault, id: EntityId) -> Result<Scope> {
    Ok(crate::sync::selector::standing_federation_grant(vault, &id)?.authority_scope)
}

/// The ids of the Grant rows over shared vault `vault_id` that confer to a membership reader at
/// the vault clock (`Vault::shared_vault_grants_in_txn`), in id order.
///
/// # Errors
///
/// A store or authority-fold read failure.
pub fn shared_vault_grant_ids(vault: &Vault, vault_id: u64) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .shared_vault_grants_in_txn(&txn, vault_id)?
        .iter()
        .map(|row| row.id())
        .collect())
}

/// The ids of the owner's git push Grants that stand at this vault's residence
/// (`Vault::git_push_grants_in_txn`), in id order.
///
/// # Errors
///
/// A store or authority-fold read failure.
pub fn standing_git_push_grant_ids(vault: &Vault) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .git_push_grants_in_txn(&txn)?
        .into_iter()
        .map(|standing| standing.id)
        .collect())
}

/// Replays the admin ruling claim `ruling` that `from` stores, with the anchor entity it names
/// as its subject, into `to` through the replay door, as sync delivers them (review #8852).
///
/// # Errors
///
/// [`crate::Error::EntityNotFound`] for a ruling `from` holds no claim row for, a body that
/// does not decode, or the replay door's refusal.
pub fn replicate_admin_ruling(from: &Vault, to: &Vault, ruling: EntityId) -> Result<()> {
    let anchor = {
        let txn = from.store.env.read_txn()?;
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&from.store, &txn, &ruling)?
            .ok_or(crate::Error::EntityNotFound)?;
        let body = raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .ok_or(crate::Error::EntityNotFound)?;
        match crate::claim::decode_claim_body(body, true)?.subject {
            crate::claim::ClaimSubject::Entity(anchor) => anchor,
            _ => return Err(crate::Error::EntityNotFound),
        }
    };
    super::host_taint_replica::replicate_entities(from, to, &[anchor, ruling])
}
