//! An erased actor leaves the workspace roster (FIX 3520): the member rows,
//! the companion-principal bindings and the member-intent reservations that
//! name them go, each in the erase's own transaction. An id whose entity is
//! no actor scans nothing.

use super::join_receipt::names_no_actor;
use super::*;

/// Erasing `actor` from the roster's member rows: each row that names it as
/// the member, the member's actor, or the companion's PERSON or actor goes,
/// so no roster read returns it or its companion association again.
///
/// # Errors
///
/// Storage errors, or a member row that cannot be read.
pub(crate) fn erase_member_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let doomed: Vec<RosterMemberKey> = MEMBER
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, row)| {
            row.person_ref == *actor
                || row.actor_ref == *actor
                || row.companion_person_ref == Some(*actor)
                || row.companion_actor_ref == Some(*actor)
        })
        .map(|(key, _)| key)
        .collect();
    for key in &doomed {
        MEMBER.delete(&vault.store, wtxn, key)?;
    }
    Ok(())
}

/// Erasing `actor` from the companion-principal bindings: the binding of
/// the companion PERSON it is, and every binding naming it as the
/// principal, go.
///
/// # Errors
///
/// Storage errors, or a binding row that cannot be read.
pub(crate) fn erase_companion_principal_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let doomed: Vec<EntityId> = COMPANION_PRINCIPAL
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(companion, principal)| companion == actor || principal == actor)
        .map(|(companion, _)| companion)
        .collect();
    for companion in &doomed {
        COMPANION_PRINCIPAL.delete(&vault.store, wtxn, companion)?;
    }
    Ok(())
}

/// Erasing `actor` from the member-intent reservations: every workspace
/// onboarding slot it holds as the member goes.
///
/// # Errors
///
/// Storage errors, or a reservation row that cannot be read.
pub(crate) fn erase_member_intent_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let doomed: Vec<MemberIntentKey> = MEMBER_INTENT
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(key, _)| key.person_ref == *actor)
        .map(|(key, _)| key)
        .collect();
    for key in &doomed {
        MEMBER_INTENT.delete(&vault.store, wtxn, key)?;
    }
    Ok(())
}
