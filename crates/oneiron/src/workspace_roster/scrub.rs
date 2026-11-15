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

/// Every roster actor `person`'s memberships speak through
/// ([MEMBER-REMOVAL-KEEPS-ACTOR-GRANTS]): the `actor_ref` of each MEMBER row,
/// in any workspace, whose `person_ref` names `person`, in id order. A
/// merged member PERSON still matches: besides the exact row, a row matches
/// when the heads [`Vault::resolve_entity_in_txn`] reads for its `person_ref`
/// meet the heads it reads for `person`.
///
/// Actor refs only: never a `companion_actor_ref` or a companion's PERSON.
/// A work companion is her own principal, not her member's voice, so her
/// rows stay whatever removes her member.
///
/// # Errors
///
/// Storage errors, a member row that cannot be read, or an identity
/// projection that cannot be resolved.
pub(crate) fn member_actor_refs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: &EntityId,
) -> Result<Vec<EntityId>> {
    let member_heads = vault.resolve_entity_in_txn(txn, person)?;
    let mut actors = Vec::new();
    for (_, row) in MEMBER.scan(&vault.store, txn)? {
        if row.person_ref == *person {
            actors.push(row.actor_ref);
            continue;
        }
        if vault
            .resolve_entity_in_txn(txn, &row.person_ref)?
            .iter()
            .any(|head| member_heads.contains(head))
        {
            actors.push(row.actor_ref);
        }
    }
    actors.sort();
    actors.dedup();
    Ok(actors)
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
