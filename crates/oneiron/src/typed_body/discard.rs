//! Letting an open fork's unlanded work go (FIX 10016): its opener's or the
//! vault owner's own act, or a settlement's rejection.

use heed::{RoTxn, RwTxn};

use super::{BodyActor, FORK_DOCS, FORKS, TypedBodyFork, TypedForkState, invalid, validate_actor};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;

/// Abandons an open fork's unlanded work: its opener's own act, or the
/// vault owner's (FIX 10016). Another actor's fork is let go only by its
/// proposal's settlement ([`discard_admitted_typed_body_fork_in_txn`]). The
/// actor is checked in this, the deleting, transaction.
pub(crate) fn discard_typed_body_fork_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    fork: &EntityId,
    actor: WriteActor,
) -> Result<TypedBodyFork> {
    let record = open_fork_record(vault, txn, entity, fork)?;
    validate_actor(vault, txn, actor)?;
    if !record.opener.is(actor.entity_ref()) && !is_vault_owner(vault, txn, actor) {
        return Err(invalid(
            "only a fork's opener or the vault's owner discards it; another's is rejected through its proposal",
        ));
    }
    discard_open_fork_in_txn(vault, txn, record, actor)
}

/// Abandons an open fork whose proposal an office settlement rejected
/// (OF-505, FIX 10016): [`discard_typed_body_fork_in_txn`] without its
/// opener check. A person's word from outside the opener's lineage is what
/// lets it go; only that settlement constructs the admission, for this
/// fork and its caller.
pub(crate) fn discard_admitted_typed_body_fork_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    fork: &EntityId,
    actor: WriteActor,
    admission: &crate::office_body::DiscardAdmission,
) -> Result<TypedBodyFork> {
    if admission.artifact() != entity
        || admission.fork() != fork
        || *admission.caller() != actor.entity_ref()
    {
        return Err(invalid("the admission names another fork or caller"));
    }
    let record = open_fork_record(vault, txn, entity, fork)?;
    validate_actor(vault, txn, actor)?;
    discard_open_fork_in_txn(vault, txn, record, actor)
}

fn open_fork_record(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    fork: &EntityId,
) -> Result<TypedBodyFork> {
    let record = FORKS
        .get(&vault.store, txn, &(*entity, *fork))?
        .ok_or(Error::EntityNotFound)?;
    if record.state != TypedForkState::Open {
        return Err(invalid("the fork is not open"));
    }
    Ok(record)
}

fn discard_open_fork_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    mut record: TypedBodyFork,
    actor: WriteActor,
) -> Result<TypedBodyFork> {
    let key = (record.entity, record.fork);
    record.state = TypedForkState::Discarded {
        by: BodyActor::Actor(actor.entity_ref()),
        at: vault.now_recorded_at(),
    };
    FORKS.put(&vault.store, txn, &key, &record)?;
    FORK_DOCS.delete(&vault.store, txn, &key)?;
    Ok(record)
}

/// Whether `actor` is the vault's owner: a person the authority log binds
/// as it, as the owner verbs judge it.
fn is_vault_owner(vault: &Vault, txn: &RoTxn<'_>, actor: WriteActor) -> bool {
    actor.actor_class() == crate::EdgeActorClass::Human
        && crate::memory::verify_owner_actor_binding_in_txn(vault, txn, actor.entity_ref()).is_ok()
}
