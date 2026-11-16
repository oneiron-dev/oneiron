//! Fixture that deletes the PERSON the host key binds while keeping its Active
//! binding (L9-52 b): the key binds a live stand-in for the delete, then binds
//! the deleted person again.

use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Deletes `person`, the actor the host key binds, as a delete did before
/// the last-owner guard (L9-52 b) refused it: the key binds a live stand-in
/// for the delete, then binds the deleted `person` again at `class`. The
/// test reads a deleted actor that still holds an Active binding. Returns
/// whether the row existed.
pub(crate) fn delete_bound_person(
    vault: &Vault,
    issuer: &crate::authority::HostSlipIssuer,
    person: EntityId,
    class: &str,
    reason: crate::deletion::DeleteReason,
) -> bool {
    let stand_in = EntityId::now();
    vault
        .put_entity(
            &stand_in,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"stand-in",
        )
        .expect("FIXTURE: a live stand-in person");
    vault
        .bind_host_actor_for_test(issuer, stand_in, "human")
        .expect("FIXTURE: the host key binds the stand-in");
    let existed = vault
        .delete_entity_with_reason(&person, reason)
        .expect("FIXTURE: the host deletes the person")
        .existed;
    vault
        .bind_host_actor_for_test(issuer, person, class)
        .expect("FIXTURE: the host key binds the deleted person again");
    existed
}
