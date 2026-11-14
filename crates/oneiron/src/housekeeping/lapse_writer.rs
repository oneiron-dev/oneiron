//! The engine writer a host-run commitment lapse lands under (ARCH-0005a
//! #housekeeping-open; Engine ruling on L9-42-LAPSE-WRITER = A, after
//! FIT-INSTALL-DESIGN = A). The housekeeping pass lapses an overdue instance
//! because its due time passed, not because a person acted, so the lapse is a
//! System act: this one engine MACHINE writes it, signed with the signer the
//! host retained for it. The default manifest binds one actor-ceiling row to
//! this writer alone; class `system` as a whole keeps default-deny.
//!
//! A vault whose policy names no ceiling for the writer (an owner-authored
//! manifest written before the row), or whose host retained no signer for
//! it, keeps the owner's Human lapse it had before. This module never writes
//! a manifest: an owner's own policy decides whether the writer may write,
//! and only an untouched seeded manifest takes the shipped one on open
//! (`gate::policy_upgrade`), as for every shipped row.

use crate::edge::EdgeActorClass;
use crate::entity_id::derived_domains::COMMITMENT_LAPSE_ACTOR;
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::{EntityId, Error, Result, TimeRange, Vault};

/// The commitment lapse writer's id: derived, so every device names the same
/// one.
pub(crate) fn commitment_lapse_writer_id() -> Result<EntityId> {
    EntityId::derive(COMMITMENT_LAPSE_ACTOR, &[])
}

/// The commitment lapse writer's MACHINE row, put on first use. A row of
/// another type under its id refuses.
pub(crate) fn ensure_commitment_lapse_writer_machine(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<EntityId> {
    let id = commitment_lapse_writer_id()?;
    match vault.get_entity_type_in_txn(txn, &id)? {
        None => vault
            .batch_in()
            .put_internal(
                &id,
                ENTITY_TYPE_MACHINE,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"commitment lapse writer",
            )
            .apply(txn)?,
        Some(ENTITY_TYPE_MACHINE) => {}
        Some(_) => {
            return Err(Error::InvariantViolation(
                "the commitment lapse writer is unavailable",
            ));
        }
    }
    Ok(id)
}

/// The writer the housekeeping pass lapses under on `vault`: the commitment
/// lapse writer when the policy in force names a `system` ceiling for it and
/// the host retained its signer; `None` keeps the owner's Human lapse.
pub(super) fn commitment_lapse_writer(vault: &Vault) -> Result<Option<EntityId>> {
    let writer = commitment_lapse_writer_id()?;
    if !vault.has_retained_machine_signer(writer)? {
        return Ok(None);
    }
    let ceiling_named = vault
        .gate_actor_ceiling_exists(EdgeActorClass::System.gate_actor_class(), &writer.to_hex())?;
    Ok(ceiling_named.then_some(writer))
}
