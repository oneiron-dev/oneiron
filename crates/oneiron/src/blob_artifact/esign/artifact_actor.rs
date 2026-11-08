//! Vault-local machine identity for capability uploads and verified seal output.
use super::model::invalid;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Result, TimeRange, Vault};

/// Esign machine actor id. Key: ().
const ACTOR: SideTable<(), EntityId, Raw> = SideTable::new(&side_table::ESIGN_ARTIFACT_ACTOR);

pub(crate) fn actor(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<crate::write_envelope::WriteActor> {
    let id = if let Some(id) = ACTOR.get(&vault.store, txn, &())? {
        if vault.get_entity_type_in_txn(txn, &id)? != Some(crate::registry::ENTITY_TYPE_MACHINE) {
            return Err(invalid("artifact actor is unavailable"));
        }
        id
    } else {
        let id = vault.new_entity_id()?;
        vault
            .batch_in()
            .put_internal(
                &id,
                crate::registry::ENTITY_TYPE_MACHINE,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"esign artifact processing",
            )
            .apply(txn)?;
        ACTOR.put(&vault.store, txn, &(), &id)?;
        id
    };
    Ok(crate::write_envelope::WriteActor::new(
        id,
        crate::edge::EdgeActorClass::System,
    ))
}

/// A separate, policy-nameable writer for verified SealJob outputs only.
pub(crate) fn seal_actor(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<crate::write_envelope::WriteActor> {
    let id = EntityId::derive(crate::entity_id::derived_domains::ESIGN_SEAL_ACTOR, &[])?;
    match vault.get_entity_type_in_txn(txn, &id)? {
        None => vault
            .batch_in()
            .put_internal(
                &id,
                crate::registry::ENTITY_TYPE_MACHINE,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"esign verified seal producer",
            )
            .apply(txn)?,
        Some(crate::registry::ENTITY_TYPE_MACHINE) => {}
        Some(_) => return Err(invalid("seal actor is unavailable")),
    }
    Ok(crate::write_envelope::WriteActor::new(
        id,
        crate::edge::EdgeActorClass::System,
    ))
}
