//! Vault-local machine identity for capability uploads and verified seal output.
use super::model::invalid;
use crate::{EntityId, Result, TimeRange, Vault};
const ACTOR: &[u8] = b"esign.artifact_actor.v1";
pub(super) fn actor(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<crate::write_envelope::WriteActor> {
    let id = if let Some(bytes) = vault.store.vault_meta.get(txn, ACTOR)? {
        let id = EntityId::from_bytes(
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| invalid("artifact actor encoding"))?,
        )?;
        if vault.get_entity_type_in_txn(txn, &id)? != Some(crate::registry::ENTITY_TYPE_MACHINE) {
            return Err(invalid("artifact actor is unavailable"));
        }
        id
    } else {
        let id = EntityId::now();
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
        vault.store.vault_meta.put(txn, ACTOR, id.as_bytes())?;
        id
    };
    Ok(crate::write_envelope::WriteActor::new(
        id,
        crate::edge::EdgeActorClass::System,
    ))
}
