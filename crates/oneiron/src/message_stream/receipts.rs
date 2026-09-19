//! Finality sidecars written inside the witness transaction.
use super::*;
fn key(message: EntityId) -> Vec<u8> {
    [b"message_finality:v1:".as_slice(), message.as_bytes()].concat()
}
pub(crate) fn write_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &MessageFinalityReceipt,
    turn: &WitnessTurn,
    actor: EntityId,
) -> Result<()> {
    let message = EntityId::from_hex(&receipt.message_id)?;
    if receipt.actor_id != actor.to_hex()
        || turn.messages.len() != 1
        || turn.messages[0].id.as_deref() != Some(receipt.message_id.as_str())
        || receipt.text_blake3
            != blake3::hash(turn.messages[0].content.as_bytes())
                .to_hex()
                .to_string()
    {
        return Err(Error::InvariantViolation(
            "stream receipt differs from witnessed message",
        ));
    }
    if vault.get_entity_type_in_txn(txn, &message)? != Some(crate::registry::ENTITY_TYPE_MESSAGE) {
        return Err(Error::EntityNotFound);
    }
    let bytes = rmp_serde::to_vec_named(receipt)
        .map_err(|_| Error::InvariantViolation("stream receipt encode"))?;
    if let Some(old) = vault.store.vault_meta.get(txn, &key(message))?
        && old.as_ref() != bytes.as_slice()
    {
        return Err(Error::InvalidConfig(
            "MESSAGE finality receipt already exists".into(),
        ));
    }
    vault.store.vault_meta.put(txn, &key(message), &bytes)?;
    Ok(())
}
impl Vault {
    pub fn message_finality_receipt(
        &self,
        message: EntityId,
    ) -> Result<Option<MessageFinalityReceipt>> {
        let txn = self.store.env.read_txn()?;
        if self.get_entity_type_in_txn(&txn, &message)?
            != Some(crate::registry::ENTITY_TYPE_MESSAGE)
            || self.archive_tombstone_in_txn(&txn, &message)?.is_some()
        {
            return Ok(None);
        }
        self.store
            .vault_meta
            .get(&txn, &key(message))?
            .map(|bytes| {
                rmp_serde::from_slice(&bytes)
                    .map_err(|_| Error::CorruptedIndex("stream finality receipt"))
            })
            .transpose()
    }
}
