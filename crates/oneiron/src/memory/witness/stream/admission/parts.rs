//! A continuation's ordered output parts, in its authorized terminal writer.

use super::*;
use crate::store::witness_message_body::StoredMessagePart;

/// The caller has already admitted the stream generation, author, topology
/// and document grant in this transaction. Text has its existing Loro append;
/// this write changes only the ordered parts axis under a full-envelope token.
pub(in crate::memory::witness::stream) fn append_model_parts_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    seed: &Seed,
    text: &str,
    suffix: &[crate::ContentPart],
) -> MessageStreamResult<()> {
    if suffix.is_empty() {
        return Ok(());
    }
    let stored = committed_body(vault, txn, &seed.message_id)?.ok_or(Error::EntityNotFound)?;
    let mut parts: Vec<StoredMessagePart> = stored
        .get("parts")
        .map(|parts| serde_json::from_value(parts.clone()))
        .transpose()
        .map_err(|_| Error::CorruptedIndex("message parts"))?
        .unwrap_or_default();
    let mut suffix: Vec<_> = suffix
        .iter()
        .cloned()
        .map(StoredMessagePart::Inline)
        .collect();
    crate::batch::secret_scan::seal_message_parts_in_txn(
        vault,
        txn,
        seed.message_id,
        parts.len(),
        &mut suffix,
    )?;
    parts.extend(suffix);
    let message = seed.message_with_parts(text.to_owned(), None);
    let mut envelope = witness_message_envelope(&message);
    envelope.parts = Some(parts);
    let body = envelope.encode_body()?;
    let actor = WriteActor::new(seed.actor, seed.class()?);
    let policy = resolve_policy_manifest(&vault.store, txn)?;
    let authorization =
        check_witness_message_ceiling(&vault.store, txn, actor, &envelope, &body, &policy)?;
    crate::entity_doc::append_message_parts_in_txn(
        vault,
        txn,
        &seed.message_id,
        authorization,
        actor,
        seed.occurred_at,
    )?;
    Ok(())
}
