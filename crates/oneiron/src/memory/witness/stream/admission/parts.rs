//! A continuation's ordered output parts, in its authorized terminal writer.

use super::*;
use crate::store::witness_message_body::StoredMessagePart;
use zeroize::Zeroizing;

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
    let suffix = stored_suffix_in_txn(vault, txn, seed, parts.len(), suffix)?;
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

/// Only fresh signed parts are considered. The existing prefix, and the
/// direct parts writer's scan-off behavior, stay unchanged.
fn stored_suffix_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    seed: &Seed,
    start: usize,
    suffix: &[crate::ContentPart],
) -> crate::Result<Vec<StoredMessagePart>> {
    use crate::batch::secret_scan::{
        SecretScanMode, seal_whole_part_in_txn, secret_scan_mode_in_txn, write_payload_hit,
    };
    use crate::secret_custody::KeptValues;
    use crate::store::known_value_index::KnownValues;

    let signed = |part: &crate::ContentPart| {
        matches!(part, crate::ContentPart::Reasoning { signature, data, .. }
            if signature.is_some() || data.is_some())
    };
    if !suffix.iter().any(&signed)
        || secret_scan_mode_in_txn(&vault.store, txn)? == SecretScanMode::Off
    {
        return Ok(suffix
            .iter()
            .cloned()
            .map(StoredMessagePart::Inline)
            .collect());
    }
    let known = KnownValues::shared_in_writer(&vault.store, txn)?;
    let origin = seed.message_id;
    let kept = KeptValues::for_records_in_txn(&vault.store, txn, [origin])?;
    let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let mut stored = Vec::with_capacity(suffix.len());
    for (offset, part) in suffix.iter().enumerate() {
        if !signed(part) {
            stored.push(StoredMessagePart::Inline(part.clone()));
            continue;
        }
        let bytes =
            Zeroizing::new(rmp_serde::to_vec_named(part).map_err(|_| {
                Error::InvalidClaimBody("a signed reasoning part is not encodable")
            })?);
        let screened = kept.screened(&origin, &bytes).map(Zeroizing::new);
        let scan = screened.as_deref().map_or(bytes.as_slice(), Vec::as_slice);
        let reason = write_payload_hit(scan);
        let known_hit = known.as_ref().is_some_and(|known| {
            !known
                .spans_except(&bytes, |value| kept.holds(&origin, value))
                .is_empty()
        });
        if !known_hit && reason.is_none() {
            stored.push(StoredMessagePart::Inline(part.clone()));
            continue;
        }
        let handle = seal_whole_part_in_txn(
            vault,
            txn,
            origin,
            &format!("parts/{}", start + offset),
            &bytes,
            reason,
            at,
        )?;
        stored.push(StoredMessagePart::Custody { custody: handle });
    }
    Ok(stored)
}
