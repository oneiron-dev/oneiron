//! Whole immutable MESSAGE parts, sealed without changing their signed bytes.

use crate::batch::secret_scan::{
    SecretScanMode, seal_whole_part_in_txn, secret_scan_mode_in_txn, write_payload_hit,
};
use crate::error::{Error, Result};
use crate::secret_custody::KeptValues;
use crate::store::known_value_index::KnownValues;
use crate::store::witness_message_body::StoredMessagePart;
use crate::{EntityId, Vault};
use zeroize::{Zeroize, Zeroizing};

/// Considers only fresh inline signed parts. Stored prefixes are not passed
/// here; their references and raw bytes stay unchanged.
pub(crate) fn seal_message_parts_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    message: EntityId,
    start: usize,
    parts: &mut [StoredMessagePart],
) -> Result<()> {
    let signed = |part: &StoredMessagePart| {
        matches!(part, StoredMessagePart::Inline(crate::ContentPart::Reasoning { signature, data, .. })
            if signature.is_some() || data.is_some())
    };
    if !parts.iter().any(&signed)
        || secret_scan_mode_in_txn(&vault.store, txn)? == SecretScanMode::Off
    {
        return Ok(());
    }
    let known = KnownValues::shared_in_writer(&vault.store, txn)?;
    let kept = KeptValues::for_records_in_txn(&vault.store, txn, [message])?;
    let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    for (offset, stored) in parts.iter_mut().enumerate() {
        if !signed(stored) {
            continue;
        }
        let StoredMessagePart::Inline(part) = &*stored else {
            continue;
        };
        let bytes =
            Zeroizing::new(rmp_serde::to_vec_named(part).map_err(|_| {
                Error::InvalidClaimBody("a signed reasoning part is not encodable")
            })?);
        let screened = kept.screened(&message, &bytes).map(Zeroizing::new);
        let scan = screened.as_deref().map_or(bytes.as_slice(), Vec::as_slice);
        let reason = write_payload_hit(scan);
        let known_hit = known.as_ref().is_some_and(|known| {
            !known
                .spans_except(&bytes, |value| kept.holds(&message, value))
                .is_empty()
        });
        if !known_hit && reason.is_none() {
            continue;
        }
        let custody = seal_whole_part_in_txn(
            vault,
            txn,
            message,
            &format!("parts/{}", start + offset),
            &bytes,
            reason,
            at,
        )?;
        if let StoredMessagePart::Inline(crate::ContentPart::Reasoning {
            text,
            signature,
            data,
            ..
        }) = stored
        {
            text.zeroize();
            signature.zeroize();
            data.zeroize();
        }
        *stored = StoredMessagePart::Custody { custody };
    }
    Ok(())
}
