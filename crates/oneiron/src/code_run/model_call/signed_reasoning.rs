//! Whole signed reasoning parts use existing custody, never text masking.

use zeroize::Zeroizing;

use super::{MODEL_CALLS, ModelCallPartRef, ModelCallRecord};
use crate::batch::secret_scan::{
    SecretScanMode, seal_whole_part_in_txn, secret_scan_mode_in_txn, side_row_origin,
    write_payload_hit,
};
use crate::secret_custody::KeptValues;
use crate::store::known_value_index::KnownValues;
use crate::{ContentPart, Error, Result, Vault};

pub(super) fn seal_signed_reasoning_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &mut ModelCallRecord,
) -> Result<()> {
    let signed = |part: &ContentPart| {
        matches!(part, ContentPart::Reasoning { signature, data, .. }
            if signature.is_some() || data.is_some())
    };
    if !record
        .reasoning
        .iter()
        .any(|part| part.occurrence.is_none() && part.terminal_part.as_ref().is_some_and(&signed))
        || secret_scan_mode_in_txn(&vault.store, txn)? == SecretScanMode::Off
    {
        return Ok(());
    }
    let known = KnownValues::shared_in_writer(&vault.store, txn)?;
    let place = format!("side:{}", MODEL_CALLS.decl().name);
    let origin = side_row_origin(&place, &MODEL_CALLS.key_bytes(&record.key()))?;
    let kept = KeptValues::for_records_in_txn(&vault.store, txn, [origin])?;
    let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    for (index, part) in record.reasoning.iter_mut().enumerate() {
        let Some(terminal) = part.terminal_part.take() else {
            continue;
        };
        if part.occurrence.is_some() || !signed(&terminal) {
            continue;
        }
        let bytes =
            Zeroizing::new(rmp_serde::to_vec_named(&terminal).map_err(|_| {
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
            continue;
        }
        // A known credential inside a part is not the whole signed part.
        // Its new custody belongs to this call, independently erasable from
        // another call's or credential's custody.
        let handle = seal_whole_part_in_txn(
            vault,
            txn,
            origin,
            &format!("reasoning/{index}"),
            &bytes,
            reason,
            at,
        )?;
        part.text = None;
        part.bytes = None;
        part.signature = None;
        part.occurrence = Some(ModelCallPartRef::Custody { handle });
    }
    Ok(())
}
