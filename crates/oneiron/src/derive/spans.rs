//! Optional span locators on derive items: byte ranges
//! over a cited TURN's text as the committing actor reads it through
//! `vault.evidence.spans`, bound to stored ranges in the commit's transaction.

use super::batch::DerivedEvidenceSpans;
use crate::EntityId;
use crate::dreamer_consolidation::resources::stored_range_for_served_range;
use crate::error::{Error, Result};
use crate::snapshot_read::{
    masked_turn_spans, source_version_in_txn, turn_lifted_keys_with_masked_in_txn, turn_spans,
};

/// One spans entry's stored ranges, in the entry's order.
#[derive(Debug, Clone)]
pub(super) struct BoundSpans {
    /// The TURN the entry names.
    pub(super) source: EntityId,
    /// Stored byte ranges, one per served range.
    pub(super) ranges: Vec<(usize, usize)>,
}

/// Binds each entry's served ranges to stored ranges, as the committing actor
/// reads them: masked when the actor's read key has masked secret sight,
/// stored otherwise. Each range must be one `vault.evidence.spans` would
/// serve this actor; a bound range maps to stored bytes by the bound
/// extraction read's rule.
///
/// # Errors
///
/// `InvalidClaimBody` when an entry does not bind, and storage errors.
pub(super) fn bind_in_txn(
    vault: &crate::Vault,
    read: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    spans: &[DerivedEvidenceSpans],
) -> Result<Vec<BoundSpans>> {
    let mut bound = Vec::with_capacity(spans.len());
    for entry in spans {
        bound.push(bind_entry_in_txn(vault, read, txn, entry)?);
    }
    Ok(bound)
}

/// Binds one entry's served ranges to stored ranges.
fn bind_entry_in_txn(
    vault: &crate::Vault,
    read: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    entry: &DerivedEvidenceSpans,
) -> Result<BoundSpans> {
    let Some((_, Some(text))) = source_version_in_txn(read, txn, &entry.source)? else {
        return Err(Error::InvalidClaimBody(
            "evidence span source is not a TURN the actor reads",
        ));
    };
    if entry.ranges.is_empty() {
        return Err(Error::InvalidClaimBody("evidence span entry has no range"));
    }
    let masked = !read.actor_key().reads_as_vault_owner();
    let keys =
        turn_lifted_keys_with_masked_in_txn(&vault.store, read, txn, masked, &entry.source, &text)?;
    match &keys {
        Some(keys) => masked_turn_spans(&text, keys, &entry.ranges),
        None => turn_spans(&text, &entry.ranges).map(|spans| (spans, false)),
    }
    .map_err(|_| Error::InvalidClaimBody("evidence span is not served"))?;
    let stored = text
        .text()
        .ok_or(Error::InvalidClaimBody("evidence span source has no text"))?;
    let mut ranges = Vec::with_capacity(entry.ranges.len());
    for range in &entry.ranges {
        ranges.push(stored_range_in(&keys, stored, *range)?);
    }
    Ok(BoundSpans {
        source: entry.source,
        ranges,
    })
}

/// Maps one served range to its stored bytes: directly when unmasked, else by
/// the bound extraction read's rule.
fn stored_range_in(
    keys: &Option<crate::batch::secret_scan::LiftedKeys>,
    stored: &str,
    range: crate::snapshot_read::EvidenceRange,
) -> Result<(usize, usize)> {
    match keys {
        None => {
            let start = usize::try_from(range.start)
                .map_err(|_| Error::InvalidClaimBody("invalid evidence byte range"))?;
            let end = usize::try_from(range.end)
                .map_err(|_| Error::InvalidClaimBody("invalid evidence byte range"))?;
            Ok((start, end))
        }
        Some(keys) => stored_range_for_served_range(keys, stored, range),
    }
}
