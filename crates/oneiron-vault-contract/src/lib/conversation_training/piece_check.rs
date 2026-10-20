//! The anonymous training window's shape checks and decoders (TL-6): the
//! shape only. Nothing here caps a count or a size (Rule 5).

use std::collections::BTreeSet;

use super::{
    DIGEST_HEX, ID_HEX, PIECE_WIRE_VERSION, PieceBatchV1, PieceEntryV1, PieceFactsHeadV1,
    PieceFinalV1, PieceMetaPageV1, PieceReceiptPageV1, TrainingKeysV1, check_codes, check_hex,
};

impl PieceBatchV1 {
    /// Checks the batch's shape: its version; every code, digest, key and
    /// signature hex of its length; no code twice among the pieces or among
    /// the withdrawals; no part name empty or twice; each entry's parts
    /// consecutive by index and contiguous by offset, part 0 at offset 0;
    /// and a final only with totals that hold every item and range its entry
    /// sends. It caps no count or size (Rule 5).
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version != PIECE_WIRE_VERSION {
            anyhow::bail!("not a version {PIECE_WIRE_VERSION} piece batch");
        }
        let mut codes = BTreeSet::new();
        let mut part_names = BTreeSet::new();
        for entry in &self.pieces {
            check_entry(entry, &mut part_names)?;
            if !codes.insert(entry.code.as_str()) {
                anyhow::bail!("a batch names one piece twice");
            }
        }
        let mut withdrawn = BTreeSet::new();
        for withdrawal in &self.withdrawals {
            check_hex("withdrawal code", &withdrawal.code, DIGEST_HEX)?;
            if !withdrawn.insert(withdrawal.code.as_str()) {
                anyhow::bail!("a batch withdraws one piece twice");
            }
        }
        if let Some(check) = &self.install_check {
            check_hex("install check public_key", &check.public_key, DIGEST_HEX)?;
            check_hex("install check signature", &check.signature, 2 * DIGEST_HEX)?;
        }
        Ok(())
    }
}

impl PieceReceiptPageV1 {
    /// Checks the page's shape: every code 64 hex and answered once, every
    /// receipt about its entry's code with a 128 hex signature, and each
    /// entry's receipts rising by revision. Signatures are checked against
    /// the receipt keys by the engine, not here.
    pub fn validate(&self) -> anyhow::Result<()> {
        let mut codes = BTreeSet::new();
        for entry in &self.entries {
            check_hex("receipt code", &entry.code, DIGEST_HEX)?;
            if !codes.insert(entry.code.as_str()) {
                anyhow::bail!("a receipt page answers one piece twice");
            }
            let mut last: Option<u64> = None;
            for receipt in &entry.receipts {
                if receipt.body.code != entry.code {
                    anyhow::bail!("a receipt answers another piece than its entry");
                }
                check_hex("receipt signature", &receipt.signature, 2 * DIGEST_HEX)?;
                if last.is_some_and(|revision| revision >= receipt.body.revision) {
                    anyhow::bail!("a piece's receipts do not rise by revision");
                }
                last = Some(receipt.body.revision);
            }
        }
        Ok(())
    }
}

impl TrainingKeysV1 {
    /// Checks the descriptor's shape: `recipient_blake3` 64 hex, a recipient,
    /// and the current receipt key with at most the one before it. It decodes
    /// no base64.
    pub fn validate(&self) -> anyhow::Result<()> {
        check_hex("recipient_blake3", &self.recipient_blake3, DIGEST_HEX)?;
        if self.recipient.is_empty() {
            anyhow::bail!("a training descriptor names no recipient");
        }
        if !matches!(self.receipt_keys.len(), 1 | 2)
            || self.receipt_keys.iter().any(String::is_empty)
        {
            anyhow::bail!(
                "a training descriptor names its current receipt key and at most one more"
            );
        }
        Ok(())
    }
}

/// Decodes one batch strictly: its exact shape, then
/// [`PieceBatchV1::validate`].
pub fn decode_piece_batch(bytes: &[u8]) -> anyhow::Result<PieceBatchV1> {
    let batch: PieceBatchV1 = serde_json::from_slice(bytes)?;
    batch.validate()?;
    Ok(batch)
}

/// Decodes one receipt page strictly: its exact shape, then
/// [`PieceReceiptPageV1::validate`].
pub fn decode_piece_receipt_page(bytes: &[u8]) -> anyhow::Result<PieceReceiptPageV1> {
    let page: PieceReceiptPageV1 = serde_json::from_slice(bytes)?;
    page.validate()?;
    Ok(page)
}

/// Decodes the intake's descriptor strictly: its exact shape, then
/// [`TrainingKeysV1::validate`].
pub fn decode_training_keys(bytes: &[u8]) -> anyhow::Result<TrainingKeysV1> {
    let keys: TrainingKeysV1 = serde_json::from_slice(bytes)?;
    keys.validate()?;
    Ok(keys)
}

/// One piece entry's shape, its part names joining the batch's.
fn check_entry<'a>(
    entry: &'a PieceEntryV1,
    part_names: &mut BTreeSet<&'a str>,
) -> anyhow::Result<()> {
    check_hex("piece code", &entry.code, DIGEST_HEX)?;
    if let Some(meta) = &entry.meta {
        check_meta(meta)?;
    }
    // The previous part's index and the stream offset it ends at.
    let mut previous: Option<(u64, u64)> = None;
    for part in &entry.parts {
        check_hex("part digest", &part.digest, DIGEST_HEX)?;
        if part.part_name.is_empty() || !part_names.insert(part.part_name.as_str()) {
            anyhow::bail!("a part names no multipart part, or one another part names");
        }
        let Some(end) = part.offset.checked_add(part.bytes) else {
            anyhow::bail!("a part runs past the last stream offset");
        };
        let follows = match previous {
            None => part.index != 0 || part.offset == 0,
            Some((index, previous_end)) => {
                index.checked_add(1) == Some(part.index) && previous_end == part.offset
            }
        };
        if !follows {
            anyhow::bail!("a piece's parts are not consecutive by index and contiguous by offset");
        }
        previous = Some((part.index, end));
    }
    if let Some(finish) = &entry.finish {
        check_final(entry, finish, previous.map(|(_, end)| end))?;
    }
    Ok(())
}

/// One facts page's shape: its head's ids, every code and digest hex, and
/// every list's indexes inside `u64`.
fn check_meta(meta: &PieceMetaPageV1) -> anyhow::Result<()> {
    if let Some(head) = &meta.head {
        check_head(head)?;
    }
    check_codes("person", &meta.persons)?;
    check_codes("world", &meta.worlds)?;
    for chunk in &meta.chunks {
        check_hex("chunk digest", &chunk.digest, DIGEST_HEX)?;
    }
    list_end("persons", meta.persons_from, meta.persons.len())?;
    list_end("worlds", meta.worlds_from, meta.worlds.len())?;
    list_end("chunks", meta.chunks_from, meta.chunks.len())?;
    Ok(())
}

/// A final's shape against its own entry: both digests hex, every total at
/// least the end of what the entry sends of its list, the last range inside
/// `total_bytes`, and a whole chunk table summing to `total_bytes`.
fn check_final(
    entry: &PieceEntryV1,
    finish: &PieceFinalV1,
    parts_end: Option<u64>,
) -> anyhow::Result<()> {
    check_hex("total_digest", &finish.total_digest, DIGEST_HEX)?;
    check_hex("facts_digest", &finish.facts_digest, DIGEST_HEX)?;
    if parts_end.is_some_and(|end| end > finish.total_bytes) {
        anyhow::bail!("a part runs past its final's total_bytes");
    }
    let Some(meta) = &entry.meta else {
        return Ok(());
    };
    let chunks_end = list_end("chunks", meta.chunks_from, meta.chunks.len())?;
    if list_end("persons", meta.persons_from, meta.persons.len())? > finish.persons_total
        || list_end("worlds", meta.worlds_from, meta.worlds.len())? > finish.worlds_total
        || chunks_end > finish.chunks_total
    {
        anyhow::bail!("a final's totals are short of the items its entry sends");
    }
    if meta.chunks_from == 0 && chunks_end == finish.chunks_total {
        let table_bytes = meta
            .chunks
            .iter()
            .try_fold(0u64, |sum, chunk| sum.checked_add(chunk.bytes));
        if table_bytes != Some(finish.total_bytes) {
            anyhow::bail!("a final's total_bytes is not its chunk table's");
        }
    }
    Ok(())
}

/// A head's ids: the submission 32 hex, the scope, source and key 64.
pub(super) fn check_head(head: &PieceFactsHeadV1) -> anyhow::Result<()> {
    check_hex("submission_id", &head.submission_id, ID_HEX)?;
    check_hex("scope", &head.scope, DIGEST_HEX)?;
    check_hex("source", &head.source, DIGEST_HEX)?;
    check_hex("key_id", &head.key_id, DIGEST_HEX)
}

/// The absolute index one past the last item a page sends of a list.
fn list_end(list: &str, from: u64, items: usize) -> anyhow::Result<u64> {
    u64::try_from(items)
        .ok()
        .and_then(|items| from.checked_add(items))
        .ok_or_else(|| anyhow::anyhow!("a page's {list} run past the last index"))
}
