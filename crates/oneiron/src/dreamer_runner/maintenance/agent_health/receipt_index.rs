//! Each agent-health card under every reviewer receipt it holds (FIX 10880),
//! so [`crate::Vault::health_review_receipt`] reads the one card that holds
//! a receipt, not every card.
//!
//! Every card write goes through [`put_card_in_txn`], which diffs the
//! receipts the stored card held against the ones it now holds, in the
//! writer's own transaction. A receipt id that is not `health_review:` and
//! 64 hex names no index row: the lookup refuses that shape anyway. An
//! index row whose card no longer holds its receipt is passed by on lookup.
//! Cards written before this index have no index rows; no migration builds
//! them (no backward compatibility).

use std::collections::BTreeSet;

use super::{AgentHealthCard, CARDS, HEALTH_REVIEW_RECEIPT_PREFIX};
use crate::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// A card's key: id16 actor, signal byte, id16 task.
type CardKey = ([u8; 16], [u8; 1], [u8; 16]);

/// Key: the receipt's 32-byte digest, then the card's key. Value: empty.
const CARD_BY_RECEIPT: SideTable<([u8; 32], CardKey), (), Raw> =
    SideTable::new(&side_table::COACH_AGENT_HEALTH_CARD_BY_RECEIPT);

/// The digest a reviewer receipt id spells: `health_review:` and 64 hex.
pub(super) fn receipt_digest(receipt: &str) -> Option<[u8; 32]> {
    let hex = receipt.strip_prefix(HEALTH_REVIEW_RECEIPT_PREFIX)?;
    let mut digest = [0u8; 32];
    if hex.len() != 64 {
        return None;
    }
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}

/// Every receipt digest `card` holds.
fn receipts(card: &AgentHealthCard) -> BTreeSet<[u8; 32]> {
    card.review_outcomes
        .iter()
        .filter_map(|held| receipt_digest(&held.receipt))
        .collect()
}

/// Writes `card` under `key`, and keeps its receipt index rows in step, in
/// the caller's transaction. A stored card that does not read held no
/// receipt the index can name.
///
/// # Errors
///
/// Storage errors.
pub(super) fn put_card_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &CardKey,
    card: &AgentHealthCard,
) -> Result<()> {
    let before = match CARDS.get(store, txn, key) {
        Ok(Some(stored)) => receipts(&stored),
        Ok(None) | Err(_) => BTreeSet::new(),
    };
    let after = receipts(card);
    for gone in before.difference(&after) {
        CARD_BY_RECEIPT.delete(store, txn, &(*gone, *key))?;
    }
    for added in after.difference(&before) {
        CARD_BY_RECEIPT.put(store, txn, &(*added, *key), &())?;
    }
    CARDS.put(store, txn, key, card)
}

/// The keys of the cards the index says hold receipt `digest`, in key
/// order.
///
/// # Errors
///
/// Storage errors.
pub(super) fn cards_holding(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Vec<CardKey>> {
    Ok(CARD_BY_RECEIPT
        .scan_keys(store, txn, digest)?
        .into_iter()
        .map(|(_, key)| key)
        .collect())
}
