//! The Coach's proposals still waiting in the pending-consent tray, for the healer's residue
//! read (OF-418 L4). Every tray row is read, page after page to the last, in the caller's one
//! snapshot, with the live claim body behind it read through this module's own reader. A row
//! whose body is gone is returned with no body, never dropped, so the reader shows it; so is a
//! sequence row the tray does not answer for, its own index corruption (FIX 7378). Nothing
//! here writes, orders, drops or decides a bundle member.

use super::*;
use crate::store::PendingGateConsentSlot;

/// Rows one tray page reads. A page, never a cap: the read goes on to the last row.
const PENDING_HEAL_PAGE: usize = 256;

/// One pending-consent row whose live claim carries one of the asked predicates, or whose
/// live claim body could not be read, or whose tray row is corrupt.
#[derive(Debug, Clone)]
pub(crate) struct PendingHealRef {
    /// The pending claim.
    pub(crate) claim: EntityId,
    /// The gate decision that holds it for consent; `None` when the tray does not answer
    /// for its sequence row, so no decision is known (FIX 7378).
    pub(crate) decision: Option<GateDecisionId>,
    /// When it entered the tray; `None` when the tray does not answer for its sequence row.
    pub(crate) created_at: Option<u64>,
    /// Its live body; `None` when the body is gone or is no CLAIM body.
    pub(crate) body: Option<ClaimBody>,
}

impl Vault {
    /// Every pending-consent row at `txn` whose live claim's predicate is one of
    /// `predicates`, and every row whose live claim body cannot be read, in tray sequence
    /// order. A sequence row the tray does not answer for (its tray row is gone, or names
    /// another claim id) is its own row with no body, under a key-only WARN, never a failed
    /// read (FIX 7378). The tray is paged to its high-water mark at `txn`, to the last row.
    /// Only a store failure fails the read.
    pub(crate) fn pending_heal_refs_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        predicates: &[&str],
    ) -> Result<Vec<PendingHealRef>> {
        let fence = self.store.pending_gate_consents_high_water_in_txn(txn)?;
        let mut cursor = None;
        let mut refs = Vec::new();
        loop {
            let page = self.store.pending_gate_consent_slots_page_in_txn(
                txn,
                cursor,
                fence,
                PENDING_HEAL_PAGE,
            )?;
            let Some((last, ..)) = page.last() else {
                break;
            };
            cursor = Some(*last);
            for (sequence, claim, slot) in page {
                let record = match slot {
                    PendingGateConsentSlot::Held(record) => record,
                    PendingGateConsentSlot::Corrupt => {
                        tracing::warn!(
                            target: "oneiron::gate",
                            sequence,
                            claim = %claim.to_hex(),
                            fault = "tray_row_unanswered",
                            "a pending-consent sequence row the tray does not answer for is listed with no body"
                        );
                        refs.push(PendingHealRef {
                            claim,
                            decision: None,
                            created_at: None,
                            body: None,
                        });
                        continue;
                    }
                };
                let body = match live_claim_parts_in_txn(&self.store, txn, &claim) {
                    Ok((body, _)) if predicates.contains(&body.predicate.as_str()) => Some(body),
                    Ok(_) => continue,
                    Err(
                        error @ (Error::Storage(_)
                        | Error::Io(_)
                        | Error::Store(_)
                        | Error::MapFull),
                    ) => return Err(error),
                    Err(_) => None,
                };
                refs.push(PendingHealRef {
                    claim,
                    decision: Some(record.decision_id),
                    created_at: Some(record.created_at),
                    body,
                });
            }
        }
        Ok(refs)
    }
}
