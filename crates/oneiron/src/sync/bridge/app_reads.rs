//! Bounded-page adapters for authority-scoped app subscription channels.
//!
//! Each read returns one scoped page, of any size its caller asks, and the
//! continuation its next page starts from (FIX 8859): a subscription of any
//! count reads page after page, and no count is refused.
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::{MemoryReceipt, PendingWrite};
use crate::settings::ReadDestination;
use crate::store::GateDecisionId;
use crate::{EntityId, Error, Result, Vault};

/// The rows one scan step reads from the ledger.
const PAGE_SIZE: usize = 256;

fn validate_limit(limit: usize) -> Result<()> {
    if limit == 0 {
        return Err(Error::CorruptedIndex("invalid app subscription limit"));
    }
    Ok(())
}

/// Where the next page of a scoped subscription read starts: just past the
/// last row the page before it returned, in the read's own order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedContinuation(Position);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Position {
    /// Receipts go newest decision first: the next page reads older ones.
    Receipt(GateDecisionId),
    /// Pending consents go by created at, decision and claim: the next page
    /// reads the ones past this key.
    Pending(u64, GateDecisionId, [u8; 16]),
}

/// One page of a scoped subscription read, and where the next page starts:
/// `None` once the read holds no more.
#[derive(Debug, Clone)]
pub struct ScopedPage<T> {
    pub rows: Vec<T>,
    pub next: Option<ScopedContinuation>,
}

/// Whether a caller whose rows go to `destination` may learn of `claim` at
/// all: off this device, a claim a world withholds from one of its machines
/// is not there to count or name (mesh PR2b).
fn readable_at(
    vault: &Vault,
    claim: Option<[u8; 16]>,
    destination: &ReadDestination,
) -> Result<bool> {
    match claim {
        Some(claim) if destination.is_off_device() => {
            Ok(!vault.device_local_keeps_for(&EntityId::from_bytes(claim)?, destination)?)
        }
        _ => Ok(true),
    }
}

fn in_world(vault: &Vault, claim: Option<[u8; 16]>, world: Option<&str>) -> Result<bool> {
    let Some(claim) = claim else {
        return Ok(world.is_none());
    };
    let id = EntityId::from_bytes(claim)?;
    Ok(vault
        .get_claim(&id)?
        .is_some_and(|claim| claim.world.map(|id| id.to_hex()).as_deref() == world))
}

/// Apply principal and world predicates before the output limit, across all
/// pages, for a caller whose rows go to `destination`: up to `limit` rows
/// from `after` on, and the continuation past the last one.
pub fn scoped_subscription_receipts(
    vault: &Vault,
    actor: &str,
    world: Option<&str>,
    destination: impl Into<ReadDestination>,
    limit: usize,
    after: Option<ScopedContinuation>,
) -> Result<ScopedPage<MemoryReceipt>> {
    validate_limit(limit)?;
    let destination: ReadDestination = destination.into();
    let mut before = match after {
        Some(ScopedContinuation(Position::Receipt(decision))) => Some(decision),
        Some(ScopedContinuation(Position::Pending(..))) => {
            return Err(Error::CorruptedIndex(
                "receipt read continued from a consent page",
            ));
        }
        None => None,
    };
    let mut output = Vec::new();
    loop {
        let page = vault.store.gate_decisions_page(before, PAGE_SIZE)?;
        let exhausted = page.len() < PAGE_SIZE;
        before = page.last().map(|row| row.decision_id);
        for row in page {
            if row.actor_ref.as_deref() != Some(actor)
                || !in_world(vault, row.claim_id, world)?
                || !readable_at(vault, row.claim_id, &destination)?
            {
                continue;
            }
            output.push(MemoryReceipt {
                receipt_ref: format!("gate:{}", row.decision_id.to_hex()),
                kind: crate::receipt::ReceiptKind::Gate.as_str().to_owned(),
                fields: std::collections::BTreeMap::new(),
                outcome: row.outcome,
                created_at: row.created_at,
                reason_codes: row.reason_codes,
                actor_class: row.actor_class,
                actor_ref: row.actor_ref,
                content_kind: row.content_kind,
                claim_ref: row.claim_id.map(|id| bytes_to_hex_lower(&id)),
                claim: None,
            });
            if output.len() == limit {
                return Ok(ScopedPage {
                    rows: output,
                    next: Some(ScopedContinuation(Position::Receipt(row.decision_id))),
                });
            }
        }
        if exhausted {
            return Ok(ScopedPage {
                rows: output,
                next: None,
            });
        }
    }
}

/// Scan stable sequence pages and retain only the requested scoped top-k
/// past `after`, with the continuation past the last row kept. Ordering
/// matches the facade's created-at / decision / claim ordering. Off this
/// device a claim a world withholds from one of the machines the rows go to
/// is skipped, judged in the scan's snapshot (mesh PR2b).
pub fn scoped_subscription_pending(
    vault: &Vault,
    actor: &str,
    world: Option<&str>,
    destination: impl Into<ReadDestination>,
    limit: usize,
    after: Option<ScopedContinuation>,
) -> Result<ScopedPage<PendingWrite>> {
    validate_limit(limit)?;
    let after = match after {
        Some(ScopedContinuation(Position::Pending(at, decision, claim))) => {
            Some((at, decision.as_bytes(), claim))
        }
        Some(ScopedContinuation(Position::Receipt(_))) => {
            return Err(Error::CorruptedIndex(
                "consent read continued from a receipt page",
            ));
        }
        None => None,
    };
    let destination: ReadDestination = destination.into();
    let txn = vault.store.env.read_txn()?;
    let kept = crate::settings::device_local_worlds_for(vault, &txn, &destination)?;
    let mut cursor = None;
    let mut selected = Vec::new();
    let mut more = false;
    loop {
        let page = vault
            .store
            .pending_gate_consents_page_in_txn(&txn, cursor, None, PAGE_SIZE)?;
        let exhausted = page.len() < PAGE_SIZE;
        cursor = page.last().map(|(sequence, _)| *sequence);
        for (_, row) in page {
            let decision = vault.store.gate_decision_in_txn(&txn, row.decision_id)?;
            if decision.is_none_or(|decision| decision.actor_ref.as_deref() != Some(actor)) {
                continue;
            }
            let id = EntityId::from_bytes(row.claim_id)?;
            if vault
                .get_claim_in_txn(&txn, &id)?
                .is_none_or(|claim| claim.world.map(|id| id.to_hex()).as_deref() != world)
            {
                continue;
            }
            if destination.is_off_device()
                && crate::settings::device_local_keeps_among(&vault.store, &txn, &kept, &id)?
            {
                continue;
            }
            let key = (row.created_at, row.decision_id.as_bytes(), row.claim_id);
            if after.is_none_or(|after| key > after) {
                selected.push(row);
            }
        }
        // Once per scan step, not per row: the kept top-k stays in order.
        selected.sort_by_key(|row| (row.created_at, row.decision_id.as_bytes(), row.claim_id));
        more |= selected.len() > limit;
        selected.truncate(limit);
        if exhausted {
            break;
        }
    }
    let next = selected.last().filter(|_| more).map(|row| {
        ScopedContinuation(Position::Pending(
            row.created_at,
            row.decision_id,
            row.claim_id,
        ))
    });
    Ok(ScopedPage {
        rows: selected
            .into_iter()
            .map(|row| PendingWrite {
                claim_ref: bytes_to_hex_lower(&row.claim_id),
                decision_ref: format!("gate:{}", row.decision_id.to_hex()),
                created_at: row.created_at,
                reason_codes: row.reason_codes,
                dreamer_run_id: row.dreamer_run_id,
            })
            .collect(),
        next,
    })
}
