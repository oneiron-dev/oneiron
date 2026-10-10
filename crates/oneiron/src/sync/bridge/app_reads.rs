//! Bounded-page adapters for authority-scoped app subscription channels.
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::{MemoryReceipt, PendingWrite};
use crate::{EntityId, Error, Result, Vault};

const PAGE_SIZE: usize = 256;
const MAX_RESULTS: usize = 1000;

fn validate_limit(limit: usize) -> Result<()> {
    if limit == 0 || limit > MAX_RESULTS {
        return Err(Error::CorruptedIndex("invalid app subscription limit"));
    }
    Ok(())
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

/// Apply principal and world predicates before the output limit, across all pages.
pub fn scoped_subscription_receipts(
    vault: &Vault,
    actor: &str,
    world: Option<&str>,
    limit: usize,
) -> Result<Vec<MemoryReceipt>> {
    validate_limit(limit)?;
    let mut before = None;
    let mut output = Vec::new();
    loop {
        let page = vault.store.gate_decisions_page(before, PAGE_SIZE)?;
        let exhausted = page.len() < PAGE_SIZE;
        before = page.last().map(|row| row.decision_id);
        for row in page {
            if row.actor_ref.as_deref() != Some(actor) || !in_world(vault, row.claim_id, world)? {
                continue;
            }
            output.push(MemoryReceipt {
                receipt_ref: format!("gate:{}", row.decision_id.to_hex()),
                outcome: row.outcome,
                created_at: row.created_at,
                reason_codes: row.reason_codes,
                actor_class: row.actor_class,
                actor_ref: row.actor_ref,
                content_kind: row.content_kind,
                claim_ref: row.claim_id.map(|id| bytes_to_hex_lower(&id)),
            });
            if output.len() == limit {
                return Ok(output);
            }
        }
        if exhausted {
            return Ok(output);
        }
    }
}

/// Scan stable sequence pages and retain only the requested scoped top-k.
/// Ordering matches the facade's created-at / decision / claim ordering.
pub fn scoped_subscription_pending(
    vault: &Vault,
    actor: &str,
    world: Option<&str>,
    limit: usize,
) -> Result<Vec<PendingWrite>> {
    validate_limit(limit)?;
    let txn = vault.store.env.read_txn()?;
    let mut cursor = None;
    let mut selected = Vec::new();
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
            selected.push(row);
            selected.sort_by(|a, b| {
                a.created_at
                    .cmp(&b.created_at)
                    .then_with(|| a.decision_id.as_bytes().cmp(&b.decision_id.as_bytes()))
                    .then_with(|| a.claim_id.cmp(&b.claim_id))
            });
            selected.truncate(limit);
        }
        if exhausted {
            break;
        }
    }
    Ok(selected
        .into_iter()
        .map(|row| PendingWrite {
            claim_ref: bytes_to_hex_lower(&row.claim_id),
            decision_ref: format!("gate:{}", row.decision_id.to_hex()),
            created_at: row.created_at,
            reason_codes: row.reason_codes,
            dreamer_run_id: row.dreamer_run_id,
        })
        .collect())
}
