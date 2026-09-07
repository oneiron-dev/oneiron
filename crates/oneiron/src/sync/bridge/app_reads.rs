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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::store::{GateDecisionId, GateDecisionRecord};

    #[test]
    fn scoped_receipts_page_past_one_thousand_unrelated_rows() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
        let actor = "11111111111111111111111111111111";
        let other = "22222222222222222222222222222222";
        vault
            .with_write_txn(|txn| {
                for n in 0u64..1005 {
                    let mut bytes = [1; 16];
                    bytes[8..].copy_from_slice(&n.to_be_bytes());
                    let record = GateDecisionRecord {
                        version: 0,
                        decision_id: GateDecisionId::from_bytes(bytes),
                        created_at: n,
                        outcome: "approved".into(),
                        reason_codes: vec!["gate.test".into()],
                        receipt_reasons: Vec::new(),
                        system_notices: Vec::new(),
                        actor_class: "human".into(),
                        actor_ref: Some(if n == 0 { actor } else { other }.into()),
                        content_kind: "claim".into(),
                        policy_manifest_version: "v0".into(),
                        claim_id: None,
                        grant_ref: None,
                        diff_handle: vec![1],
                        read_frontier_hash: [0; 32],
                        redacted_at: None,
                    };
                    vault.store.append_gate_decision_in_txn(txn, &record)?;
                }
                Ok(())
            })
            .unwrap();
        let rows = scoped_subscription_receipts(&vault, actor, None, 1).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].created_at, 0);
        assert!(
            scoped_subscription_receipts(&vault, actor, Some(other), 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn scoped_pending_pages_by_principal_and_world_before_ordered_limit() {
        use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
        use crate::store::PendingGateConsentRecord;
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
        let actor = "11111111111111111111111111111111";
        let other = "22222222222222222222222222222222";
        let world = EntityId::from_hex("33333333333333333333333333333333").unwrap();
        let other_world = EntityId::from_hex("44444444444444444444444444444444").unwrap();
        let id_for = |n: u64| {
            let mut bytes = [0x72; 16];
            bytes[8..].copy_from_slice(&n.to_be_bytes());
            EntityId::from_bytes(bytes).unwrap()
        };
        let mut batch = vault.batch();
        for n in 0..1009 {
            let mut body = ClaimBody::new(
                "view.pending",
                ClaimSubject::Entity(id_for(n)),
                rmpv::Value::from("pending"),
                1.0,
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
            );
            body.world = if n == 1008 {
                None
            } else if n < 1005 && n % 2 == 1 {
                Some(other_world)
            } else {
                Some(world)
            };
            batch = batch.put_replicated(
                &id_for(n),
                crate::registry::ENTITY_TYPE_CLAIM,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                &crate::claim::encode_claim_body(&body).unwrap(),
            );
        }
        batch.commit().unwrap();
        vault
            .with_write_txn(|txn| {
                for n in 0..1009 {
                    let decision_id = GateDecisionId::from_bytes(*id_for(n).as_bytes());
                    let created_at = if n == 1005 {
                        30
                    } else if n >= 1006 {
                        10
                    } else {
                        n
                    };
                    let record = GateDecisionRecord {
                        version: 0,
                        decision_id,
                        created_at,
                        outcome: "proposed".into(),
                        reason_codes: vec!["gate.pending.test".into()],
                        receipt_reasons: Vec::new(),
                        system_notices: Vec::new(),
                        actor_class: "human".into(),
                        actor_ref: Some(if n < 1005 && n % 2 == 0 { other } else { actor }.into()),
                        content_kind: "claim".into(),
                        policy_manifest_version: "v0".into(),
                        claim_id: Some(*id_for(n).as_bytes()),
                        grant_ref: None,
                        diff_handle: vec![1],
                        read_frontier_hash: [0; 32],
                        redacted_at: None,
                    };
                    vault.store.append_gate_decision_in_txn(txn, &record)?;
                    vault.store.put_pending_gate_consent_in_txn(
                        txn,
                        &PendingGateConsentRecord {
                            version: 0,
                            claim_id: *id_for(n).as_bytes(),
                            decision_id,
                            created_at,
                            diff_handle: vec![1],
                            read_frontier_hash: [0; 32],
                            reason_codes: vec!["gate.pending.test".into()],
                            dreamer_run_id: None,
                        },
                    )?;
                }
                Ok(())
            })
            .unwrap();
        for (limit, expected) in [
            (1, vec![1006]),
            (2, vec![1006, 1007]),
            (10, vec![1006, 1007, 1005]),
        ] {
            let rows =
                scoped_subscription_pending(&vault, actor, Some(&world.to_hex()), limit).unwrap();
            assert_eq!(
                rows.iter()
                    .map(|row| row.claim_ref.clone())
                    .collect::<Vec<_>>(),
                expected
                    .into_iter()
                    .map(|n| id_for(n).to_hex())
                    .collect::<Vec<_>>()
            );
        }
        let base = scoped_subscription_pending(&vault, actor, None, 10).unwrap();
        assert_eq!(base.len(), 1);
        assert_eq!(base[0].claim_ref, id_for(1008).to_hex());
        assert!(
            scoped_subscription_pending(&vault, other, None, 10)
                .unwrap()
                .is_empty()
        );
    }
}
