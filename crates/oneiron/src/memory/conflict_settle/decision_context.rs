//! The member read contexts and loop a conflict settlement, its approval or
//! its revert answers (FIX 7500, 11002). Member reads are all-or-none, and
//! only conflict-kind bundles join the answering chain; unrelated bundles
//! never become claim verdicts.

use crate::error::{Error, Result};
use crate::store::{GateDecisionContext, GateDecisionRecord};
use crate::{EntityId, Vault};
use rmpv::Value;

use super::{APPROVAL_KIND, KIND, REVERT_KIND};

fn is_conflict_bundle_kind(kind: &str) -> bool {
    kind == KIND || kind == APPROVAL_KIND || kind == REVERT_KIND
}

fn conflict_bundles_for_claim(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
) -> Vec<GateDecisionRecord> {
    vault
        .store
        .bundle_gate_decisions_for_claim_in_txn(txn, claim.as_bytes())
        .unwrap_or_default()
        .into_iter()
        .filter(|record| is_conflict_bundle_kind(&record.content_kind))
        .collect()
}

/// The context of a decision answering the newest decision bound to `claim`
/// that carries a loop link, of the tag `kind` when one is named. Its loop
/// links stay; its member read contexts are added by `answering_members`.
pub(super) fn answering_claim(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
    kind: Option<&str>,
) -> GateDecisionContext {
    vault
        .store
        .gate_decisions_for_claim_in_txn(txn, claim.as_bytes())
        .unwrap_or_default()
        .into_iter()
        .chain(conflict_bundles_for_claim(vault, txn, claim))
        .filter(|record| {
            !record.context.links.is_empty() && kind.is_none_or(|kind| record.content_kind == kind)
        })
        .max_by_key(|record| record.created_at)
        .map(|answered| GateDecisionContext {
            read: Vec::new(),
            ..GateDecisionContext::answering(&answered)
        })
        .unwrap_or_default()
}

fn member_decision(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    member: &EntityId,
) -> Option<GateDecisionRecord> {
    vault
        .store
        .gate_decisions_for_claim_in_txn(txn, member.as_bytes())
        .unwrap_or_default()
        .into_iter()
        .chain(conflict_bundles_for_claim(vault, txn, *member))
        .filter(|record| {
            record
                .context
                .read
                .iter()
                .any(|read| read.record == Some(*member))
        })
        .max_by_key(|record| record.created_at)
}

/// Answers every member with its newest read-carrying decision. One member
/// without such a decision withholds the aggregate's whole read context.
/// Copied bundles carry their complete erase refs into the new receipt.
pub(super) fn answering_members(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    members: &[EntityId],
    loop_claim: EntityId,
    kind: Option<&str>,
) -> Result<(GateDecisionContext, Vec<[u8; 16]>)> {
    let mut answered = Vec::with_capacity(members.len());
    for member in members {
        answered.extend(member_decision(vault, txn, member));
    }
    let mut context = GateDecisionContext::answering_all(&answered);
    if answered.len() != members.len() {
        context.read.clear();
    }
    let mut claim_refs: Vec<[u8; 16]> = members.iter().map(|member| *member.as_bytes()).collect();
    if !context.read.is_empty() {
        for record in &answered {
            if record.claim_id.is_none() {
                claim_refs.extend(
                    vault
                        .store
                        .gate_decision_claim_refs_in_txn(txn, record.decision_id)?,
                );
            }
        }
    }
    for link in answering_claim(vault, txn, loop_claim, kind).links {
        if !context.links.contains(&link) {
            context.links.push(link);
        }
    }
    Ok((context, claim_refs))
}

/// Adds the kept claim named by a resolved claim's durable resolution, then
/// makes the member set unique for both context gathering and claim refs.
pub(super) fn add_resolved_kept(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    members: &mut Vec<EntityId>,
    resolved: EntityId,
) -> Result<()> {
    let answer = vault
        .get_claim_in_txn(txn, &resolved)?
        .ok_or(Error::EntityNotFound)?;
    let resolution = match &answer.value {
        Value::Map(rows) => rows
            .iter()
            .find(|(name, _)| name.as_str() == Some("resolution"))
            .map(|(_, value)| value),
        _ => None,
    };
    if let Some(resolution) = resolution {
        members.extend(crate::dreamer_consolidation::marker_ids(resolution, "kept"));
    }
    members.sort_unstable();
    members.dedup();
    Ok(())
}

/// Appends a conflict receipt bound to its explicit and inherited members.
pub(super) fn append(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &GateDecisionRecord,
    claim_refs: &[[u8; 16]],
) -> Result<()> {
    vault
        .store
        .append_gate_decision_with_claim_refs_in_txn(wtxn, record, claim_refs)
}
