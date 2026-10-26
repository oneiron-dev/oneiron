//! The context a consent bundle's receipt keeps (FIX 7499, 7500): the Dreamer
//! run it answers, and each member's read context, so a reader sees its
//! outcome only when it is admitted to every member. The receipt is bound to
//! its members' claims, so each member's erase reaches it.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{
    GateDecisionContext, GateDecisionReadContext, GateDecisionRecord, GateLoopLink,
    GateLoopOrigin, GateLoopSource, Store,
};

/// The context of the receipt answering run `run`'s bundle of `members`:
/// each member's read context from the newest decision on it that kept one.
/// A member with none leaves the receipt no read context at all, since a
/// reader judged on fewer members than the bundle had would read too much.
fn bundle_context(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    run: &str,
    members: &[EntityId],
) -> GateDecisionContext {
    let mut read = Vec::with_capacity(members.len());
    for member in members {
        let Some(kept) = member_read_context(store, txn, member) else {
            read.clear();
            break;
        };
        read.push(kept);
    }
    GateDecisionContext {
        read,
        links: vec![GateLoopLink::action(
            GateLoopSource::Runner,
            Some(run.to_owned()),
            None,
            GateLoopOrigin::Unresolved,
        )],
        analysis: None,
    }
}

fn member_read_context(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    member: &EntityId,
) -> Option<GateDecisionReadContext> {
    store
        .gate_decisions_for_claim_in_txn(txn, member.as_bytes())
        .ok()?
        .into_iter()
        .filter_map(|record| {
            let created_at = record.created_at;
            record
                .context
                .read
                .into_iter()
                .find(|read| read.record == Some(*member))
                .map(|read| (created_at, read))
        })
        .max_by_key(|(created_at, _)| *created_at)
        .map(|(_, read)| read)
}

/// Appends the receipt `record` answering run `run`'s bundle of `members`,
/// its context filled first, bound to the members' claims when it has any.
pub(super) fn append(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &mut GateDecisionRecord,
    run: &str,
    members: &[EntityId],
) -> Result<()> {
    record.context = bundle_context(&vault.store, wtxn, run, members);
    let claim_refs: Vec<[u8; 16]> = members.iter().map(|member| *member.as_bytes()).collect();
    if claim_refs.is_empty() {
        vault.store.append_gate_decision_in_txn(wtxn, record)
    } else {
        vault
            .store
            .append_gate_decision_with_claim_refs_in_txn(wtxn, record, &claim_refs)
    }
}
