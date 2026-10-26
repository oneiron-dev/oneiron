//! The context a consent bundle's receipt keeps (FIX 7499, 7500): the Dreamer
//! run it answers, and each member's newest decision that kept its read
//! context, answered: the member's read context and loop links, with that
//! decision as their basis. A reader sees the outcome only when it is
//! admitted to every member. The receipt is bound to its members' claims, so
//! each member's erase reaches it.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{
    GateDecisionContext, GateDecisionRecord, GateLoopLink, GateLoopOrigin, GateLoopSource, Store,
};

/// The context of the receipt answering run `run`'s bundle of `members`. A
/// member no decision kept a read context for leaves the receipt no read
/// context at all, since a reader judged on fewer members than the bundle
/// had would read too much.
pub(super) fn bundle(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: &str,
    members: &[EntityId],
) -> GateDecisionContext {
    let mut answered = Vec::with_capacity(members.len());
    for member in members {
        answered.extend(member_decision(&vault.store, txn, member));
    }
    let every_member = answered.len() == members.len();
    let mut context = GateDecisionContext::answering_all(&answered);
    if !every_member {
        context.read.clear();
    }
    let run = GateLoopLink::action(
        GateLoopSource::Runner,
        Some(run.to_owned()),
        None,
        GateLoopOrigin::Unresolved,
    );
    if !context.links.contains(&run) {
        context.links.push(run);
    }
    context
}

/// The newest decision bound to `member` whose read context names it.
fn member_decision(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    member: &EntityId,
) -> Option<GateDecisionRecord> {
    store
        .gate_decisions_for_claim_in_txn(txn, member.as_bytes())
        .ok()?
        .into_iter()
        .filter(|record| {
            record
                .context
                .read
                .iter()
                .any(|read| read.record == Some(*member))
        })
        .max_by_key(|record| record.created_at)
}

/// Appends the bundle's receipt `record`, bound to its `members`' claims
/// when it has any, so the primary and its constituent refs land together.
pub(super) fn append(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &GateDecisionRecord,
    members: &[EntityId],
) -> Result<()> {
    let claim_refs: Vec<[u8; 16]> = members.iter().map(|member| *member.as_bytes()).collect();
    if claim_refs.is_empty() {
        vault.store.append_gate_decision_in_txn(wtxn, record)
    } else {
        vault
            .store
            .append_gate_decision_with_claim_refs_in_txn(wtxn, record, &claim_refs)
    }
}
