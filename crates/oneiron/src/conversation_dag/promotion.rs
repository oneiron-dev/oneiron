//! Preserve journaled legacy TURNs when a save joins an already-adopted DAG.

use super::{admission, graph, writes};
use crate::Vault;
use crate::batch::{BatchBuilder, BatchOp};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::off_record::PromoteReplayGrant;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_TURN;
use crate::session_overlay::PromotePlan;

/// The floor's ordinary replay, with native append bookkeeping for a fresh
/// legacy trunk TURN. The grant admits only this session's members; it does
/// not supply a byline, a session, or a thread placement.
pub(crate) fn promote_replay_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    plan: &PromotePlan,
    ops: Vec<BatchOp>,
    grant: &PromoteReplayGrant,
) -> Result<()> {
    let turn = plan.turn();
    let conversation = plan.conversation();
    let legacy = legacy_trunk_in_txn(vault, txn, plan, &ops, grant)?;
    let parent = if legacy {
        let parent = graph::canonical_chain(&vault.store, txn, &conversation)?
            .last()
            .copied();
        admission::permit(&vault.store, txn, &turn, &conversation)?;
        parent
    } else {
        None
    };
    let replayed =
        BatchBuilder::promotion_replay(vault, ops, grant).apply_recording_gate_decisions(txn);
    let finished = if legacy {
        admission::finish(&vault.store, txn, &turn)
    } else {
        Ok(())
    };
    replayed?;
    finished?;
    if !legacy {
        return Ok(());
    }

    // Inspect the landed row and topology, not a placement inferred from the grant.
    if graph::is_thread_record(&vault.store, txn, &turn)?
        || graph::is_sub_session_record(&vault.store, txn, &turn)?
        || crate::compaction::turn_session_membership_in_txn(&vault.store, txn, &turn)?.is_some()
    {
        return Err(graph::invalid(
            "conversation adopted DAG; append through append_dag_record",
        ));
    }
    let row = vault
        .store
        .port_entity_record(txn, &turn)?
        .ok_or(crate::Error::EntityNotFound)?;
    admission::reconcile_addressing(vault, txn, &turn, &row.body, row.learned_at)?;
    admission::pin_record(&vault.store, txn, &turn)?;
    // A parent supplied by an existing carrier is never replaced or advanced.
    if graph::parent(&vault.store, txn, &turn)?.is_some() {
        graph::chain(&vault.store, txn, &conversation, turn)?;
        return Ok(());
    }
    if let Some(parent) = parent {
        let fields = writes::value(row.learned_at);
        BatchBuilder::promotion_replay(
            vault,
            vec![BatchOp::PublicEdgeWithCreatedAt {
                src: turn,
                kind: EdgeKind::Parent,
                tgt: parent,
                weight: fields.weight,
                created_at: fields.created_at,
                vad: fields.vad,
            }],
            grant,
        )
        .apply_recording_gate_decisions(txn)?;
    }
    writes::set_head_in_txn(vault, txn, &conversation, turn)
}

fn legacy_trunk_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    plan: &PromotePlan,
    ops: &[BatchOp],
    grant: &PromoteReplayGrant,
) -> Result<bool> {
    let turn = plan.turn();
    let conversation = plan.conversation();
    if !grant.exempts(&turn)
        || vault.store.port_entity_present(txn, &turn)?
        || graph::MIGRATED.get(&vault.store, txn, &conversation)? != Some([1])
        || graph::parent(&vault.store, txn, &turn)?.is_some()
    {
        return Ok(false);
    }
    if !matches!(
        crate::vault::live_entity_row_in_txn(&vault.store, txn, &conversation)?,
        crate::vault::LiveEntityRow::Live { entity_type, .. }
            if entity_type == crate::registry::ENTITY_TYPE_CONVERSATION
    ) {
        return Ok(false);
    }
    #[cfg(feature = "sync")]
    if crate::sync::bridge::has_unresolved_parent_for_source_in_txn(vault, txn, &turn)? {
        return Ok(false);
    }
    let mut has_turn = false;
    let mut has_membership = false;
    for op in ops {
        match op {
            BatchOp::Put {
                id,
                entity_type,
                data,
                ..
            } if *id == turn => {
                if *entity_type != ENTITY_TYPE_TURN
                    || admission::record_kind(data)?.is_some()
                    || crate::workspace_roster::thread_binding(data)?.is_some()
                {
                    return Ok(false);
                }
                has_turn = true;
            }
            BatchOp::PublicEdgeWithCreatedAt { src, kind, tgt, .. } if *src == turn => match kind {
                EdgeKind::ChildOf if *tgt == conversation => has_membership = true,
                EdgeKind::ChildOf
                | EdgeKind::Parent
                | EdgeKind::RepliesTo
                | EdgeKind::SpawnedBy => {
                    return Ok(false);
                }
                _ => {}
            },
            _ => {}
        }
    }
    Ok(has_turn && has_membership)
}
