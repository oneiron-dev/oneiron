//! Final-state leader-chat TURN candidates, independent of batch op order.
use crate::batch_op::BatchOp;
use oneiron_base::edge::EdgeKind;
use oneiron_base::registry::ENTITY_TYPE_TURN;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeSet;

pub fn local_turns(ops: &[BatchOp]) -> BTreeSet<EntityId> {
    ops.iter()
        .filter_map(|op| match op {
            BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_TURN,
                allow_maintenance,
                allow_reserved_predicate,
                ..
            } if !(*allow_maintenance && *allow_reserved_predicate) => Some(*id),
            BatchOp::Edge {
                src,
                kind: EdgeKind::ChildOf,
                ..
            }
            | BatchOp::PublicEdgeWithCreatedAt {
                src,
                kind: EdgeKind::ChildOf,
                ..
            } => Some(*src),
            _ => None,
        })
        .collect()
}
