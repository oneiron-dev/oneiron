//! Typed productivity roles (DOOR-113): an inert Goal, Milestone or Habit
//! TASK under its checked `ChildOf` parent, and the role-labelled tree.
//! Tasks keep `tasks.create` (they route); check-ins keep
//! `vault.habits.checkin` (immutable, streak-deriving).

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimReadStatus, ScopedReadResult};
use crate::error::Error;
use crate::memory::support::encode_rmpv;
use crate::memory::{Memory, MemoryResult};
use crate::registry::ENTITY_TYPE_TASK;
use crate::temporal::TimeRange;
use crate::write_envelope::task_body::{
    TASK_BODY_CURRENT_STREAK_KEY, TASK_BODY_LONGEST_STREAK_KEY, TASK_BODY_ROLE_KEY, TaskRole,
    task_role_from_body_bytes,
};

use super::EntityRefReceipt;

/// The TASK body key the label rides under, as `tasks.create` writes it.
const TASK_BODY_LABEL_KEY: &str = "label";

#[doc(hidden)]
pub use oneiron_verb_wire::memory::structural::productivity::{
    ProductivityCreateRequest, ProductivityCreateRole, ProductivityNode, ProductivityRole,
    ProductivityTree, ProductivityTreeRequest,
};

/// What the tree walk decodes from one admitted TASK row.
struct NodeBody {
    role: ProductivityRole,
    label: Option<String>,
    streak: Option<(u32, u32)>,
}

impl Memory<'_> {
    /// Creates one inert Goal, Milestone or Habit TASK (`{role, label}`, no
    /// route) and its checked `ChildOf` edge in one actor write: an illegal
    /// pair refuses the whole write.
    pub fn productivity_create(
        &self,
        input: &ProductivityCreateRequest,
    ) -> MemoryResult<EntityRefReceipt> {
        crate::task_verb::check_task_label(&input.label)?;
        let parent = input
            .parent_ref
            .as_deref()
            .map(|reference| self.resolve_ref(reference))
            .transpose()?;
        let data = encode_rmpv(&Value::Map(vec![
            (
                Value::from(TASK_BODY_ROLE_KEY),
                Value::from(u64::from(input.role.task_role().role_byte())),
            ),
            (
                Value::from(TASK_BODY_LABEL_KEY),
                Value::from(input.label.as_str()),
            ),
        ]))?;
        let id = self.vault.store.clock.entity_id()?;
        self.with_actor_content_write_txn(|content| {
            let now = content.recorded_at()?;
            let mut batch = self.vault.batch_in().put(
                &id,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &data,
            );
            if let Some(parent) = &parent {
                batch = batch.edge_checked(&id, parent, 1.0);
            }
            content.apply_batch(batch)?;
            Ok(())
        })?;
        self.entity_ref_receipt_of(&id, ENTITY_TYPE_TASK)
    }

    /// The role-labelled `ChildOf` tree under one TASK, read through the
    /// caller's lane: a withheld child and its subtree are absent and
    /// counted in the receipt; a non-TASK child is not part of the tree.
    pub fn productivity_tree(
        &self,
        input: &ProductivityTreeRequest,
    ) -> MemoryResult<ScopedReadResult<Option<ProductivityTree>>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let root = self.resolve_ref_in_lane(&lane, &input.root_ref)?;
        lane.child_of_tree_projected(&root, input.max_depth, node_body, |txn, nodes| {
            let Some(nodes) = nodes else {
                return Ok(None);
            };
            let ref_of = |id: &crate::EntityId| -> MemoryResult<String> {
                Ok(self
                    .short_ref_of_in_txn(txn, id)?
                    .unwrap_or_else(|| id.to_hex()))
            };
            let mut rows = Vec::with_capacity(nodes.len());
            for node in nodes {
                rows.push(ProductivityNode {
                    task_ref: ref_of(&node.id)?,
                    id_hex: node.id.to_hex(),
                    parent_ref: node.parent.as_ref().map(ref_of).transpose()?,
                    depth: node.depth,
                    role: node.node.role,
                    label: node.node.label,
                    current_streak: node.node.streak.map(|(current, _)| current),
                    longest_streak: node.node.streak.map(|(_, longest)| longest),
                });
            }
            Ok(Some(ProductivityTree {
                root_ref: ref_of(&root)?,
                nodes: rows,
            }))
        })
    }
}

/// A TASK row of a public role, with its label and a Habit's counters
/// (zero before its first check-in); `None` for any other row.
fn node_body(raw: &[u8]) -> MemoryResult<Option<NodeBody>> {
    let header = EntityMetadataHeader::parse(raw)
        .ok_or(Error::CorruptedIndex("productivity tree header"))?;
    if header.entity_type != ENTITY_TYPE_TASK {
        return Ok(None);
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let Some(role) = ProductivityRole::of(task_role_from_body_bytes(body)?) else {
        return Ok(None);
    };
    // The role decoder above has refused every body that is not one map.
    let entries = match rmpv::decode::read_value(&mut &body[..]) {
        Ok(Value::Map(entries)) => entries,
        _ => return Err(Error::CorruptedIndex("productivity tree body").into()),
    };
    let field = |key: &str| {
        entries
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, value)| value)
    };
    let counter = |key: &str| {
        field(key)
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .unwrap_or(0)
    };
    Ok(Some(NodeBody {
        role,
        label: field(TASK_BODY_LABEL_KEY)
            .and_then(Value::as_str)
            .map(str::to_owned),
        streak: (role == ProductivityRole::Habit).then(|| {
            (
                counter(TASK_BODY_CURRENT_STREAK_KEY),
                counter(TASK_BODY_LONGEST_STREAK_KEY),
            )
        }),
    }))
}
