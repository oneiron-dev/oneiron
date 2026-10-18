//! Typed productivity roles (DOOR-113): an inert Goal, Milestone or Habit
//! TASK under its checked `ChildOf` parent, and the role-labelled tree.
//! Tasks keep `tasks.create` (they route); check-ins keep
//! `vault.habits.checkin` (immutable, streak-deriving).

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimReadStatus, ScopedReadResult};
use crate::error::Error;
use crate::habit::{
    TASK_BODY_CURRENT_STREAK_KEY, TASK_BODY_LONGEST_STREAK_KEY, TASK_BODY_ROLE_KEY, TaskRole,
    task_role_from_body_bytes,
};
use crate::memory::support::encode_rmpv;
use crate::memory::{Memory, MemoryResult};
use crate::registry::ENTITY_TYPE_TASK;
use crate::temporal::TimeRange;

use super::EntityRefReceipt;

/// The TASK body key the label rides under, as `tasks.create` writes it.
const TASK_BODY_LABEL_KEY: &str = "label";

/// A role this door creates. A Task is routed work (`tasks.create`); a
/// HabitCheckin is appended under its Habit (`vault.habits.checkin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProductivityCreateRole {
    Goal,
    Milestone,
    Habit,
}

impl ProductivityCreateRole {
    const fn task_role(self) -> TaskRole {
        match self {
            Self::Goal => TaskRole::Goal,
            Self::Milestone => TaskRole::Milestone,
            Self::Habit => TaskRole::Habit,
        }
    }
}

/// A TASK row's pinned productivity role, as the tree reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProductivityRole {
    Task,
    Goal,
    Milestone,
    Habit,
    HabitCheckin,
}

impl ProductivityRole {
    /// `None` for the engine-reserved authority-fact role, never shown.
    const fn of(role: TaskRole) -> Option<Self> {
        match role {
            TaskRole::Task => Some(Self::Task),
            TaskRole::Goal => Some(Self::Goal),
            TaskRole::Milestone => Some(Self::Milestone),
            TaskRole::Habit => Some(Self::Habit),
            TaskRole::HabitCheckin => Some(Self::HabitCheckin),
            TaskRole::AuthorityFact => None,
        }
    }
}

/// One inert productivity row.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProductivityCreateRequest {
    pub role: ProductivityCreateRole,
    /// Display label; must not be blank.
    pub label: String,
    /// Parent TASK ref (short-id ref or hex); `None` ⇒ a root. The pinned
    /// nesting matrix decides in the write: a Milestone nests under a Goal.
    #[serde(default)]
    pub parent_ref: Option<String>,
}

/// The productivity tree under one TASK.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProductivityTreeRequest {
    /// Root TASK ref (short-id ref or hex).
    pub root_ref: String,
    /// Levels below the root to walk; `0` ⇒ the root alone.
    pub max_depth: u32,
}

/// The readable `ChildOf` tree under a root, root first, then by depth and id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProductivityTree {
    pub root_ref: String,
    pub nodes: Vec<ProductivityNode>,
}

/// One TASK in a productivity tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProductivityNode {
    /// Short-id ref of the TASK (hex fallback).
    pub task_ref: String,
    /// 32-hex id of the TASK.
    pub id_hex: String,
    /// Its tree parent's ref; `None` at the root.
    pub parent_ref: Option<String>,
    /// Levels below the root.
    pub depth: u32,
    pub role: ProductivityRole,
    pub label: Option<String>,
    /// A Habit's derived counters; `None` for every other role.
    pub current_streak: Option<u32>,
    pub longest_streak: Option<u32>,
}

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
                    parent_ref: node.parent.as_ref().map(&ref_of).transpose()?,
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
