//! Moved from `crates/oneiron/src/memory/structural/productivity.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::write_envelope::task_body::TaskRole;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;

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
