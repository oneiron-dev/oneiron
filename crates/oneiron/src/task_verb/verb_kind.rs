use crate::error::{Error, RecordError, Result};

/// Shape discriminator on the typed TASK body. Absent on a schema-v1 row,
/// where it means [`TaskKind::Standard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Standard,
    Consult,
    Reconciliation,
}

impl TaskKind {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Consult => "consult",
            Self::Reconciliation => "reconciliation",
        }
    }

    /// The OF-543 seed-type hint this shape contributes to placement. A
    /// hint only: placement (`crate::task_type`) makes the one call, and a
    /// standard task carries no hint.
    #[must_use]
    pub const fn seed_task_type(self) -> Option<crate::task_type::SeedTaskType> {
        match self {
            Self::Standard => None,
            Self::Consult => Some(crate::task_type::SeedTaskType::Judge),
            Self::Reconciliation => Some(crate::task_type::SeedTaskType::Solve),
        }
    }

    pub(super) fn from_token(token: &str) -> Result<Self> {
        match token {
            "standard" => Ok(Self::Standard),
            "consult" => Ok(Self::Consult),
            "reconciliation" => Ok(Self::Reconciliation),
            _ => Err(Error::Record(RecordError::InvalidTaskBody(
                "tasks.body.kind",
            ))),
        }
    }
}

pub use crate::gate::task_assignee::TaskAssignee;

/// Absolute expiry instant. A relative duration would mean a different wall
/// time on every replica, so the caller's clock is resolved once, here.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct TaskTtl {
    pub deadline_at: u64,
}

impl TaskTtl {
    /// An already-absolute deadline.
    #[must_use]
    pub const fn at(deadline_at: u64) -> Self {
        Self { deadline_at }
    }

    /// Resolves `now + duration` to the stored absolute deadline.
    #[must_use]
    pub const fn after(now: u64, duration_seconds: u64) -> Self {
        Self {
            deadline_at: now.saturating_add(duration_seconds),
        }
    }
}
