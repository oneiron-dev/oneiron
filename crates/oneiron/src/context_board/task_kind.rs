use oneiron_contracts::register::Register;

use crate::error::{Error, RecordError, Result};

/// Shape discriminator on the typed TASK body. Absent on a schema-v1 row,
/// where it means [`TaskKind::Standard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Register)]
#[serde(rename_all = "snake_case")]
#[register("task.kind")]
pub enum TaskKind {
    Standard,
    Consult,
    Reconciliation,
}

impl TaskKind {
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

    pub(crate) fn from_token(token: &str) -> Result<Self> {
        <Self as Register>::named(token)
            .ok_or_else(|| Error::Record(RecordError::InvalidTaskBody("tasks.body.kind")))
    }
}
