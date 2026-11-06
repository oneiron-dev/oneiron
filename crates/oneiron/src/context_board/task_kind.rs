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

    pub(crate) fn from_token(token: &str) -> Result<Self> {
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
