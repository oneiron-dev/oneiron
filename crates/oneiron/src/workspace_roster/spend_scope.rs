use crate::attempt_queue::AttemptId;
use crate::claim::dispatch_input::invalid;
use serde::{Deserialize, Serialize};

/// A spend scope's id. A root scope's id is its launch id; a child scope's id
/// is the child's attempt id, in lowercase hex.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct SpendScopeId(pub(crate) String);

impl SpendScopeId {
    /// A root launch id the host names: printable ASCII, at most 128 bytes,
    /// and never shaped like an attempt id, so roots and children cannot meet.
    pub fn launch(id: impl Into<String>) -> crate::error::Result<Self> {
        let id = id.into();
        if id.is_empty()
            || id.len() > 128
            || !id.bytes().all(|byte| byte.is_ascii_graphic())
            || (id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(invalid(
                "a launch id is 1..=128 printable bytes, not an attempt id",
            ));
        }
        Ok(Self(id))
    }

    /// The scope an agent attempt spends under.
    #[must_use]
    pub fn for_attempt(attempt: &AttemptId) -> Self {
        Self(crate::entity_id::bytes_to_hex_lower(attempt.as_bytes()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SpendScopeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Whether a scope still takes spend and reservations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpendState {
    Open,
    /// Settled into its parent. Late spend lands on the nearest open ancestor.
    Closed,
}

/// What a child launch asks of its parent's scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChildSpend {
    /// The spawn set `budget`: a hard cap the child can never pass.
    Carve { cap_units: u64 },
    /// No `budget`: hold the calibrated expected spend; top up later, up to the
    /// nearest hard ancestor's cap. A hold is never refused for its estimate.
    Hold { expected_units: u64 },
}
