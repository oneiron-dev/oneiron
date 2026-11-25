//! The `vault.arms.*` verbs' inputs and answers. Ids travel as lower hex; the
//! stored arm goes out whole, beside what is derived from it.
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MemoryError, MemoryResult};

use super::ExperimentArm;

/// `vault.arms.get`: one arm, by its id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmRef {
    /// The arm's id, hex.
    pub arm: String,
}

impl ArmRef {
    /// The arm's id.
    ///
    /// # Errors
    ///
    /// `bad_request` for an id that does not parse.
    pub fn id(&self) -> MemoryResult<EntityId> {
        parse_id(&self.arm, "arm")
    }
}

/// `vault.arms.list`: the arms the caller may read, newest first; with
/// `line` only that line's, with `family` only that family's, and with
/// `open_only` only the arms no rung closed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmListRequest {
    #[serde(default)]
    pub line: Option<String>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub open_only: bool,
}

impl ArmListRequest {
    /// The line and family filters, parsed.
    ///
    /// # Errors
    ///
    /// `bad_request` for an id that does not parse.
    pub fn filters(&self) -> MemoryResult<(Option<EntityId>, Option<EntityId>)> {
        let line = self
            .line
            .as_deref()
            .map(|line| parse_id(line, "line"))
            .transpose()?;
        let family = self
            .family
            .as_deref()
            .map(|family| parse_id(family, "family"))
            .transpose()?;
        Ok((line, family))
    }
}

/// One arm as a door answers it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmView {
    pub arm: ExperimentArm,
    /// Whether no rung closed the arm.
    pub open: bool,
    /// The rung the arm stands at.
    pub rung: u8,
    /// True when a write door answered a repeat of an ask it had already
    /// written under the same intent key.
    #[serde(default)]
    pub replayed: bool,
}

impl ArmView {
    /// The view of `arm`; `replayed` for a write door's repeat.
    #[must_use]
    pub fn of(arm: ExperimentArm, replayed: bool) -> Self {
        Self {
            open: arm.is_open(),
            rung: arm.current_rung(),
            arm,
            replayed,
        }
    }
}

/// `vault.arms.list`'s answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmList {
    pub arms: Vec<ArmView>,
}

fn parse_id(hex: &str, what: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(hex).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            format!("the {what} id is not an entity id in hex"),
            &["Pass the id as the doors answer it."],
        )
    })
}
