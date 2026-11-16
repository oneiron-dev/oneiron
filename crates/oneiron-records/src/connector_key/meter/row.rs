//! Moved from `crates/oneiron/src/connector_key/meter/row.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Usage-row key tag of a key budget row.
pub const EFFECTOR_BUDGET_ROW_TAG_KEY: u8 = 0;

/// Usage-row key tag of a compiled-charter cap row (GOV-10).
pub const EFFECTOR_BUDGET_ROW_TAG_CHARTER: u8 = 1;

/// Where a budget row is declared on its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectorBudgetRowSource {
    /// The key's own `budgets` rows.
    Key,
    /// The stamped charter's compiled `channel_caps` (GOV-10).
    Charter,
}

impl EffectorBudgetRowSource {
    /// The usage-row key tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Key => EFFECTOR_BUDGET_ROW_TAG_KEY,
            Self::Charter => EFFECTOR_BUDGET_ROW_TAG_CHARTER,
        }
    }

    /// The source a usage-row key tag names.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            EFFECTOR_BUDGET_ROW_TAG_KEY => Some(Self::Key),
            EFFECTOR_BUDGET_ROW_TAG_CHARTER => Some(Self::Charter),
            _ => None,
        }
    }
}

/// One budget row of a key: its source and its ordinal within that source.
/// Order is key rows first, then charter caps, each ascending, so a row set
/// sorts the way the meter evaluates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EffectorBudgetRowId {
    pub source: EffectorBudgetRowSource,
    pub index: u64,
}

/// Bytes of a usage-row key suffix: the source tag, then the ordinal BE.
pub const EFFECTOR_BUDGET_ROW_KEY_LEN: usize = 1 + size_of::<u64>();

impl EffectorBudgetRowId {
    /// The key budget row at `index`.
    #[must_use]
    pub const fn key(index: u64) -> Self {
        Self {
            source: EffectorBudgetRowSource::Key,
            index,
        }
    }

    /// The compiled charter cap at `index`.
    #[must_use]
    pub const fn charter(index: u64) -> Self {
        Self {
            source: EffectorBudgetRowSource::Charter,
            index,
        }
    }

    /// The usage-row key suffix after the owning key's id.
    pub fn usage_key(self) -> [u8; EFFECTOR_BUDGET_ROW_KEY_LEN] {
        let mut key = [0_u8; EFFECTOR_BUDGET_ROW_KEY_LEN];
        key[0] = self.source.tag();
        key[1..].copy_from_slice(&self.index.to_be_bytes());
        key
    }

    /// The row a usage-row key suffix names; `None` for an unknown tag.
    pub fn from_usage_key(key: [u8; EFFECTOR_BUDGET_ROW_KEY_LEN]) -> Option<Self> {
        let source = EffectorBudgetRowSource::from_tag(key[0])?;
        let mut index = [0_u8; size_of::<u64>()];
        index.copy_from_slice(&key[1..]);
        Some(Self {
            source,
            index: u64::from_be_bytes(index),
        })
    }
}

/// The budget row a charge stopped on, under the key that owns it: the
/// per-grant key's own row, or its catalog pool's row under the catalog key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectorBudgetLocation {
    pub key_ref: EntityId,
    pub row: EffectorBudgetRowId,
}
