//! Point-read targets, frontiers, and admitted row values.

use crate::vault::entity_revision::types::ReadMode;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;

/// What one point read names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadTarget<'r> {
    /// An entity id.
    Id(EntityId),
    /// An engine-issued short reference: short id plus content-hash byte.
    ShortRef { short_id: &'r str, content_hash: u8 },
}

/// One read in a [`ScopedRead::read`] slice: its target and its frontier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointRead<'r> {
    pub target: ReadTarget<'r>,
    pub mode: ReadMode,
}

impl<'r> PointRead<'r> {
    /// The live body of `id`.
    #[must_use]
    pub fn id(id: EntityId) -> Self {
        Self {
            target: ReadTarget::Id(id),
            mode: ReadMode::Live,
        }
    }

    /// The live row behind an engine-issued short reference.
    #[must_use]
    pub fn short(short_id: &'r str, content_hash: u8) -> Self {
        Self {
            target: ReadTarget::ShortRef {
                short_id,
                content_hash,
            },
            mode: ReadMode::Live,
        }
    }

    /// The same target at another frontier (indexed or a pinned revision).
    #[must_use]
    pub fn at(self, mode: ReadMode) -> Self {
        Self { mode, ..self }
    }
}
