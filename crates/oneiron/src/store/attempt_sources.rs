//! Typed sources retained by an attempt and its terminal receipt.
//!
//! Hashes bind original stored bytes without copying source bodies. These
//! witnesses record reads; the current reader still admits each native row.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::EntityId;

/// The entity and native components of one complete producer report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptSources {
    pub entities: Vec<EntityId>,
    pub native: BTreeSet<NativeReadSource>,
}

impl AttemptSources {
    pub fn entities(mut entities: Vec<EntityId>) -> Self {
        entities.sort_unstable();
        entities.dedup();
        Self {
            entities,
            native: BTreeSet::new(),
        }
    }

    /// An entity-only projection is complete only without native sources.
    pub fn entity_rows(&self) -> Option<&[EntityId]> {
        self.native.is_empty().then_some(self.entities.as_slice())
    }
}

/// A verdict primary and the displacement row its original decoder read.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SkillEditVerdictSource {
    pub id: EntityId,
    pub key: Vec<u8>,
    pub body_hash: [u8; 32],
    pub displacement_key: Vec<u8>,
    /// `None` witnesses the actual absence, not an unknown marker.
    pub displacement_hash: Option<[u8; 32]>,
}

/// A native discovery proposal at its actual u64 primary key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SkillEditProposalSource {
    pub sequence: u64,
    pub id: EntityId,
    pub key: Vec<u8>,
    pub body_hash: [u8; 32],
}

/// Family tags never grant ENTITY access, even for UUID-shaped native keys.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum NativeReadSource {
    SkillEditProposal {
        row: SkillEditProposalSource,
    },
    /// The exact original eager scan, including rows filtered out later.
    SkillEditProposalScan {
        prefix: Vec<u8>,
        rows: Vec<SkillEditProposalSource>,
    },
    JudgeLabel {
        ask_id: [u8; 32],
        key: Vec<u8>,
        body_hash: [u8; 32],
    },
    SkillEditVerdict {
        row: SkillEditVerdictSource,
    },
    /// An original completed scan, including its exact membership and order.
    SkillEditVerdictScan {
        prefix: Vec<u8>,
        rows: Vec<SkillEditVerdictSource>,
    },
}
