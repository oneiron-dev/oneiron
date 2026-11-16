//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/applied.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::maintenance::identity;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::side_table::key::SideKey;
use serde::Deserialize;
use serde::Serialize;

/// The Gate receipt the owner's revert of one leaves.
pub const MAINTENANCE_REVERT_KIND: &str = "dreamer_maintenance_revert";

/// What one applied write is filed under: the finding it landed, the
/// identity ask a background abstention kept provisional or a background
/// settle decided, or the project tree fork the Coach put in force; the last
/// two have no finding claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceTarget {
    Finding(EntityId),
    /// The ask's key, the 64 hex `/v1/owner/identity/asks` lists while it
    /// is open; a settle's names the mention as its ask would.
    IdentityAsk([u8; 32]),
    /// A project and the team-shape fork put in force for it.
    ProjectTreeFork {
        project: EntityId,
        fork: EntityId,
    },
}

/// The first byte of a project tree fork's key, ahead of its two ids.
pub const PROJECT_TREE_FORK_KEY: u8 = 1;

impl MaintenanceTarget {
    /// A finding's 32 hex, an identity ask's 64 hex, or a project tree
    /// fork's project and fork, 32 hex each, joined by `:`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        match self {
            Self::Finding(id) => id.to_hex(),
            Self::IdentityAsk(key) => oneiron_contracts::entity_id::bytes_to_hex_lower(key),
            Self::ProjectTreeFork { project, fork } => {
                format!("{}:{}", project.to_hex(), fork.to_hex())
            }
        }
    }

    /// The identity ask a 64-hex key names.
    #[must_use]
    pub fn identity_ask(hex: &str) -> Option<Self> {
        identity::parse_key(hex).map(Self::IdentityAsk)
    }

    /// The finding claim, when the target is one.
    pub const fn finding(&self) -> Option<EntityId> {
        match self {
            Self::Finding(id) => Some(*id),
            Self::IdentityAsk(_) | Self::ProjectTreeFork { .. } => None,
        }
    }
}

/// A finding's 16 id bytes, an ask's 32 key bytes, or a project tree fork's
/// tag byte and its project's and fork's 16 id bytes (33): the width tells
/// them apart.
impl SideKey for MaintenanceTarget {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Finding(id) => id.encode_into(out),
            Self::IdentityAsk(key) => key.encode_into(out),
            Self::ProjectTreeFork { project, fork } => {
                out.push(PROJECT_TREE_FORK_KEY);
                project.encode_into(out);
                fork.encode_into(out);
            }
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            16 => EntityId::decode_key(bytes).map(Self::Finding),
            32 => <[u8; 32]>::decode_key(bytes).map(Self::IdentityAsk),
            33 => {
                let (&tag, ids) = bytes.split_first()?;
                if tag != PROJECT_TREE_FORK_KEY {
                    return None;
                }
                let (project, fork) = ids.split_at(16);
                Some(Self::ProjectTreeFork {
                    project: EntityId::decode_key(project)?,
                    fork: EntityId::decode_key(fork)?,
                })
            }
            _ => None,
        }
    }
}

/// What the owner's revert of one applied write did: the records standing
/// again in place, the Dreamer's fresh copies of its own signed records as
/// (record, copy), the outputs the write made that the revert closed, the
/// settings rows put back, the identity asks put to the owner (64 hex), and
/// what a later write changed, left as it is (a record's 32-hex id, an ask's
/// or a mention's 64 hex, or a settings row's name), or what no revert takes
/// back (a person a settle confirmed). A write closed by its parent's revert
/// names that parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceRevert {
    pub target: MaintenanceTarget,
    pub restored: Vec<EntityId>,
    pub copied: Vec<(EntityId, EntityId)>,
    pub closed: Vec<EntityId>,
    pub settings: Vec<String>,
    pub asked: Vec<String>,
    pub left_alone: Vec<String>,
    pub receipt_ref: String,
    /// The applied write whose revert closed this one with it (a reach-out
    /// whose revert withdrew this follow-up plan, FIX 3329); none for the
    /// owner's own revert of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<MaintenanceTarget>,
}
