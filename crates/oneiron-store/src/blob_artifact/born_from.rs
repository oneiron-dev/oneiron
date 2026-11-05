//! Born-from (ARCH-0078 section 4): every artifact answers "born from what"
//! the same way. An artifact's first version stamps the artifact row's birth
//! (`provenance::birth`, so [`Vault::rows_born_from`] lists the artifacts a
//! task, ask, run or skill produced). This index is the version-level
//! complement over the version ledger: the trigger in every version's
//! made_by, and the agent run in its provenance, read backwards, so a task
//! also lists the versions it made of artifacts it did not create.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::write_envelope::provenance::made_by::MadeByTrigger;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use oneiron_base::registry::ENTITY_TYPE_CLAIM;
use oneiron_contracts::entity_id::EntityId;

pub const SOURCE_TASK: u8 = b't';
pub const SOURCE_ASK: u8 = b'a';
pub const SOURCE_CODE_RUN: u8 = b'c';
pub const SOURCE_SKILL: u8 = b's';
pub const SOURCE_AGENT_RUN: u8 = b'r';

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornFromRow {
    pub at: u64,
}
