//! Receipted commit messages in an entity document's history (FIX 6479): a
//! generic commit's stamp with its made_by receipt (FIX 7790), and a
//! proposal text artifact's (`oneiron.edit_distance.v1`). Each names its
//! actor in its stamp and as its receipt's process actor, and a proposal's
//! default receipt names it a third time as its process identity. Each is cut
//! out at its own path; the receipt is read in a projection form whose actor
//! and identity may be erased, never as a live [`MadeBy`], and spelled back
//! exactly as stored. A message this cannot cut losslessly keeps its whole
//! group under the vault-wide seal, as before. Nothing here authenticates a
//! receipt: the reader does, through the writing peer's binding.
//!
//! [`MadeBy`]: crate::provenance::made_by::MadeBy

use serde::{Deserialize, Serialize};

use crate::checkpoint_payload::loro::Split;
use crate::checkpoint_payload::loro::SplitValue;
use crate::entity_doc::commit_receipts::RECEIPT_PREFIX;
use crate::entity_doc::document::cut_stamp;
use crate::receipt_identity::ERASED_CALL_IDENTITY;
use crate::write_envelope::provenance::made_by::MadeByClass;
use crate::write_envelope::provenance::made_by::MadeByInput;
use crate::write_envelope::provenance::made_by::MadeByTrigger;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The path of a receipt's process actor in its message.
pub const PROCESS_ACTOR: &str = "made_by.process.actor";
/// The path of a receipt's process identity, where it spells its actor.
pub const PROCESS_IDENTITY: &str = "made_by.process.identity";

/// A receipted message no projection here cuts losslessly.
pub const NOT_A_RECEIPT: &str = "an entity document commit receipt that does not spell back";

/// A made_by receipt as a projection holds it: field for field the live
/// envelope, its process actor and identity plain text that may be erased.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub inputs: Vec<MadeByInput>,
    pub process: Process,
    pub at: u64,
    pub trigger: Option<MadeByTrigger>,
}

/// A receipt's process, as [`Receipt`] holds it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Process {
    actor: String,
    class: MadeByClass,
    identity: String,
    version: String,
    params_hash: String,
}

/// A receipted message cut around its carriers: the stamp before its actor
/// id, the id, the stamp's rest up to its receipt, and the receipt.
pub struct Cut<'m> {
    pub head: &'m str,
    pub id: &'m str,
    pub tail: &'m str,
    pub receipt: Receipt,
}

impl Cut<'_> {
    /// The message spelled back with `id` in its stamp.
    pub fn spell(&self, id: &str) -> Option<String> {
        let receipt = serde_json::to_string(&self.receipt).ok()?;
        Some(format!(
            "{}{id}{}{RECEIPT_PREFIX}{receipt}",
            self.head, self.tail
        ))
    }
}

/// A generic stamp's cut ([`cut_stamp`]) and its receipt's JSON.
pub fn generic(message: &str) -> Option<(&str, &str, &str, &str)> {
    let (stamped, json) = message.split_once(RECEIPT_PREFIX)?;
    let (head, id, tail) = cut_stamp(stamped)?;
    Some((head, id, tail, json))
}
