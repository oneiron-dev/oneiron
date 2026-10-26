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

use super::super::commit_receipts::RECEIPT_PREFIX;
use super::super::document::cut_stamp;
use super::hex_id;
use super::loro::STAMP_ACTOR;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::provenance::made_by::{MadeByClass, MadeByInput, MadeByTrigger};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::store::checkpoint_payload::loro::{Split, SplitValue};
use crate::store::checkpoint_payload::rows;

/// The path of a receipt's process actor in its message.
const PROCESS_ACTOR: &str = "made_by.process.actor";
/// The path of a receipt's process identity, where it spells its actor.
const PROCESS_IDENTITY: &str = "made_by.process.identity";

/// A receipted message no projection here cuts losslessly.
const NOT_A_RECEIPT: &str = "an entity document commit receipt that does not spell back";

/// A made_by receipt as a projection holds it: field for field the live
/// envelope, its process actor and identity plain text that may be erased.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    inputs: Vec<MadeByInput>,
    process: Process,
    at: u64,
    trigger: Option<MadeByTrigger>,
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
struct Cut<'m> {
    head: &'m str,
    id: &'m str,
    tail: &'m str,
    receipt: Receipt,
}

impl Cut<'_> {
    /// The message spelled back with `id` in its stamp.
    fn spell(&self, id: &str) -> Option<String> {
        let receipt = serde_json::to_string(&self.receipt).ok()?;
        Some(format!(
            "{}{id}{}{RECEIPT_PREFIX}{receipt}",
            self.head, self.tail
        ))
    }
}

/// `message` cut, when it is a receipted generic or proposal message whose
/// receipt spells back byte for byte.
fn cut(message: &str) -> Option<Cut<'_>> {
    let (head, id, tail, json) = generic(message).or_else(|| proposal(message))?;
    let receipt: Receipt = serde_json::from_str(json).ok()?;
    let cut = Cut {
        head,
        id,
        tail,
        receipt,
    };
    (cut.spell(id)? == message).then_some(cut)
}

/// A generic stamp's cut ([`cut_stamp`]) and its receipt's JSON.
fn generic(message: &str) -> Option<(&str, &str, &str, &str)> {
    let (stamped, json) = message.split_once(RECEIPT_PREFIX)?;
    let (head, id, tail) = cut_stamp(stamped)?;
    Some((head, id, tail, json))
}

/// A proposal stamp's cut and its receipt's JSON, as the proposal text
/// artifact spells them; no build without sync writes one.
#[cfg(feature = "sync")]
fn proposal(message: &str) -> Option<(&str, &str, &str, &str)> {
    crate::edit_distance::proposal_text::cut_receipted_message(message)
}

#[cfg(not(feature = "sync"))]
fn proposal(_: &str) -> Option<(&str, &str, &str, &str)> {
    None
}

/// The split of `message` when it carries a receipt: its no-one form and its
/// actor at each path it names it, or the carrier refused. `None` for a
/// message with no receipt, which the plain stamp split reads.
pub(super) fn split(message: &str) -> Option<Split<String>> {
    message
        .contains(RECEIPT_PREFIX)
        .then(|| split_receipted(message))
}

fn split_receipted(message: &str) -> Split<String> {
    let mut cut = cut(message).ok_or(NOT_A_RECEIPT)?;
    let erased = ERASED_CALL_IDENTITY;
    if cut.id == erased && cut.receipt.process.actor == erased {
        return Ok(SplitValue::kept(message.to_owned()));
    }
    // The stamp and its receipt name one actor, or neither is read.
    let actor = hex_id(cut.id).ok_or(NOT_A_RECEIPT)?;
    if cut.receipt.process.actor != cut.id {
        return Err(NOT_A_RECEIPT);
    }
    let mut actors = vec![
        (STAMP_ACTOR.to_owned(), actor),
        (PROCESS_ACTOR.to_owned(), actor),
    ];
    cut.receipt.process.actor = erased.to_owned();
    if cut.receipt.process.identity == cut.id {
        cut.receipt.process.identity = erased.to_owned();
        actors.push((PROCESS_IDENTITY.to_owned(), actor));
    }
    let no_one = cut.spell(erased).ok_or(NOT_A_RECEIPT)?;
    Ok(SplitValue { no_one, actors })
}

/// The receipted no-one message `no_one` with `actor` back at `path`, in any
/// order of its holes; `None` for a message with no receipt.
pub(super) fn fill(no_one: &str, path: &str, actor: EntityId) -> Option<Result<String>> {
    no_one
        .contains(RECEIPT_PREFIX)
        .then(|| fill_receipted(no_one, path, actor))
}

fn fill_receipted(no_one: &str, path: &str, actor: EntityId) -> Result<String> {
    let mut cut = cut(no_one).ok_or_else(rows::bad_part)?;
    let hex = actor.to_hex();
    let erased = ERASED_CALL_IDENTITY;
    let mut id = cut.id;
    match path {
        STAMP_ACTOR if id == erased => id = hex.as_str(),
        PROCESS_ACTOR if cut.receipt.process.actor == erased => {
            cut.receipt.process.actor.clone_from(&hex);
        }
        PROCESS_IDENTITY if cut.receipt.process.identity == erased => {
            cut.receipt.process.identity.clone_from(&hex);
        }
        _ => return Err(rows::bad_part()),
    }
    cut.spell(id).ok_or_else(rows::bad_part)
}
