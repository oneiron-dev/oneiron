//! Core half of `entity_doc::checkpoint::message_receipts`: its store-layer items live in `oneiron_store::entity_doc::checkpoint::message_receipts` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::entity_doc::checkpoint::message_receipts::*;

use super::super::commit_receipts::RECEIPT_PREFIX;
use super::super::document::cut_stamp;
use super::hex_id;
use super::loro::STAMP_ACTOR;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::checkpoint_payload::loro::{Split, SplitValue};
use crate::store::checkpoint_payload::rows;
use crate::store::receipt_identity::ERASED_CALL_IDENTITY;
use crate::write_envelope::provenance::made_by::{MadeByClass, MadeByInput, MadeByTrigger};
use serde::{Deserialize, Serialize};

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
