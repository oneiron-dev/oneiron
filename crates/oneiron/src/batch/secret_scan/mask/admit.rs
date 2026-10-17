//! Mask on write for content a writer stores outside the batch door
//! (OF-067): a message stream's seed, a NOTE's live text, a proposal's body,
//! a code file's edit. The batch door's own plan reads it: each secret its
//! text rules place goes to custody and leaves its handle, the copy is read
//! again, and a hit no span places refuses the write before any record is
//! minted. The owner's switch, read in the writer's transaction, turns it
//! off as it turns off the batch door.
//!
//! It mints through the side-row wall's one core
//! ([`admit_seeded_parts`]), with each part's own record and place on its
//! custody origin.
//!
//! A document whose stored history is its receipt ledger cannot take a
//! handle in place of what an operation wrote; [`scan_document_in_txn`]
//! refuses a hit there instead.

use std::collections::HashMap;

use heed::{RoTxn, RwTxn};

use super::super::{SecretScanMode, scan_payload, secret_scan_mode_in_txn};
use super::secret_spans;
use super::side_row::{SidePart, admit_seeded_parts};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::SideTableDbs;

/// What a stream's admitted text keeps in place of a secret it may still be
/// writing: a span that reaches the end of the text so far. The door reads it
/// as a placeholder, so a credential name before it holds no value.
const WITHHELD: &str = "[secret redacted]";

/// The secrets one writer lifted into custody so far, by value, each with its
/// handle: a stream reads its whole text again at each checkpoint and keeps
/// the handle an earlier checkpoint minted. What one transaction adds is kept
/// only once that transaction commits.
#[derive(Clone, Default)]
pub(crate) struct Lifted(pub(super) HashMap<Vec<u8>, String>);

/// One part of a record a writer stores outside a batch: text, read as the
/// batch door reads a text field, or a body, read as it reads a put.
pub(crate) enum Part<'a> {
    Text(&'a mut String),
    Body(&'a mut Vec<u8>),
}

/// Admits the `parts` of `record`, each under its place (`text:<field>`,
/// `body`), in the writer's transaction. With the owner's switch on, parts the
/// door would refuse are planned on a copy with a stand-in for each secret
/// their spans place, and the copy is read again: only a clean copy mints
/// custody records, one per value (a value in `lifted` keeps its handle). The
/// parts then hold their handles. A hit the plan leaves refuses the write with
/// the door's reason, before anything is minted. Returns whether a part
/// changed.
pub(crate) fn admit_parts_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    record: EntityId,
    parts: &mut [(&str, Part<'_>)],
    lifted: &mut Lifted,
) -> Result<bool> {
    let origins = parts
        .iter()
        .map(|(place, _)| (record, *place))
        .collect::<Vec<_>>();
    let mut admitted = parts
        .iter()
        .map(|(_, part)| match part {
            Part::Text(text) => SidePart::Text((**text).clone()),
            Part::Body(data) => SidePart::Body((**data).clone()),
        })
        .collect::<Vec<_>>();
    if !admit_seeded_parts(vault, wtxn, &origins, &mut admitted, lifted, |_| true)? {
        return Ok(false);
    }
    for ((_, part), admitted) in parts.iter_mut().zip(admitted) {
        match (part, admitted) {
            (Part::Text(text), SidePart::Text(masked)) => **text = masked,
            (Part::Body(data), SidePart::Body(masked)) => **data = masked,
            _ => {
                return Err(Error::InvariantViolation(
                    "an admitted part is no longer what it was",
                ));
            }
        }
    }
    Ok(true)
}

/// [`admit_parts_in_txn`] for a stream's text, read again whole at each
/// checkpoint. While the stream is `open`, a span that reaches the end of the
/// text may still grow (a key arriving a token at a time): the admitted text
/// withholds it ([`WITHHELD`]) and nothing is minted for it yet. Once the text
/// goes past it, or the stream ends, it goes to custody whole. Returns the
/// admitted text and whether it withholds a span.
pub(crate) fn admit_stream_text_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    record: EntityId,
    place: &str,
    text: &str,
    open: bool,
    lifted: &mut Lifted,
) -> Result<(String, bool)> {
    if secret_scan_mode_in_txn(&vault.store, wtxn)? == SecretScanMode::Off {
        return Ok((text.to_owned(), false));
    }
    let growing = secret_spans(text)
        .last()
        .filter(|(span, _)| open && span.end == text.len())
        .map(|(span, _)| span.start);
    let mut admitted = match growing {
        Some(start) => [&text[..start], WITHHELD].concat(),
        None => text.to_owned(),
    };
    admit_parts_in_txn(
        vault,
        wtxn,
        record,
        &mut [(place, Part::Text(&mut admitted))],
        lifted,
    )?;
    Ok((admitted, growing.is_some()))
}

/// The batch door's scan of content a writer stores outside a batch, under
/// the owner's switch as the writer's transaction reads it: a hit refuses.
/// For a field no handle can stand in (an identifier, a quote its hash
/// checks), and for a writer that owns bytes this door does not rewrite.
pub(crate) fn scan_content_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    data: &[u8],
) -> Result<()> {
    if secret_scan_mode_in_txn(store, txn)? == SecretScanMode::Off {
        return Ok(());
    }
    let _secrets_nulled = scan_payload(data)?;
    Ok(())
}

/// [`scan_content_in_txn`] over a document as one write leaves it, where its
/// stored history keeps what each operation wrote, so no handle can replace
/// it. A hit refuses unless `before` (the document as the write found it,
/// read only on a hit) reads the same way: a secret stored before this wall
/// existed, or while the switch was off, is not this write's, and only a lift
/// sweep reaches it.
pub(crate) fn scan_document_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    after: &[u8],
    before: impl FnOnce() -> Result<Option<Vec<u8>>>,
) -> Result<()> {
    let Err(refusal) = scan_content_in_txn(store, txn, after) else {
        return Ok(());
    };
    match before()? {
        Some(before) if scan_payload(&before).is_err() => Ok(()),
        _ => Err(refusal),
    }
}
