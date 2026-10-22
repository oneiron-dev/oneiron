//! A semantic NOTE command as this host queues it for its authority (FIX
//! 2375; C-NOTE-COMMAND). Its prose, each edit's insert and a new title, is
//! admitted before the command is framed, queued or sent
//! ([`super::free_text`]). The queue keeps one envelope per request: the
//! digest of the command as its caller gave it, which only a retry of the
//! same request on this host matches, and the exact frame of the command as
//! admitted, which is what is sent and replayed and what the authority's
//! receipt hashes. No copy of the command as given is kept. A pin, its hash
//! and cursors, a base frontier and the frame's header are no prose and stay
//! as given.

use super::document::invalid;
use super::{NoteChange, NoteEdit, NoteOperation};
use crate::Vault;
use crate::batch::secret_scan::{Lifted, Part};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The envelope's first byte: its layout.
const ENVELOPE_V1: u8 = 1;

/// Where a command's secrets were found, for their custody records.
const INSERT: &str = "text:insert";
const TITLE: &str = "text:title";

/// The carrier [`super::free_text`] names.
const CARRIER: &str = "note.pending_request";

/// One queued request: the digest of the command as given, and the frame of
/// the command as admitted.
pub(crate) struct PendingNoteRequest<'a> {
    pub(crate) input: [u8; 32],
    pub(crate) frame: &'a [u8],
}

impl<'a> PendingNoteRequest<'a> {
    /// The digest a retry of `operation`, as its caller gives it, matches.
    pub(crate) fn input_digest(operation: &NoteOperation) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&operation.encode()?).as_bytes())
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.input.len() + self.frame.len());
        bytes.push(ENVELOPE_V1);
        bytes.extend_from_slice(&self.input);
        bytes.extend_from_slice(self.frame);
        bytes
    }

    /// The envelope `bytes` lays out; `None` for bytes no envelope does.
    pub(crate) fn decode(bytes: &'a [u8]) -> Option<Self> {
        let (&ENVELOPE_V1, rest) = bytes.split_first()? else {
            return None;
        };
        let (input, frame) = rest.split_first_chunk::<32>()?;
        (!frame.is_empty()).then_some(Self {
            input: *input,
            frame,
        })
    }
}

/// `operation` as this host sends it for NOTE `note`: each edit's insert and
/// a new title admitted with one plan. An edit after an admitted insert has
/// its positions moved to the text that insert now leaves ([`moved`]).
pub(crate) fn admit_note_operation_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    operation: &NoteOperation,
) -> Result<NoteOperation> {
    let mut admitted = operation.clone();
    let mut lifted = Lifted::default();
    match (&operation.change, &mut admitted.change) {
        (NoteChange::Edit { edits: given, .. }, NoteChange::Edit { edits, .. }) => {
            let mut parts = edits
                .iter_mut()
                .map(|edit| (INSERT, Part::Text(&mut edit.insert)))
                .collect::<Vec<_>>();
            let changed = super::free_text::admit_free_text_in_txn(
                vault,
                txn,
                note,
                CARRIER,
                &mut parts,
                &mut lifted,
            )?;
            drop(parts);
            if changed {
                moved(given, edits)?;
            }
        }
        (_, NoteChange::SetTitle { title }) => {
            super::free_text::admit_free_text_in_txn(
                vault,
                txn,
                note,
                CARRIER,
                &mut [(TITLE, Part::Text(title))],
                &mut lifted,
            )?;
        }
        _ => {}
    }
    Ok(admitted)
}

/// One stretch of an edited text whose admitted reading differs: `len`
/// characters from `start` of the text the command as given leaves, read as
/// `admitted` characters of the text it leaves as admitted.
#[derive(Clone, Copy)]
struct Stretch {
    start: usize,
    len: usize,
    admitted: usize,
}

impl Stretch {
    const fn end(self) -> usize {
        self.start + self.len
    }
}

/// Moves each of `edits`, the admitted copies of `given`, to the text the
/// admitted edits before it leave, in Unicode scalar positions. A position
/// past an admitted insert moves by what that insert gained or lost; a range
/// edge inside one moves out to its edge, and an insert inside one to its
/// end, so no edit splits a handle (C-NOTE-COMMAND).
fn moved(given: &[NoteEdit], edits: &mut [NoteEdit]) -> Result<()> {
    let mut stretches = Vec::<Stretch>::new();
    for (given, edit) in given.iter().zip(edits.iter_mut()) {
        let (start, len) = (given.start, given.insert.chars().count());
        let end = start
            .checked_add(given.delete)
            .ok_or_else(|| invalid("NOTE range overflow"))?;
        let around = |at: usize| {
            stretches
                .iter()
                .copied()
                .find(|stretch| stretch.start < at && at < stretch.end())
        };
        let inside = around(start).filter(|_| given.delete == 0);
        let (left, right) = match inside {
            Some(stretch) => (stretch.start, stretch.end()),
            None => (
                around(start).map_or(start, |stretch| stretch.start),
                around(end).map_or(end, Stretch::end),
            ),
        };
        let from = if inside.is_some() { right } else { left };
        edit.start = admitted_at(&stretches, from);
        edit.delete = admitted_at(&stretches, right) - edit.start;
        let admitted = edit.insert.chars().count() + inside.map_or(0, |stretch| stretch.admitted);
        let widened = left < start || right > end || inside.is_some();
        stretches.retain(|stretch| stretch.end() <= left || stretch.start >= right);
        for stretch in &mut stretches {
            if stretch.start >= right {
                stretch.start = stretch.start - given.delete + len;
            }
        }
        if widened || edit.insert != given.insert {
            stretches.push(Stretch {
                start: left,
                len: start - left + len + (right - end),
                admitted,
            });
            stretches.sort_by_key(|stretch| stretch.start);
        }
    }
    Ok(())
}

/// Where `at`, a position in the text the command as given leaves, falls in
/// the text it leaves as admitted: past each stretch before it, by what that
/// stretch gained or lost.
fn admitted_at(stretches: &[Stretch], at: usize) -> usize {
    stretches
        .iter()
        .filter(|stretch| stretch.end() <= at)
        .fold(at, |moved, stretch| moved - stretch.len + stretch.admitted)
}
