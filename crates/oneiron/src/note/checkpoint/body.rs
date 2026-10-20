//! A NOTE core's author in its raw entity row (FIX 6072, Engine R2): the
//! `author_ref` of the pinned four-key body split out and put back, every
//! other byte kept. The core reads with the strict decoder and must spell
//! its own bytes back, so a fill gives back exactly the stored row. An
//! author that did not open stays the erased marker, which names no one and
//! no `AuthoredBy` edge; the content survives. A revision document's raw
//! insertions take the same projection (FIX 6072, part 3).
//!
//! A live author's erase changes the core's raw bytes, and so every binding
//! derived from them: the revision refs hashed over raw entity bytes, the
//! short id's content byte and the citation views that render them. No
//! public revision ref changes and no restore rewrites a short id (FIX 6072,
//! lead pick (b)), so the entity-row getter keeps a core with a live author
//! under the vault-wide seal ([`CORE_RAW_REFS`]). A core that names no one,
//! and an erased NOTE's empty shell, stay their tree's as they stand.

use super::super::{NoteActor, NoteBody, NoteKind, decode_note_body_using, encode_note_body};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::store::checkpoint_payload::loro::{self as shared, Split, SplitValue};
use crate::store::checkpoint_payload::rows::{self, ActorPart};

/// The path of a NOTE core's author in its body.
pub(crate) const CORE_AUTHOR: &str = "NoteBody.author_ref";

/// A NOTE core that does not read, or does not spell its bytes back.
pub(crate) const CORE_UNREAD: &str = "a NOTE core that does not spell back";

/// A NOTE core whose live author's erase would change the raw bytes its
/// revision refs, short id and citation views are derived from, which no
/// restore derives again: no public revision ref changes (FIX 6072, lead
/// pick (b)).
pub(crate) const CORE_RAW_REFS: &str = "a NOTE core author whose erase changes raw-derived refs";

/// A NOTE core body, read strictly, when it spells its own bytes back.
fn stored_core(body: &[u8]) -> Option<NoteBody> {
    let core = decode_note_body_using(body, NoteKind::wire).ok()?;
    let spelled = encode_note_body(&core).ok()?;
    (spelled.as_slice() == body).then_some(core)
}

/// Splits a NOTE core's raw row, its entity header then its body: the row
/// with its author in the erased form, and that author. A core whose author
/// is erased names no one and stays as it is.
pub(crate) fn split_core_row(row: &[u8]) -> Split<Vec<u8>> {
    let (header, body) = row
        .split_at_checked(ENTITY_METADATA_HEADER_LEN)
        .ok_or(CORE_UNREAD)?;
    let core = stored_core(body).ok_or(CORE_UNREAD)?;
    let Some(author) = core.author_ref.id() else {
        return Ok(SplitValue::kept(row.to_vec()));
    };
    let no_one = NoteBody {
        author_ref: NoteActor::Erased,
        ..core
    };
    let no_one = encode_note_body(&no_one).map_err(|_| CORE_UNREAD)?;
    Ok(SplitValue {
        no_one: [header, no_one.as_slice()].concat(),
        actors: vec![(CORE_AUTHOR.to_owned(), author)],
    })
}

/// A NOTE core's no-one row with its author back when that author's part
/// opened; with no part it stays no one. Refuses a row whose author is not
/// the erased form, a part for another field and a second part.
pub(crate) fn join_core_row(no_one: &[u8], parts: &[&ActorPart]) -> Result<Vec<u8>> {
    let (header, body) = no_one
        .split_at_checked(ENTITY_METADATA_HEADER_LEN)
        .ok_or_else(rows::bad_part)?;
    let core = stored_core(body).filter(|core| core.author_ref == NoteActor::Erased);
    let core = core.ok_or_else(rows::bad_part)?;
    let atoms = shared::opened_atoms(parts)?;
    let author = match atoms.as_slice() {
        [] => return Ok(no_one.to_vec()),
        [atom] if atom.field == CORE_AUTHOR => atom.actor,
        _ => return Err(rows::bad_part()),
    };
    let core = NoteBody {
        author_ref: NoteActor::Actor(author),
        ..core
    };
    Ok([header, encode_note_body(&core)?.as_slice()].concat())
}

/// Whether `row` is a NOTE core the split reads, whichever author it names.
pub(crate) fn reads_core_row(row: &[u8]) -> bool {
    split_core_row(row).is_ok()
}
