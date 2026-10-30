//! The memory a parsed object tree holds, on its inspection's host (FIX
//! 12230). An object-stream member the preflight parses itself is admitted
//! before its parse at the bound its source bytes set, and kept at its
//! measured size while the document holds it. lopdf's own load parses the
//! file's objects before any of them can be admitted, so they are measured,
//! and admitted, as soon as it returns.
use super::*;
use std::mem::size_of;

/// The most one node of a parsed object tree takes beside its byte buffers:
/// its slot in the array or dictionary that holds it (a dictionary's slot is
/// the value beside its hash, key and index), four times over for that
/// table's growth and least capacity. Every array and dictionary is charged
/// one more slot for its own table's least capacity.
const TREE_SLOT_BYTES: usize =
    4 * (size_of::<Object>() + size_of::<Vec<u8>>() + 2 * size_of::<usize>());

/// The most a parsed object tree takes per byte it is parsed from, the one
/// factor this file sizes trees by: the parser makes at most one node or one
/// table per source byte, and a name or string buffer holds at most eight
/// bytes per source byte, an empty buffer's least capacity included.
pub(super) const TREE_BYTES_PER_SOURCE_BYTE: usize = TREE_SLOT_BYTES + 8;

/// Admits what the document keeps of `object`, one tree in its object
/// table, at its measured size ([`tree_bytes`]).
pub(super) fn keep(stage: &Stage, object: &Object) -> Result<()> {
    if !stage.admits() {
        return Ok(());
    }
    stage.admit(held_bytes(object))
}

/// Admits every tree lopdf's load parsed into `document`'s object table, at
/// its measured size. A stream's content is lopdf's own admitted copy and is
/// not counted again.
pub(super) fn keep_loaded(stage: &Stage, document: &Document) -> Result<()> {
    if !stage.admits() {
        return Ok(());
    }
    stage.admit(
        document
            .objects
            .values()
            .map(held_bytes)
            .fold(0, usize::saturating_add),
    )
}

/// `object` in an object table: its entry's share of the table, and its tree.
fn held_bytes(object: &Object) -> usize {
    btree_entry_bytes::<ObjectId, Object>().saturating_add(tree_bytes(object))
}

/// What `object`'s tree holds: a slot per node and per table, and its
/// buffers' capacities. Never more than its source bytes times
/// [`TREE_BYTES_PER_SOURCE_BYTE`].
fn tree_bytes(object: &Object) -> usize {
    let own = match object {
        Object::Name(bytes) | Object::String(bytes, _) => bytes.capacity(),
        Object::Array(items) => items
            .iter()
            .map(tree_bytes)
            .fold(TREE_SLOT_BYTES, usize::saturating_add),
        Object::Dictionary(dictionary) => dictionary_bytes(dictionary),
        Object::Stream(stream) => dictionary_bytes(&stream.dict),
        _ => 0,
    };
    TREE_SLOT_BYTES.saturating_add(own)
}

fn dictionary_bytes(dictionary: &Dictionary) -> usize {
    dictionary
        .iter()
        .map(|(key, value)| key.capacity().saturating_add(tree_bytes(value)))
        .fold(TREE_SLOT_BYTES, usize::saturating_add)
}
