//! The order one pass or delta visits AUTHORITY_LOG rows in.
//!
//! The replicated door holds a row whose signer no folded row admitted
//! (H72), so a pass that met a signer's rows before its enrollment would hold
//! them until the next pass. Authority rows therefore land first, each after
//! every row of the same pass it names as a parent: an enrollment is an
//! ancestor of every valid row its key signs. Each signer's rows land by
//! sequence, so no row is first observed below a sibling's sequence and
//! folded as a rollback (`authority::authority_stage_order`).

use crate::authority::{
    authority_entry_hash, authority_stage_order, decode_authority_log_entry_body,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;

/// Whether an entities-map value carries an AUTHORITY_LOG row.
pub(in crate::sync) fn is_authority_row(blob: &[u8]) -> bool {
    EntityMetadataHeader::parse(blob)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_AUTHORITY_LOG)
}

/// Indices of `rows` (key, entity blob) in the order the store door takes
/// them, ties by key. A row whose body does not decode goes first; its door
/// refuses it.
pub(in crate::sync) fn authority_parent_order(rows: &[(&str, &[u8])]) -> Vec<usize> {
    let mut by_key: Vec<usize> = (0..rows.len()).collect();
    by_key.sort_by_key(|at| rows[*at].0);
    let (mut order, mut decoded, mut positions) = (Vec::new(), Vec::new(), Vec::new());
    for at in by_key {
        let entry = rows[at]
            .1
            .get(ENTITY_METADATA_HEADER_LEN..)
            .and_then(|body| decode_authority_log_entry_body(body).ok());
        match entry.and_then(|entry| Some((authority_entry_hash(&entry).ok()?, entry))) {
            Some(row) => {
                decoded.push(row);
                positions.push(at);
            }
            None => order.push(at),
        }
    }
    let entries: Vec<_> = decoded.iter().map(|(hash, entry)| (*hash, entry)).collect();
    order.extend(
        authority_stage_order(&entries)
            .into_iter()
            .map(|index| positions[index]),
    );
    order
}
