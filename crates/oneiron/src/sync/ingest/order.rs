//! The order one pass or delta visits AUTHORITY_LOG rows in.
//!
//! The replicated door holds a row whose signer no folded row admitted
//! (H72), so a pass that met a signer's rows before its enrollment would hold
//! them until the next pass. Authority rows therefore land first, each after
//! every row of the same pass it names as a parent: an enrollment is an
//! ancestor of every valid row its key signs.

use std::collections::{BTreeMap, BTreeSet};

use crate::authority::{AuthorityEntryHash, authority_entry_hash, decode_authority_log_entry_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;

/// Whether an entities-map value carries an AUTHORITY_LOG row.
pub(in crate::sync) fn is_authority_row(blob: &[u8]) -> bool {
    EntityMetadataHeader::parse(blob)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_AUTHORITY_LOG)
}

/// Indices of `rows` (key, entity blob) parents first, ties by key. A row
/// whose body does not decode names no parent; its door refuses it.
pub(in crate::sync) fn authority_parent_order(rows: &[(&str, &[u8])]) -> Vec<usize> {
    let decoded: Vec<Option<(AuthorityEntryHash, BTreeSet<AuthorityEntryHash>)>> = rows
        .iter()
        .map(|(_, blob)| {
            let entry =
                decode_authority_log_entry_body(blob.get(ENTITY_METADATA_HEADER_LEN..)?).ok()?;
            let hash = authority_entry_hash(&entry).ok()?;
            Some((hash, entry.parent_hashes.into_iter().collect()))
        })
        .collect();
    let index: BTreeMap<_, _> = decoded
        .iter()
        .enumerate()
        .filter_map(|(at, row)| row.as_ref().map(|(hash, _)| (*hash, at)))
        .collect();
    let mut waiting = vec![0_usize; rows.len()];
    let mut children = vec![Vec::new(); rows.len()];
    for (at, row) in decoded.iter().enumerate() {
        let Some((_, parents)) = row else { continue };
        for parent in parents.iter().filter_map(|parent| index.get(parent)) {
            waiting[at] += 1;
            children[*parent].push(at);
        }
    }
    let mut ready: BTreeSet<(&str, usize)> = (0..rows.len())
        .filter(|at| waiting[*at] == 0)
        .map(|at| (rows[at].0, at))
        .collect();
    let mut order = Vec::with_capacity(rows.len());
    while let Some((_, at)) = ready.pop_first() {
        order.push(at);
        for child in &children[at] {
            waiting[*child] -= 1;
            if waiting[*child] == 0 {
                ready.insert((rows[*child].0, *child));
            }
        }
    }
    // Content addressing leaves no cycle; this only guards the invariant.
    if order.len() < rows.len() {
        let placed: BTreeSet<_> = order.iter().copied().collect();
        let mut rest: Vec<_> = (0..rows.len()).filter(|at| !placed.contains(at)).collect();
        rest.sort_by_key(|at| rows[*at].0);
        order.extend(rest);
    }
    order
}
