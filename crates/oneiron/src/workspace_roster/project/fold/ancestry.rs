//! A project's ancestry decided from the root-most up (FIX 11122). A
//! project's decision reads each parent project's view, and that read
//! decided the parent where it stood, so a long ancestry once nested one
//! native fold per level; the settled lineage (`validity/settle.rs`) covers
//! one project's own revisions only. Before a parent's view is read, the
//! projects its parents tie it to that this reader has not decided are
//! found on the heap, one component of "names as parent" at a time
//! ([`ProjectReader::component`]), and decided parents first: each meets its
//! parents' decisions already kept, and the view asked for nests one fold
//! deep. Nothing else changes: a decision is the one the reader keeps
//! whichever read asks for it first, and a decision that fails ends the
//! settling, keeping nothing, so the read asked for meets that failure where
//! it always did. The projects a walk enters are counted against
//! [`EngineScan::ProjectAncestryRows`] for the project read; a crossing
//! raises a check and the walk reads on.
use super::*;
use crate::scan_check::{EngineScan, ScanCount};

/// Decides `id`'s undecided ancestry, each component once and parents
/// first, before `id`'s own decision is read.
pub(in super::super) fn settle_ancestry(reader: &ProjectReader<'_, '_>, id: EntityId) {
    if reader.has_decided(id) {
        return;
    }
    let Ok((entered, order)) = undecided_ancestry(reader, id) else {
        return;
    };
    count_rows(reader, id, entered);
    for member in order {
        if reader.decide(member).is_err() {
            break;
        }
    }
}

/// How many projects a walk from `id` enters, its own component's included,
/// and one member of each undecided ancestor component, parents first: a
/// depth-first walk that closes a component only after every component it
/// names as parent, and stops at a project already decided or not stored.
/// `id`'s own component, closed last, is left to the read that asked.
fn undecided_ancestry(
    reader: &ProjectReader<'_, '_>,
    id: EntityId,
) -> Result<(usize, Vec<EntityId>)> {
    let mut entered = BTreeSet::new();
    let mut order = Vec::new();
    let mut todo = vec![(id, false)];
    while let Some((at, parents_done)) = todo.pop() {
        if parents_done {
            order.push(at);
            continue;
        }
        if entered.contains(&at) || reader.has_decided(at) || reader.facts(at)?.is_none() {
            continue;
        }
        let members = reader.component(at)?;
        entered.extend(members.iter().copied());
        todo.push((at, true));
        let mut parents = BTreeSet::new();
        for member in members.iter() {
            if let Some(facts) = reader.facts(*member)? {
                parents.extend(facts.edges.iter().copied());
            }
        }
        // The lowest id first, as component discovery visits them.
        for parent in parents.into_iter().rev() {
            if !entered.contains(&parent) {
                todo.push((parent, false));
            }
        }
    }
    order.pop();
    Ok((entered.len(), order))
}

/// Counts the `rows` projects a walk from `id` entered.
fn count_rows(reader: &ProjectReader<'_, '_>, id: EntityId, rows: usize) {
    if rows == 0 {
        return;
    }
    let store = reader.store();
    let scope = [id.as_bytes().as_slice(), b"fold".as_slice()].concat();
    match ScanCount::start(store, reader.txn(), EngineScan::ProjectAncestryRows, &scope) {
        Ok(mut count) => {
            count.rows(rows);
            count.defer(store);
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "project ancestry was not counted");
        }
    }
}
