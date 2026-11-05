//! Native ordering of the two actual selected settlement sources.

use loro::CommitOptions;

use super::super::EntityDoc;
use super::inspect::NativeMapInventory;
use super::register::{CURRENT, ROOT, read_fact};
use crate::error::{Error, Result};

/// Called only by the fixed authorized fork-settlement producer with its own
/// two source inventories. These inventories alone grant no native admission.
/// A floor or hidden historical insert is never another selected candidate.
pub(in crate::entity_doc) fn reconcile_settlement(
    document: &EntityDoc,
    source: &NativeMapInventory,
    fork: &NativeMapInventory,
) -> Result<()> {
    let (Some(source), Some(fork)) = (&source.current, &fork.current) else {
        // Absence has no signed native order. Preserve the original join's
        // selected value, including None, rather than searching its history.
        return Ok(());
    };
    let selected = if source.order()? >= fork.order()? {
        source
    } else {
        fork
    };
    if read_fact(document)?.as_ref() == Some(selected) {
        return Ok(());
    }
    document
        .doc
        .get_map(ROOT)
        .insert(CURRENT, selected.encode()?.as_slice())
        .map_err(|_| Error::CorruptedIndex("native SKILL state settlement register"))?;
    document
        .doc
        .commit_with(CommitOptions::new().commit_msg(super::ANONYMOUS_COMMIT));
    Ok(())
}
