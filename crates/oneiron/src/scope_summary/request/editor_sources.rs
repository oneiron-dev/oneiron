//! The rows an edited summary's words were written from (FIX 10092). A
//! re-derivation sends the edited predecessor's text to the model, so every
//! row that text came from beyond the declaration's own records is read as
//! the Dreamer reads it and pinned at its version beside the evidence, and
//! the new summary keeps each one as a dependency: erasing or withholding
//! any of them reaches it and every reply that copies it.
use std::collections::BTreeSet;

use super::super::codec::invalid;
use super::super::derivation::SummarySourceVersion;
use crate::dreamer_consolidation::{ScopeSummaryEvidence, editor_source_pins_in_txn};
use crate::error::Result;
use crate::{EntityId, Vault};

/// Each dependency `previous` registered (its covers, its MESSAGEs and the
/// read refs of every edit made to it) that `evidence` does not already
/// read, pinned as the Dreamer reads it in `txn`. One that is gone or that
/// the Dreamer does not read refuses the plan, as a missing cover does.
pub(super) fn editor_sources_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    previous: &EntityId,
    evidence: &ScopeSummaryEvidence,
) -> Result<Vec<SummarySourceVersion>> {
    let read: BTreeSet<EntityId> = evidence
        .covers
        .iter()
        .copied()
        .chain(evidence.messages.iter().map(|message| message.id))
        .collect();
    let mut extra = crate::ports::dependency_sources_in(&vault.store, txn, previous)?;
    extra.retain(|source| !read.contains(source));
    extra.sort_unstable();
    extra.dedup();
    editor_source_pins_in_txn(vault, txn, &extra)?
        .ok_or_else(|| invalid("edited summary no longer has all its source evidence"))
}

/// Registers each of `evidence`'s editor sources as a dependency of
/// `summary`, in the writer that mints it.
pub(super) fn register_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    summary: &EntityId,
    evidence: &ScopeSummaryEvidence,
) -> Result<()> {
    for pin in &evidence.editor_sources {
        let source = EntityId::from_hex(&pin.id)?;
        crate::ports::record_derived_edge_in_txn(&vault.store, txn, summary, &source)?;
    }
    Ok(())
}
