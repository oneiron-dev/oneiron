//! Doors for the owed export audit's integration tests (L5-17,
//! `tests/export_audit_owed_notice.rs`): one-shot faults on the calling
//! thread, and a read of the owed rows.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// Fails the next export audit write on this thread, once: the write that
/// writes a copy's audit row and its threads' notices, inline or in a
/// housekeeping pass.
pub fn fail_next_export_audit_write() {
    crate::memory::export_audit_faults::fail_next_audit_write();
}

/// Fails the next write of a copy's owed audit row on this thread, once.
pub fn fail_next_owed_export_audit_write() {
    crate::memory::export_audit_faults::fail_next_owed_row_write();
}

/// Every owed export audit row: each export id, with every person its
/// thread bindings name.
///
/// # Errors
///
/// Storage errors, or a row that does not decode.
pub fn owed_export_audits(vault: &Vault) -> Result<BTreeMap<EntityId, BTreeSet<EntityId>>> {
    crate::memory::owed_export_audits(vault)
}
