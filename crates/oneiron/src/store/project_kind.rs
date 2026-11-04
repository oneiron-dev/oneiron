//! The run-time kind lookups for PROJECT and its revision companion: the pack
//! and short-id prefixes they are registered under, read from the store's
//! in-memory structural kind registrations. `workspace_roster::project`
//! re-exports each item at its old path.

use crate::store::Store;

/// The short-id prefix PROJECT is registered under at run time.
pub(crate) const PROJECT_SHORT_ID_PREFIX: &str = "pj";
/// The pack PROJECT is registered under at run time.
pub(crate) const PROJECT_PACK: &str = "oneiron.project";
const PACK: &str = PROJECT_PACK;

/// The short-id prefix the revision kind is registered under at run time,
/// beside PROJECT in PROJECT's pack.
pub(crate) const PROJECT_REVISION_SHORT_ID_PREFIX: &str = "pv";

pub(crate) fn is_project_type(store: &crate::store::Store, kind: u8) -> bool {
    store
        .structural_kind_registration(kind)
        .is_some_and(|row| row.pack == PACK && row.short_id_prefix == PROJECT_SHORT_ID_PREFIX)
}

pub(crate) fn is_project_revision_type(store: &Store, kind: u8) -> bool {
    store.structural_kind_registration(kind).is_some_and(|row| {
        row.pack == PACK && row.short_id_prefix == PROJECT_REVISION_SHORT_ID_PREFIX
    })
}

pub(crate) fn project_revision_type(store: &Store) -> Option<u8> {
    store
        .structural_kind_registrations()
        .into_iter()
        .find(|row| row.pack == PACK && row.short_id_prefix == PROJECT_REVISION_SHORT_ID_PREFIX)
        .map(|row| row.type_byte)
}
