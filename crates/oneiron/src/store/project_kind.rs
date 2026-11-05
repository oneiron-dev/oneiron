//! Core half of `store::project_kind`: its store-layer items live in `oneiron_store::project_kind` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::project_kind::*;

use crate::store::Store;

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
