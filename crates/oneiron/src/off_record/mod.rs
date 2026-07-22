//! Off-record session lifecycle and promotion surfaces.

mod lifecycle;
mod promote;

pub use lifecycle::{
    OffRecordBackendClass, OffRecordCloseOutcome, OffRecordMode, OffRecordSession,
    OffRecordSessionRecord, OffRecordSessionVault,
};
pub use promote::OffRecordPromoteReceipt;

pub(crate) use lifecycle::{
    FloorWrites, OffRecordSessionRegistry, guard_off_record_entity_put, off_record_fence_active,
    off_record_fences_present,
};
