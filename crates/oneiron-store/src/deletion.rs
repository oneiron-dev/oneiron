//! Store-layer modules of core `deletion`; core re-exports each one at its old path.

pub mod archive_role;
pub mod coop_delivery;
pub mod delete;
#[cfg(feature = "sync")]
pub mod delete_bearing_update;
pub mod receipt;
#[cfg(feature = "sync")]
pub mod window_document_format;
