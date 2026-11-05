//! Store-layer modules of core `deletion`; core re-exports each one at its old path.

pub mod archive_role;
pub mod delete;
#[cfg(feature = "sync")]
pub mod delete_bearing_update;
#[cfg(feature = "sync")]
pub mod window_document_format;
