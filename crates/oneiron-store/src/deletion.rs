//! Store-layer modules of core `deletion`; core re-exports each one at its old path.

pub mod archive_role;
pub mod coop_delivery;
pub mod coop_reply;
pub mod coop_request;
pub mod coop_succession;
pub mod delete;
#[cfg(feature = "sync")]
pub mod delete_bearing_update;
pub mod receipt;
pub mod sweep_queue;
#[cfg(feature = "sync")]
pub mod window_document_format;
