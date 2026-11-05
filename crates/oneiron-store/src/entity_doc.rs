//! Store-layer modules of core `entity_doc`; core re-exports each one at its old path.

pub mod document_resources;
pub mod recovery;
pub mod side_keys;
#[cfg(feature = "sync")]
pub mod sync;
