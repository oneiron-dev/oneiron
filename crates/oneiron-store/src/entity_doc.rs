//! Store-layer modules of core `entity_doc`; core re-exports each one at its old path.

pub mod checkpoint;
pub mod commit_receipts;
pub mod document;
pub mod document_resources;
pub mod recovery;
pub mod review_explainer;
pub mod side_keys;
#[cfg(feature = "sync")]
pub mod sync;
