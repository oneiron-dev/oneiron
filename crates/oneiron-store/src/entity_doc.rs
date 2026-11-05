//! Store-layer modules of core `entity_doc`; core re-exports each one at its old path.

pub mod checkpoint;
pub mod citation_floor;
pub mod commit_receipts;
pub mod document;
pub mod document_resources;
pub mod proposal_lineage;
pub mod prose_admission;
pub mod recovery;
pub mod review_explainer;
pub mod side_keys;
#[cfg(feature = "sync")]
pub mod sync;
pub mod token_uses;
