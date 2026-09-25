//! Vault-as-origin serving plane (ARCH-0068 Phase A).
//!
//! Downstream surfaces — object storage serving, publication gating, change
//! index, conflict trees, residence — nest here as their own files land. This
//! root predeclares none of them: each downstream change adds its own single
//! additive `pub mod ...;` line when its file exists.

mod document_ingress;
pub use document_ingress::ReceivedFileOperation;
pub mod lfs;
pub mod publication;
pub mod smart_http;

pub mod change_index;
pub mod conflict_tree;
pub mod export;
pub mod residence;
pub mod tree;
