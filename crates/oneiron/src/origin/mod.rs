//! Vault-as-origin serving plane (ARCH-0068 Phase A).
//!
//! Downstream surfaces — object storage serving, publication gating, change
//! index, conflict trees, residence — nest here as their own files land. This
//! root predeclares none of them: each downstream change adds its own single
//! additive `pub mod ...;` line when its file exists.

pub(crate) mod actor_erase;
mod document_ingress;
pub use document_ingress::ReceivedFileOperation;
pub(crate) use document_ingress::erase_code_operations_actor_in_txn;
pub mod lfs;
pub mod publication;
pub mod smart_http;

pub mod change_index;
pub mod conflict_tree;
pub mod export;
pub mod mirror;
pub mod mirror_auto;
mod mirror_census;
mod mirror_run;
mod mirror_status;
pub mod mirror_strategy;
mod mirror_wake;
pub(crate) use mirror_wake::OriginMirrorWake;
pub mod publish;
pub mod registration;
pub mod residence;
pub mod secret_manifest;
pub mod tree;
