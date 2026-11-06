//! Vault-as-origin serving plane (ARCH-0068 Phase A).
//!
//! Downstream surfaces — object storage serving, publication gating, change
//! index, conflict trees, residence — nest here as their own files land. This
//! root predeclares none of them: each downstream change adds its own single
//! additive `pub mod ...;` line when its file exists.

pub(crate) mod actor_erase;
mod document_candidate_types;
mod document_candidates;
mod document_ingress;
pub use document_candidate_types::{
    CodePushCandidateState, CodePushCandidateView, ReceivedCandidateRef, ReceivedRefIngress,
    ReceivedRefSource,
};
pub(crate) use document_candidates::CandidateQueue;
pub use document_candidates::projected::{
    RepoProjectedCandidateFilePin, RepoProjectedCandidatePins,
};
pub use document_ingress::ReceivedFileOperation;
pub(crate) use document_ingress::erase_code_operations_actor_in_txn;
pub(crate) use oneiron_store::origin::git_ref_change;
pub use secret_projection::clearance::RepoProjectionHoldCause;
pub mod lfs;
pub mod publication;
pub mod smart_http;

pub mod change_index;
pub mod conflict_tree;
pub mod export;
mod export_input;
mod export_parent;
pub mod export_preview;
pub mod git_transport;
pub mod mirror;
pub mod mirror_auto;
mod mirror_census;
mod mirror_run;
mod mirror_status;
pub mod mirror_strategy;
mod mirror_wake;
pub(crate) use mirror_census::history_lfs_objects;
pub(crate) use mirror_wake::OriginMirrorWake;
pub mod publish;
pub(crate) use oneiron_store::origin::receive_scan_verdict;
pub mod registration;
mod repo_import;
pub(crate) use repo_import::{ImportedCodeRepo, ServedImportSource};
mod repo_manifest;
#[cfg(feature = "sync")]
pub(crate) use repo_manifest::RepoManifestMerge;
pub(crate) use repo_manifest::erase_repo_manifests_in_txn;
pub(crate) use repo_manifest::standing_portable_id_for_location_in_txn;
pub use repo_manifest::{REPO_MANIFEST_VERSION, RepoManifest, RepoManifestWriter, RepoPortableId};
pub mod residence;
pub mod secret_manifest;
pub(crate) mod secret_marks;
pub(crate) mod secret_projection;
pub mod secret_publication;
pub mod tree;
