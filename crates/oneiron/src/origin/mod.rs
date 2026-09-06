//! Vault-as-origin serving plane (ARCH-0068 Phase A).
//!
//! Downstream surfaces — object storage serving, publication gating, change
//! index, conflict trees, residence — nest here as their own files land. This
//! root predeclares none of them: each downstream change adds its own single
//! additive `pub mod ...;` line when its file exists.

pub mod smart_http;
pub mod lfs;
pub mod publication;
