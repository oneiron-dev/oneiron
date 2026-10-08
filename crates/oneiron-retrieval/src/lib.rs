//! Retrieval kernels of the oneiron engine: the multilingual analyzer, cosine distance and
//! score fusion. Depends only on `oneiron-contracts`. `oneiron` re-exports every module here at its old
//! `oneiron::<module>` path; applications depend on `oneiron`, not on this crate.

pub mod analyzer;
pub mod distance;
pub mod fusion;
pub mod pipeline;
