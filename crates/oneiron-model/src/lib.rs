//! Model seam of the oneiron engine: the LLM request, response, streaming, usage, error and
//! catalog types, the backend trait, the per-attempt budget guard that issues the leases a
//! backend call carries, and extraction evaluation. Depends only on `oneiron-contracts`.
//! `oneiron` re-exports every module here at its old `oneiron::<module>` path; applications
//! depend on `oneiron`, not on this crate.

pub mod extraction_eval;
pub mod llm;
