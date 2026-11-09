//! The Dreamer wake contract below core (core split slice 3): wake triggers, requests and pass reports,
//! deadlines and cancellation, the sieve recipe records, and the attempt progress and park vocabulary.
//! `oneiron` re-exports every item at its old path.
#![deny(ambiguous_glob_reexports)]

pub mod attempt_queue;
pub mod dreamer_consolidation;
pub mod dreamer_runner;
pub mod dreamer_wake;
pub mod llm;
pub mod memory;
pub mod model_step_effect;
pub mod settings;
pub mod store;
