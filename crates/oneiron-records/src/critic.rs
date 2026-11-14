//! Moved from `crates/oneiron/src/critic.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::critic::flaw::FlawIdentity;
pub use crate::critic::flaw::FlawLocation;
pub use crate::critic::review::dissent::CriticPrediction;
pub use oneiron_store::critic_lens::CRITIC_LENS_CATALOG_SCHEMA_VERSION;
pub use oneiron_store::critic_lens::CriticLens;
pub use oneiron_store::critic_lens::LensCatalog;
pub use oneiron_store::critic_lens::OF366_SEED_LENS_CATALOG_JSON;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

pub const CRITIQUE_ARTIFACT_SCHEMA_VERSION: u64 = 1;

pub const MAX_SUGGESTED_EDIT_BYTES: usize = 8192;

/// How an erased critic's ref begins (FIX 4477; a call): the erased spelling
/// and a colon, then an opaque id of its own that hashes no actor.
pub const ERASED_CRITIC_REF_PREFIX: &str = "erased:";

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct CritiqueTriageScores {
    pub accept: f64,
    pub revise: f64,
    pub discard: f64,
}
pub mod flaw;
pub mod review;
