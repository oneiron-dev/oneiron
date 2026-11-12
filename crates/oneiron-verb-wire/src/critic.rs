//! Moved from `crates/oneiron/src/critic.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::critic_lens::CRITIC_LENS_CATALOG_SCHEMA_VERSION;
pub use oneiron_store::critic_lens::CriticLens;
pub use oneiron_store::critic_lens::LensCatalog;
pub use oneiron_store::critic_lens::OF366_SEED_LENS_CATALOG_JSON;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CritiqueVerdict {
    Accept,
    Revise,
    Discard,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CritiqueSeverity {
    Info,
    Low,
    Medium,
    High,
    Blocking,
}

impl CritiqueSeverity {
    const fn score_multiplier(self) -> f64 {
        match self {
            Self::Info => 0.25,
            Self::Low => 0.5,
            Self::Medium => 1.0,
            Self::High => 1.5,
            Self::Blocking => 2.0,
        }
    }
}
pub mod review;
