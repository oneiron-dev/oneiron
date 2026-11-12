//! Moved from `crates/oneiron/src/critic.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::critic_lens::CRITIC_LENS_CATALOG_SCHEMA_VERSION;
pub use oneiron_store::critic_lens::CriticLens;
pub use oneiron_store::critic_lens::LensCatalog;
pub use oneiron_store::critic_lens::OF366_SEED_LENS_CATALOG_JSON;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CritiqueVerdict {
    Accept,
    Revise,
    Discard,
}
pub mod review;
