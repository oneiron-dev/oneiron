//! Moved from `crates/oneiron/src/critic.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::claim::ClaimLifecycleStatus;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
pub use oneiron_store::critic_lens::CRITIC_LENS_CATALOG_SCHEMA_VERSION;
pub use oneiron_store::critic_lens::CriticLens;
pub use oneiron_store::critic_lens::LensCatalog;
use oneiron_store::critic_lens::MAX_CONTRACT_BYTES;
use oneiron_store::critic_lens::MAX_DOMAIN_BYTES;
use oneiron_store::critic_lens::MAX_ID_BYTES;
use oneiron_store::critic_lens::MAX_OUTPUT_SCHEMA_BYTES;
pub use oneiron_store::critic_lens::OF366_SEED_LENS_CATALOG_JSON;
use oneiron_store::critic_lens::invalid_critic_config;
use oneiron_store::critic_lens::validate_catalog;
use oneiron_store::critic_lens::validate_identifier;
use oneiron_store::critic_lens::validate_lens;
use oneiron_store::side_table::key::SideKey;
use oneiron_store::write_envelope::WriteActor;
use oneiron_store::write_envelope::claim_body::ClaimBody;
use oneiron_store::write_envelope::claim_body::ClaimSubject;
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
