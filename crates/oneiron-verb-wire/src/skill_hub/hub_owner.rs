//! Moved from `crates/oneiron/src/skill_hub/hub_owner.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::skill_source::hub_record::HubRef;

/// Explicit owner selection. Provider version/tag strings are download locators;
/// only the separate expected fields assert the caller's desired identity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClawHubImportRequest {
    pub hub: EntityId,
    pub slug: String,
    pub version: Option<String>,
    pub tag: Option<String>,
    pub publisher: String,
    pub expected_skill_id: Option<String>,
    pub expected_skill_version: Option<String>,
    /// Native SHA-256 canonical-tree hex, not a provider or archive hash.
    pub expected_content_hash: Option<String>,
    /// The initial HTTP response budget; native expanded-tree bounds still apply.
    pub response_limit_bytes: Option<usize>,
}

/// A source pin records the actual imported tree. Without an explicit expected
/// native hash it is first-observed identity, not a previously reviewed pin.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ClawHubImportReply {
    Imported {
        entity: EntityId,
        source: HubRef,
        github_handoff: Option<super::ClawHubGitHubHandoff>,
    },
    ProviderError {
        status: u16,
        retry_after: Option<String>,
        body: String,
    },
}
