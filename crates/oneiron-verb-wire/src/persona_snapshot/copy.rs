//! Moved from `crates/oneiron/src/persona_snapshot/copy.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::share_travel::copy::CopyTravelChoice;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Replaces only one accepted row's text. Its sources and attribution stay intact.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonaSnapshotTextEdit {
    pub row_id: String,
    pub text: String,
}

/// Consent to issue exactly the previewed version, with explicit row exclusions.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonaSnapshotCopyRequest {
    pub subject: EntityId,
    pub stamp: String,
    #[serde(default)]
    pub strike: BTreeSet<String>,
    #[serde(default)]
    pub unstrike: BTreeSet<String>,
    /// Whether the copy carries its vault refs; absent is today's copy.
    #[serde(default)]
    pub travel: Option<CopyTravelChoice>,
}

/// An accepted copy's stamp fences its edits. Each edit issues a new immutable
/// export; an already handed copy and the neutral source claims remain unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonaSnapshotCopyEditRequest {
    pub export_id: EntityId,
    pub stamp: String,
    pub edits: Vec<PersonaSnapshotTextEdit>,
    #[serde(default)]
    pub strike: BTreeSet<String>,
    #[serde(default)]
    pub unstrike: BTreeSet<String>,
    /// Whether the new copy carries its vault refs; absent is today's copy.
    #[serde(default)]
    pub travel: Option<CopyTravelChoice>,
}
