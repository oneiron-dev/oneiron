//! Moved from `crates/oneiron/src/memory/identity_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::ingest::resolution::EntityResolutionCandidate;
use crate::ingest::resolution::EntityResolutionWaterfallDecision;
use oneiron_base::registry::ENTITY_TYPE_ORG;
use oneiron_base::registry::ENTITY_TYPE_PERSON;
use oneiron_base::registry::ENTITY_TYPE_PLACE;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::write_envelope::provenance::made_by::MadeBy;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityKind {
    Person,
    Org,
    Place,
}

impl IdentityKind {
    fn type_byte(self) -> u8 {
        match self {
            Self::Person => ENTITY_TYPE_PERSON,
            Self::Org => ENTITY_TYPE_ORG,
            Self::Place => ENTITY_TYPE_PLACE,
        }
    }
}

/// The fields declared by `identity_fields_for_kind`, not an identity id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityHints {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub phonetic: Vec<String>,
    #[serde(default)]
    pub contact_handle: Vec<String>,
}

impl IdentityHints {
    fn terms(&self, kind: IdentityKind) -> MemoryResult<BTreeSet<String>> {
        if kind != IdentityKind::Person && !self.contact_handle.is_empty() {
            return Err(MemoryError::bad_request(
                "contact_handle is declared only for PERSON",
            ));
        }
        let terms: BTreeSet<_> = self
            .name
            .iter()
            .chain(&self.aliases)
            .chain(&self.phonetic)
            .chain(&self.contact_handle)
            .map(|term| term.trim().to_lowercase())
            .filter(|term| !term.is_empty())
            .collect();
        if terms.is_empty() {
            return Err(MemoryError::bad_request(
                "at least one declared identity hint is required",
            ));
        }
        Ok(terms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonCreateRequest {
    pub identity: IdentityHints,
    /// Existing contact, organisation, message or other evidence records.
    /// A name alone is not identity evidence.
    pub identity_evidence_refs: Vec<String>,
    pub occurred_at: u64,
    #[serde(default)]
    pub learned_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityLookupRequest {
    pub kind: IdentityKind,
    pub identity: IdentityHints,
    /// Already-produced provider.enrichment claims about index candidates.
    /// Omit these to read candidates without proposing any match.
    #[serde(default)]
    pub mention_evidence: Vec<EntityResolutionCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityConfidenceEvidence {
    pub claim_ref: String,
    pub effective_confidence: f32,
    pub source: Option<String>,
    pub evidence: Option<serde_json::Value>,
    pub made_by: Option<MadeBy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityLookupCandidate {
    pub entity_ref: String,
    pub matched_hints: Vec<String>,
    pub identity_evidence_refs: Vec<String>,
    pub identity_owner_ref: Option<String>,
    pub identity_recorded_at: Option<u64>,
    pub made_by: Option<MadeBy>,
    pub mention_evidence: Vec<IdentityConfidenceEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityLookup {
    pub kind: IdentityKind,
    pub candidates: Vec<IdentityLookupCandidate>,
    /// Scoring only: even a selected subject is not linked or restored by
    /// this query. No evidence means no selected subject.
    pub waterfall: EntityResolutionWaterfallDecision,
}
