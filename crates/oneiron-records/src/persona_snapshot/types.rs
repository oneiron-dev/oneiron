//! Moved from `crates/oneiron/src/persona_snapshot/types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::persona_snapshot_record::PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION;
pub use oneiron_store::persona_snapshot_record::PERSONA_SNAPSHOT_EXPORT_BODY_KEYS;
pub use oneiron_store::persona_snapshot_record::PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION;
pub use oneiron_store::persona_snapshot_record::PersonaSnapshotExportRecord;
use std::collections::BTreeSet;

/// Row kind on a compiled persona snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PersonaSnapshotRowKind {
    /// The identity line row.
    Identity,
    /// A coarse key-relationship row (name + role).
    Relationship,
    /// A top-salience claim about the card's subject.
    SubjectClaim,
    /// A claim about a third party; default-struck, enters only via
    /// explicit un-strike at preview.
    ThirdPartyClaim,
    /// An actor-attributed agent take (OF-330 aside).
    AgentTake,
}

impl PersonaSnapshotRowKind {
    /// Returns the stable render string for this row kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Relationship => "relationship",
            Self::SubjectClaim => "subject_claim",
            Self::ThirdPartyClaim => "third_party_claim",
            Self::AgentTake => "agent_take",
        }
    }
}

/// One strikeable row of a compiled persona snapshot.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PersonaSnapshotRow {
    /// Content-derived stable row id (strike-list handle).
    pub row_id: String,
    /// Row kind.
    pub kind: PersonaSnapshotRowKind,
    /// Rendered row text (coarse name + role for relationship rows).
    pub text: String,
    /// Entity this row is about.
    pub subject_ref: EntityId,
    /// Salience of the backing claim, when the row is claim-backed.
    pub salience: Option<f32>,
    /// Provenance refs backing this row (`claim:`/`companion:`/`take:`).
    pub provenance_refs: Vec<String>,
    /// Authoring actor ref; always present on agent-take rows.
    pub attribution: Option<String>,
    /// Default strike state at preview (struck rows are absent from the
    /// export unless explicitly un-struck).
    pub struck: bool,
}

/// Compile stamp minted for every persona snapshot compile.
///
/// The fingerprint is content-addressed over the compiled rows (not the
/// compile time), so an unchanged recompile keeps the same identity and
/// previously granted export consent stays valid — mirroring the
/// `GateConsentBinding` content-addressing law.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersonaSnapshotCompileStamp {
    /// Stamp schema version.
    pub schema_version: String,
    /// The card's subject.
    pub subject_ref: EntityId,
    /// Compile wall-clock time (Unix seconds).
    pub compiled_at_secs: u64,
    /// blake3 hex fingerprint over the canonical compiled content.
    pub compiled_fingerprint: String,
}

impl PersonaSnapshotCompileStamp {
    /// Returns the stamp identity in the RCPT-7 `persona_compile_stamp`
    /// value format: `{schema_version}:{fingerprint}`.
    #[must_use]
    pub fn identity(&self) -> String {
        format!("{}:{}", self.schema_version, self.compiled_fingerprint)
    }
}

/// A compiled persona snapshot: the strikeable preview row list plus the
/// compile stamp. This is the consent surface's input; export applies the
/// owner's strike decisions over exactly this compile.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PersonaSnapshotCompile {
    /// The card's subject.
    pub subject_ref: EntityId,
    /// The compiled identity line.
    pub identity_line: String,
    /// Strikeable rows in render order.
    pub rows: Vec<PersonaSnapshotRow>,
    /// Audience actor ref when the card is FOR someone.
    pub audience_ref: Option<String>,
    /// Whether agent takes were toggled into this card.
    pub takes_included: bool,
    /// Compile wall-clock time (Unix seconds).
    pub compiled_at_secs: u64,
    /// Relative stale_after freshness hint.
    pub stale_after_secs: u64,
    /// The persona compile stamp.
    pub stamp: PersonaSnapshotCompileStamp,
    /// The audience's folded read of every candidate claim, when the card is
    /// FOR someone. Claims the audience may not read are counted here.
    pub read_receipt: Option<oneiron_contracts::claim::ScopedReadReceipt>,
    /// The claims the relationship rows' labels read (FIX 6080): each related
    /// person's name claim, and their role claim where the relationship
    /// record names no role. Outside the compile fingerprint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub label_claims: Vec<EntityId>,
}

/// Strike decisions applied at export over a compile's row list.
///
/// The effective struck set is `(default-struck ∪ strike) − unstrike`;
/// un-striking is the explicit consent step that lets a default-struck
/// third-party row enter the artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersonaSnapshotStrikeList {
    /// Row ids struck at preview.
    pub strike: BTreeSet<String>,
    /// Row ids explicitly un-struck at preview.
    pub unstrike: BTreeSet<String>,
}
