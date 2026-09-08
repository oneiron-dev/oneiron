//! Snapshot/export row, consent, and artifact domain types with pinned key and schema consts.

use std::collections::BTreeSet;

use super::codec::{invalid_snapshot, validate_fingerprint_hex, validate_row_id_list};
use crate::claim::ScopedReadActorKey;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Schema version string carried by every persona snapshot compile stamp.
///
/// The stamp identity (`{schema_version}:{compiled_fingerprint}`) matches the
/// `persona_compile_stamp` value format of the OF-369/RS9 context receipt
/// field-set, so persona-card export receipts and emit receipts read
/// uniformly.
pub const PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION: &str =
    "oneiron.persona_snapshot_compile.v1";

/// Schema marker carried by the MemoryPack-lite JSON render.
pub const MEMORY_PACK_LITE_SCHEMA_VERSION: &str = "oneiron.memory_pack_lite.v1";

/// Current PERSONA_SNAPSHOT_EXPORT record body schema version.
pub const PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for PERSONA_SNAPSHOT_EXPORT bodies.
pub const PERSONA_SNAPSHOT_EXPORT_BODY_KEYS: [&str; 14] = [
    "schemaVersion",
    "subjectRef",
    "audienceRef",
    "identityLine",
    "compiledAtSecs",
    "staleAfterSecs",
    "compiledFingerprint",
    "takesIncluded",
    "grantedBy",
    "grantedAtSecs",
    "exportedAtSecs",
    "includedRowIds",
    "struckRowIds",
    "artifactFingerprint",
];

/// Minimal projection: enough to answer "what was exported and when?".
pub(crate) const PERSONA_SNAPSHOT_EXPORT_FIELDS_MINIMAL: &[&str] =
    &["subjectRef", "exportedAtSecs"];

/// Standard projection: the export spine without the row-id lists.
pub(crate) const PERSONA_SNAPSHOT_EXPORT_FIELDS_STANDARD: &[&str] = &[
    "subjectRef",
    "audienceRef",
    "identityLine",
    "compiledAtSecs",
    "staleAfterSecs",
    "grantedBy",
    "exportedAtSecs",
];

/// Full projection: every pinned body key.
pub(crate) const PERSONA_SNAPSHOT_EXPORT_FIELDS_FULL: &[&str] = &PERSONA_SNAPSHOT_EXPORT_BODY_KEYS;

/// Default cap on top-salience subject claim rows in a compile.
pub const DEFAULT_PERSONA_SNAPSHOT_MAX_CLAIM_ROWS: usize = 12;

/// Default per-relationship cap on default-struck third-party claim rows.
pub const DEFAULT_PERSONA_SNAPSHOT_MAX_THIRD_PARTY_ROWS: usize = 4;

/// Default stale_after hint (30 days). Consuming agents distrust old copies;
/// this is a freshness HINT on the artifact, not an enforcement TTL.
pub const DEFAULT_PERSONA_SNAPSHOT_STALE_AFTER_SECS: u64 = 30 * 86_400;

/// Predicate mined for the identity line's display name.
pub const PERSONA_SNAPSHOT_NAME_PREDICATE: &str = "profile.name";

/// Predicate mined for the identity line's role.
pub const PERSONA_SNAPSHOT_ROLE_PREDICATE: &str = "profile.role";

/// Sensitivity band at or above which a claim is Tier A for disclosure
/// (OF-365): restricted-band claims never enter a compile. A claim whose
/// band cannot be resolved unambiguously also never enters (fail closed).
pub(super) const TIER_A_MIN_SENSITIVITY_BAND: u8 = 3;

pub(super) const ROW_ID_PREFIX: &str = "row:";

pub(super) const ROW_ID_HASH_CHARS: usize = 16;

const MAX_IDENTITY_LINE_BYTES: usize = 2_048;

pub(super) const FINGERPRINT_HEX_LEN: usize = 64;

/// Identity line persisted on the export record when the owner struck the
/// identity row: the export record is a queryable row, so struck name/role
/// text must not survive in it either.
pub const STRUCK_IDENTITY_LINE_PLACEHOLDER: &str = "(identity struck)";

pub(super) const KEY_SCHEMA_VERSION: &str = "schemaVersion";

pub(super) const KEY_SUBJECT_REF: &str = "subjectRef";

pub(super) const KEY_AUDIENCE_REF: &str = "audienceRef";

pub(super) const KEY_IDENTITY_LINE: &str = "identityLine";

pub(super) const KEY_COMPILED_AT_SECS: &str = "compiledAtSecs";

pub(super) const KEY_STALE_AFTER_SECS: &str = "staleAfterSecs";

pub(super) const KEY_COMPILED_FINGERPRINT: &str = "compiledFingerprint";

pub(super) const KEY_TAKES_INCLUDED: &str = "takesIncluded";

pub(super) const KEY_GRANTED_BY: &str = "grantedBy";

pub(super) const KEY_GRANTED_AT_SECS: &str = "grantedAtSecs";

pub(super) const KEY_EXPORTED_AT_SECS: &str = "exportedAtSecs";

pub(super) const KEY_INCLUDED_ROW_IDS: &str = "includedRowIds";

pub(super) const KEY_STRUCK_ROW_IDS: &str = "struckRowIds";

pub(super) const KEY_ARTIFACT_FINGERPRINT: &str = "artifactFingerprint";

/// Row kind on a compiled persona snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq)]
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

/// An actor-attributed agent take supplied to a compile (OF-330 aside).
///
/// The persona snapshot CONSUMES takes; it does not define where they are
/// stored. Callers hand the takes in; the per-card toggle
/// ([`PersonaSnapshotCompileOptions::include_agent_takes`]) gates whether
/// they enter the row list at all.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonaSnapshotAgentTake {
    /// Authoring actor ref; rendered as the attribution, never blank.
    pub actor_ref: String,
    /// The take text.
    pub text: String,
    /// Optional entity the take is about; defaults to the card subject.
    pub about_ref: Option<EntityId>,
}

/// Options for [`crate::Vault::compile_persona_snapshot`].
#[derive(Debug, Clone)]
pub struct PersonaSnapshotCompileOptions {
    /// When the card is FOR someone, their scoped-read actor key; claims
    /// outside the audience's per-contact read scope never enter the
    /// compile (absence is the boundary, not prompt-side withholding).
    pub audience: Option<ScopedReadActorKey>,
    /// Per-card agent-takes toggle; OFF by default. When off, supplied
    /// takes are not consulted at all.
    pub include_agent_takes: bool,
    /// Agent takes offered to this card; only read when
    /// `include_agent_takes` is true.
    pub agent_takes: Vec<PersonaSnapshotAgentTake>,
    /// Cap on top-salience subject claim rows.
    pub max_claim_rows: usize,
    /// Per-relationship cap on default-struck third-party claim rows.
    pub max_third_party_rows: usize,
    /// Relative stale_after freshness hint carried by the artifact.
    pub stale_after_secs: u64,
}

impl Default for PersonaSnapshotCompileOptions {
    fn default() -> Self {
        Self {
            audience: None,
            include_agent_takes: false,
            agent_takes: Vec::new(),
            max_claim_rows: DEFAULT_PERSONA_SNAPSHOT_MAX_CLAIM_ROWS,
            max_third_party_rows: DEFAULT_PERSONA_SNAPSHOT_MAX_THIRD_PARTY_ROWS,
            stale_after_secs: DEFAULT_PERSONA_SNAPSHOT_STALE_AFTER_SECS,
        }
    }
}

/// Compile stamp minted for every persona snapshot compile.
///
/// The fingerprint is content-addressed over the compiled rows (not the
/// compile time), so an unchanged recompile keeps the same identity and
/// previously granted export consent stays valid — mirroring the
/// `GateConsentBinding` content-addressing law.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq)]
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
}

/// Strike decisions applied at export over a compile's row list.
///
/// The effective struck set is `(default-struck ∪ strike) − unstrike`;
/// un-striking is the explicit consent step that lets a default-struck
/// third-party row enter the artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersonaSnapshotStrikeList {
    /// Row ids struck at preview.
    pub strike: BTreeSet<String>,
    /// Row ids explicitly un-struck at preview.
    pub unstrike: BTreeSet<String>,
}

/// Owner consent presented to an export, content-addressed to the compile
/// stamp it approves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaSnapshotExportConsent {
    /// Consenting actor ref (the owner side of the preview).
    pub granted_by: String,
    /// Stamp identity of the previewed compile this consent approves.
    pub compile_stamp: String,
    /// Consent wall-clock time (Unix seconds).
    pub granted_at_secs: u64,
}

/// The exported persona snapshot artifact: both renders from one compile.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonaSnapshotArtifact {
    /// Entity id of the persisted export record.
    pub export_id: EntityId,
    /// The card's subject.
    pub subject_ref: EntityId,
    /// MemoryPack-lite JSON render (agent consumers).
    pub memory_pack_json: String,
    /// Human markdown card render.
    pub markdown: String,
    /// Compile wall-clock time carried by both renders.
    pub compiled_at_secs: u64,
    /// Relative stale_after freshness hint carried by both renders.
    pub stale_after_secs: u64,
    /// The persona compile stamp.
    pub stamp: PersonaSnapshotCompileStamp,
    /// Row ids included in the artifact, in render order.
    pub included_row_ids: Vec<String>,
    /// Row ids struck out of the artifact.
    pub struck_row_ids: Vec<String>,
}

/// Persisted PERSONA_SNAPSHOT_EXPORT record body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaSnapshotExportRecord {
    /// The card's subject.
    pub subject_ref: EntityId,
    /// Audience actor ref when the card was compiled FOR someone.
    pub audience_ref: Option<String>,
    /// The compiled identity line.
    pub identity_line: String,
    /// Compile wall-clock time (Unix seconds).
    pub compiled_at_secs: u64,
    /// Relative stale_after freshness hint.
    pub stale_after_secs: u64,
    /// blake3 hex fingerprint of the compiled content.
    pub compiled_fingerprint: String,
    /// Whether agent takes were toggled into the card.
    pub takes_included: bool,
    /// Consenting actor ref.
    pub granted_by: String,
    /// Consent wall-clock time (Unix seconds).
    pub granted_at_secs: u64,
    /// Export wall-clock time (Unix seconds).
    pub exported_at_secs: u64,
    /// Row ids included in the artifact.
    pub included_row_ids: Vec<String>,
    /// Row ids struck out of the artifact.
    pub struck_row_ids: Vec<String>,
    /// blake3 hex fingerprint over both renders.
    pub artifact_fingerprint: String,
}

impl PersonaSnapshotExportRecord {
    /// Returns the RCPT-7 `persona_compile_stamp` value for this export.
    #[must_use]
    pub fn compile_stamp_identity(&self) -> String {
        format!(
            "{PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION}:{}",
            self.compiled_fingerprint
        )
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.identity_line.is_empty() || self.identity_line.len() > MAX_IDENTITY_LINE_BYTES {
            return Err(invalid_snapshot(
                "identityLine must be non-empty and at most 2048 bytes",
            ));
        }
        validate_fingerprint_hex(&self.compiled_fingerprint)?;
        validate_fingerprint_hex(&self.artifact_fingerprint)?;
        if self.granted_by.trim().is_empty() {
            return Err(invalid_snapshot("grantedBy must be non-empty"));
        }
        if let Some(audience_ref) = self.audience_ref.as_deref()
            && audience_ref.trim().is_empty()
        {
            return Err(invalid_snapshot("audienceRef must be non-empty when set"));
        }
        validate_row_id_list(&self.included_row_ids, "includedRowIds")?;
        validate_row_id_list(&self.struck_row_ids, "struckRowIds")?;
        let struck: BTreeSet<&str> = self.struck_row_ids.iter().map(String::as_str).collect();
        if self
            .included_row_ids
            .iter()
            .any(|row_id| struck.contains(row_id.as_str()))
        {
            return Err(invalid_snapshot(
                "includedRowIds and struckRowIds must be disjoint",
            ));
        }
        Ok(())
    }
}
