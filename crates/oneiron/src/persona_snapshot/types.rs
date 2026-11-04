//! Snapshot/export row, consent, and artifact domain types with pinned key and schema consts.

use std::collections::BTreeSet;

use crate::claim::ScopedReadActorKey;
use crate::entity_id::EntityId;

pub use crate::store::persona_snapshot_record::PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION;

/// Schema marker carried by the MemoryPack-lite JSON render.
pub const MEMORY_PACK_LITE_SCHEMA_VERSION: &str = "oneiron.memory_pack_lite.v1";

pub use crate::store::persona_snapshot_record::{PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION, PERSONA_SNAPSHOT_EXPORT_BODY_KEYS};

pub(crate) use crate::serialize::persona_export_fields::{
    PERSONA_SNAPSHOT_EXPORT_FIELDS_FULL, PERSONA_SNAPSHOT_EXPORT_FIELDS_MINIMAL,
    PERSONA_SNAPSHOT_EXPORT_FIELDS_STANDARD,
};

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

pub(super) use crate::store::persona_snapshot_record::FINGERPRINT_HEX_LEN;

/// Identity line persisted on the export record when the owner struck the
/// identity row: the export record is a queryable row, so struck name/role
/// text must not survive in it either.
pub const STRUCK_IDENTITY_LINE_PLACEHOLDER: &str = "(identity struck)";

pub(super) use crate::store::persona_snapshot_record::{KEY_SCHEMA_VERSION, KEY_SUBJECT_REF, KEY_AUDIENCE_REF, KEY_IDENTITY_LINE, KEY_COMPILED_AT_SECS, KEY_STALE_AFTER_SECS, KEY_COMPILED_FINGERPRINT, KEY_TAKES_INCLUDED, KEY_GRANTED_BY, KEY_GRANTED_AT_SECS, KEY_EXPORTED_AT_SECS, KEY_INCLUDED_ROW_IDS, KEY_STRUCK_ROW_IDS, KEY_ARTIFACT_FINGERPRINT, KEY_OMITTED_REFS};

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
    /// Where the card's rows go. Off this device no claim a world withholds
    /// from one of its machines enters the compile (DEC-0005, mesh PR2b).
    pub destination: crate::settings::ReadDestination,
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
            destination: crate::settings::ReadDestination::on_device(),
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
    pub read_receipt: Option<crate::claim::ScopedReadReceipt>,
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
    /// blake3 hex fingerprint over both renders, as the export record keeps
    /// it: the MemoryPack-lite JSON, a NUL byte, then the markdown.
    pub artifact_fingerprint: String,
    /// The vault ref slots both renders left out, as the export record names
    /// them (FIX 1199); empty for a copy that carries its refs.
    pub omitted_refs: Vec<String>,
}

pub use crate::store::persona_snapshot_record::PersonaSnapshotExportRecord;
