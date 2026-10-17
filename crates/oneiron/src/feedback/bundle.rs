//! Feedback bundle wire contract: bundle, config, and diagnosis types plus the MessagePack codec and digest.

use std::collections::BTreeSet;
use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::config::VaultConfig;
use crate::edge::EdgeKind;

use super::error::{FeedbackError, bounded, checked_embedding_model, checked_note, checked_token};

/// Stable encoding token for the v1 feedback bundle wire contract.
pub const FEEDBACK_BUNDLE_ENCODING: &str = "oneiron.feedback.bundle.v1";

/// Stable encoding token for a bundle that carries a proposal: the six v1
/// keys in v1 order, then `proposal`.
pub const FEEDBACK_BUNDLE_ENCODING_V2: &str = "oneiron.feedback.bundle.v2";

/// The single protocol verb of the feedback family.
pub const FEEDBACK_SEND_VERB: &str = "feedback.send";

/// Exact feedback verb family in protocol sort order.
pub const FEEDBACK_VERBS: [&str; 1] = [FEEDBACK_SEND_VERB];

/// Consent action id that authorizes exactly one feedback act.
pub const FEEDBACK_APPROVE_ONCE_ACTION: &str = "approve_once";

/// Maximum accepted `engine_version` length in bytes.
pub const FEEDBACK_ENGINE_VERSION_MAX_BYTES: usize = 64;

/// Maximum accepted `embedding_model` length in bytes.
pub const FEEDBACK_EMBEDDING_MODEL_MAX_BYTES: usize = 128;

/// Maximum accepted free-text note length in bytes.
pub const FEEDBACK_USER_NOTE_MAX_BYTES: usize = 4096;

/// Maximum accepted length of a proposal's problem or fix text in bytes.
pub const FEEDBACK_PROPOSAL_MAX_BYTES: usize = 4096;

/// Maximum accepted length of any single reference token in bytes.
pub const FEEDBACK_REF_MAX_BYTES: usize = 256;

/// Maximum number of hops carried by one healer diagnosis DAG.
pub const FEEDBACK_DAG_MAX_HOPS: usize = 64;

/// Maximum number of subject references carried by one healer diagnosis.
pub const FEEDBACK_MAX_SUBJECT_REFS: usize = 64;

/// Domain separator for the bundle digest preimage.
const FEEDBACK_DIGEST_DOMAIN: &[u8] = b"oneiron.feedback.bundle.v1\0";

/// Domain separator for the v2 bundle digest preimage.
const FEEDBACK_DIGEST_DOMAIN_V2: &[u8] = b"oneiron.feedback.bundle.v2\0";

/// The wire encoding a bundle's bytes were produced under.
///
/// A bundle with no proposal is v1, byte for byte what it always was; a bundle
/// with a proposal is v2. The token travels beside the bytes, never inside
/// them, so every reader names the encoding it expects and an unknown token is
/// refused before a byte is decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeedbackEncoding {
    /// [`FEEDBACK_BUNDLE_ENCODING`]: the six frozen keys.
    #[serde(rename = "oneiron.feedback.bundle.v1")]
    V1,
    /// [`FEEDBACK_BUNDLE_ENCODING_V2`]: the six frozen keys, then `proposal`.
    #[serde(rename = "oneiron.feedback.bundle.v2")]
    V2,
}

impl FeedbackEncoding {
    /// Stable encoding token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => FEEDBACK_BUNDLE_ENCODING,
            Self::V2 => FEEDBACK_BUNDLE_ENCODING_V2,
        }
    }

    /// Resolves an encoding token, refusing any token this engine cannot read.
    pub fn from_token(token: &str) -> Result<Self, FeedbackError> {
        match token {
            FEEDBACK_BUNDLE_ENCODING => Ok(Self::V1),
            FEEDBACK_BUNDLE_ENCODING_V2 => Ok(Self::V2),
            other => Err(FeedbackError::UnknownEncoding(other.to_owned())),
        }
    }

    const fn digest_domain(self) -> &'static [u8] {
        match self {
            Self::V1 => FEEDBACK_DIGEST_DOMAIN,
            Self::V2 => FEEDBACK_DIGEST_DOMAIN_V2,
        }
    }
}

/// The typed feedback verb family. One member by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackVerb {
    /// Send one approved feedback bundle to one approved destination.
    Send,
}

impl FeedbackVerb {
    /// All typed feedback verbs in protocol sort order.
    pub const ALL: [Self; 1] = [Self::Send];

    /// Stable protocol identifier for this typed verb.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Send => FEEDBACK_SEND_VERB,
        }
    }
}

/// What kind of feedback this bundle carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FeedbackCategory {
    /// Something is broken.
    Bug,
    /// Something works but hurts.
    Papercut,
    /// Something is unclear.
    Confusion,
    /// Something is missing.
    FeatureWish,
}

impl FeedbackCategory {
    /// All categories in wire order.
    pub const ALL: [Self; 4] = [
        Self::Bug,
        Self::Papercut,
        Self::Confusion,
        Self::FeatureWish,
    ];

    /// Stable wire token for this category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bug => "bug",
            Self::Papercut => "papercut",
            Self::Confusion => "confusion",
            Self::FeatureWish => "feature-wish",
        }
    }
}

/// Build-target facts. Derived only from compile-time target constants, so it
/// carries no hostname, no user name, and no device identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackPlatform {
    /// Target operating system token.
    pub os: String,
    /// Target architecture token.
    pub arch: String,
    /// Target family token.
    pub family: String,
}

impl FeedbackPlatform {
    /// The platform this binary was compiled for.
    #[must_use]
    pub fn current() -> Self {
        Self {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            family: std::env::consts::FAMILY.to_owned(),
        }
    }

    fn validate(&self) -> Result<(), FeedbackError> {
        checked_token("platform os", &self.os, FEEDBACK_REF_MAX_BYTES)?;
        checked_token("platform arch", &self.arch, FEEDBACK_REF_MAX_BYTES)?;
        checked_token("platform family", &self.family, FEEDBACK_REF_MAX_BYTES)
    }
}

/// Graph tuning knobs, projected verbatim from the vault configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackHnswSnapshot {
    /// Maximum neighbors per node in layer 0.
    pub m_max_0: usize,
    /// Beam width used during graph construction.
    pub ef_construction: usize,
    /// Beam width used during search.
    pub ef_search: usize,
}

/// Whitelist projection of the vault configuration.
///
/// Every field is named explicitly. Nothing is copied by reflection, by
/// wildcard, or by `Default`, so a configuration field added later is absent
/// from this snapshot until somebody deliberately adds it here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackConfigSnapshot {
    /// Embedding vector dimension.
    pub dimensions: usize,
    /// Fast-lane prefix length, when a funnel is configured.
    pub fast_dims: Option<u16>,
    /// Embedding model identifier, when the vault stamps one.
    pub embedding_model: Option<String>,
    /// Map size in bytes. Renamed from the configuration's `map_size` so the
    /// unit is unambiguous to a reader who never sees the engine source.
    pub map_size_bytes: usize,
    /// Maximum reader slots.
    pub max_readers: u32,
    /// Graph tuning knobs.
    pub hnsw: FeedbackHnswSnapshot,
    /// Whether the text-index manifest handshake is skipped at open.
    pub skip_text_index_manifest_check: bool,
    /// Whether off-record sessions may be entered.
    pub off_record_enabled: bool,
    /// Per-session off-record overlay byte budget.
    pub off_record_overlay_budget_bytes: usize,
}

impl FeedbackConfigSnapshot {
    /// Projects the whitelisted, non-secret subset of a vault configuration.
    ///
    /// Rejects an `embedding_model` that is blank, longer than
    /// [`FEEDBACK_EMBEDDING_MODEL_MAX_BYTES`], not already trimmed, contains
    /// any whitespace, or looks like a URL (`://`) — a model identifier that
    /// carries a location is a leak, not a version.
    pub fn from_config(config: &VaultConfig) -> Result<Self, FeedbackError> {
        let embedding_model = match config.embedding_model.as_deref() {
            None => None,
            Some(model) => Some(checked_embedding_model(model)?),
        };
        Ok(Self {
            dimensions: config.dimensions,
            fast_dims: config.fast_dims,
            embedding_model,
            map_size_bytes: config.map_size,
            max_readers: config.max_readers,
            hnsw: FeedbackHnswSnapshot {
                m_max_0: config.hnsw.m_max_0,
                ef_construction: config.hnsw.ef_construction,
                ef_search: config.hnsw.ef_search,
            },
            skip_text_index_manifest_check: config.skip_text_index_manifest_check,
            off_record_enabled: config.off_record_enabled,
            off_record_overlay_budget_bytes: config.off_record_overlay_budget_bytes,
        })
    }

    fn validate(&self) -> Result<(), FeedbackError> {
        if let Some(model) = self.embedding_model.as_deref() {
            checked_embedding_model(model)?;
        }
        Ok(())
    }
}

/// One edge of the healer's reasoning DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackDagHop {
    /// Reference the hop reasons from.
    pub from_ref: String,
    /// The edge kind the hop walks, by its canon snake_case name
    /// ([`EdgeKind::name`]). Any other word is refused: a relation is a closed
    /// vocabulary, so a healer cannot write row text into it.
    pub relation: String,
    /// Reference the hop reasons to.
    pub to_ref: String,
}

impl FeedbackDagHop {
    /// Builds one hop.
    #[must_use]
    pub fn new(from_ref: impl Into<String>, relation: EdgeKind, to_ref: impl Into<String>) -> Self {
        Self {
            from_ref: from_ref.into(),
            relation: relation.name().to_owned(),
            to_ref: to_ref.into(),
        }
    }

    fn validate(&self) -> Result<(), FeedbackError> {
        checked_token("dag hop from_ref", &self.from_ref, FEEDBACK_REF_MAX_BYTES)?;
        if EdgeKind::from_name(&self.relation).is_none() {
            return Err(FeedbackError::InvalidBundle(
                "dag hop relation must be an edge kind name".to_owned(),
            ));
        }
        checked_token("dag hop to_ref", &self.to_ref, FEEDBACK_REF_MAX_BYTES)
    }
}

/// What the self-healer concluded: references and an ordered reasoning DAG.
///
/// This is a summary, never a dump: references are opaque tokens and the DAG
/// is an ordered list of hops whose relations are edge kinds. It carries no
/// prose. A healer's own sentence
/// could quote the rows it reasoned over, and feedback never carries world
/// text the owner did not write (owner ruling 2026-10-14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackHealerDiagnosis {
    /// Reference to the diagnosis itself.
    pub diagnosis_ref: String,
    /// References the diagnosis is about. Unordered, so an ordered set.
    pub subject_refs: BTreeSet<String>,
    /// Ordered reasoning hops, first hop first.
    pub dag: Vec<FeedbackDagHop>,
}

impl FeedbackHealerDiagnosis {
    /// Builds a diagnosis with no subjects and no hops.
    #[must_use]
    pub fn new(diagnosis_ref: impl Into<String>) -> Self {
        Self {
            diagnosis_ref: diagnosis_ref.into(),
            subject_refs: BTreeSet::new(),
            dag: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), FeedbackError> {
        checked_token(
            "healer diagnosis_ref",
            &self.diagnosis_ref,
            FEEDBACK_REF_MAX_BYTES,
        )?;
        bounded(
            "healer subject_refs",
            self.subject_refs.len(),
            FEEDBACK_MAX_SUBJECT_REFS,
        )?;
        for subject in &self.subject_refs {
            checked_token("healer subject_ref", subject, FEEDBACK_REF_MAX_BYTES)?;
        }
        bounded("healer dag", self.dag.len(), FEEDBACK_DAG_MAX_HOPS)?;
        for hop in &self.dag {
            hop.validate()?;
        }
        Ok(())
    }
}

/// A suggested fix beside the problem it answers (ARCH-0056 #proposals).
///
/// A proposal is a kind of feedback, not a category: a bug, a papercut, a
/// confusion or a wish can each carry one. Both strings are shown to the owner
/// byte for byte on the approval card and leave only as approved, so a
/// proposal that quotes vault text has already asked the owner first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackProposal {
    /// What went wrong.
    pub problem: String,
    /// The suggested fix.
    pub fix: String,
}

impl FeedbackProposal {
    /// Builds a proposal.
    #[must_use]
    pub fn new(problem: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            problem: problem.into(),
            fix: fix.into(),
        }
    }

    pub(super) fn validate(&self) -> Result<(), FeedbackError> {
        checked_note(
            "proposal problem",
            &self.problem,
            FEEDBACK_PROPOSAL_MAX_BYTES,
        )?;
        checked_note("proposal fix", &self.fix, FEEDBACK_PROPOSAL_MAX_BYTES)
    }
}

/// The feedback wire contract.
///
/// Under v1, six top-level keys, always present, always in this order. Optional
/// values serialize as nil rather than disappearing, so the shape a reader sees
/// never depends on what the sender happened to have. A bundle that carries a
/// proposal is v2: the same six keys, then `proposal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackBundle {
    /// What kind of feedback this is.
    pub category: FeedbackCategory,
    /// Engine version the report came from.
    pub engine_version: String,
    /// Build target the report came from.
    pub platform: FeedbackPlatform,
    /// Whitelisted configuration snapshot, when the reporter shares one.
    pub config: Option<FeedbackConfigSnapshot>,
    /// Self-healer conclusion, when one exists.
    pub healer_diagnosis: Option<FeedbackHealerDiagnosis>,
    /// What the owner wrote, as they wrote it. The engine never fills this.
    pub user_note: Option<String>,
    /// The suggested fix, when this bundle is a proposal. Present only under
    /// v2, so a v1 bundle keeps its six keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<FeedbackProposal>,
}

/// The six top-level bundle keys, in serialization order.
pub const FEEDBACK_BUNDLE_KEYS: [&str; 6] = [
    "category",
    "engine_version",
    "platform",
    "config",
    "healer_diagnosis",
    "user_note",
];

impl FeedbackBundle {
    /// Builds a minimal bundle: a category, a version, a platform, and
    /// nothing optional.
    #[must_use]
    pub fn new(
        category: FeedbackCategory,
        engine_version: impl Into<String>,
        platform: FeedbackPlatform,
    ) -> Self {
        Self {
            category,
            engine_version: engine_version.into(),
            platform,
            config: None,
            healer_diagnosis: None,
            user_note: None,
            proposal: None,
        }
    }

    /// Attaches a whitelisted configuration snapshot.
    #[must_use]
    pub fn with_config(mut self, config: FeedbackConfigSnapshot) -> Self {
        self.config = Some(config);
        self
    }

    /// Attaches a healer diagnosis.
    #[must_use]
    pub fn with_healer_diagnosis(mut self, diagnosis: FeedbackHealerDiagnosis) -> Self {
        self.healer_diagnosis = Some(diagnosis);
        self
    }

    /// Attaches the person's note.
    #[must_use]
    pub fn with_user_note(mut self, note: impl Into<String>) -> Self {
        self.user_note = Some(note.into());
        self
    }

    /// Attaches a proposal, which makes this a v2 bundle.
    #[must_use]
    pub fn with_proposal(mut self, proposal: FeedbackProposal) -> Self {
        self.proposal = Some(proposal);
        self
    }

    /// The encoding this bundle's bytes are produced under.
    #[must_use]
    pub const fn encoding(&self) -> FeedbackEncoding {
        if self.proposal.is_some() {
            FeedbackEncoding::V2
        } else {
            FeedbackEncoding::V1
        }
    }

    /// Checks every field constraint the wire contract promises.
    pub fn validate(&self) -> Result<(), FeedbackError> {
        checked_token(
            "engine_version",
            &self.engine_version,
            FEEDBACK_ENGINE_VERSION_MAX_BYTES,
        )?;
        self.platform.validate()?;
        if let Some(config) = &self.config {
            config.validate()?;
        }
        if let Some(diagnosis) = &self.healer_diagnosis {
            diagnosis.validate()?;
        }
        if let Some(note) = self.user_note.as_deref() {
            checked_note("user_note", note, FEEDBACK_USER_NOTE_MAX_BYTES)?;
        }
        if let Some(proposal) = &self.proposal {
            proposal.validate()?;
        }
        Ok(())
    }
}

/// Encodes a validated bundle as named MessagePack, under the encoding
/// [`FeedbackBundle::encoding`] names.
///
/// The named encoder is the contract: a compact positional encoding would make
/// the key order load-bearing for readers, and it is not.
pub fn encode_feedback_bundle(bundle: &FeedbackBundle) -> Result<Vec<u8>, FeedbackError> {
    bundle.validate()?;
    rmp_serde::to_vec_named(bundle).map_err(FeedbackError::Encode)
}

/// Decodes v1 bundle bytes, rejecting unknown fields, duplicate fields, a
/// proposal, and any trailing byte after the bundle map.
pub fn decode_feedback_bundle(bytes: &[u8]) -> Result<FeedbackBundle, FeedbackError> {
    decode_feedback_bundle_as(FeedbackEncoding::V1, bytes)
}

/// Decodes bundle bytes produced under `encoding`.
///
/// Trailing bytes are rejected by reading through a positioned deserializer
/// and comparing the consumed length against the input length, because a
/// whole-slice decode would silently accept a suffix. A v1 reader never
/// accepts a proposal and a v2 reader never accepts a bundle without one, so
/// the token and the shape cannot disagree.
pub fn decode_feedback_bundle_as(
    encoding: FeedbackEncoding,
    bytes: &[u8],
) -> Result<FeedbackBundle, FeedbackError> {
    let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(bytes));
    let bundle = FeedbackBundle::deserialize(&mut deserializer).map_err(FeedbackError::Decode)?;
    let consumed = deserializer.position();
    let total = bytes.len() as u64;
    if consumed != total {
        return Err(FeedbackError::TrailingBytes { consumed, total });
    }
    bundle.validate()?;
    if bundle.encoding() != encoding {
        return Err(FeedbackError::EncodingMismatch {
            expected: encoding.as_str(),
            found: bundle.encoding().as_str(),
        });
    }
    Ok(bundle)
}

/// Lowercase hex digest binding the exact v1 bundle bytes a destination
/// receives.
///
/// The preimage is the encoding token, a NUL, the big-endian byte length, and
/// the bytes. Length-prefixing keeps two different bundles from colliding
/// through concatenation, and the domain tag keeps this digest from colliding
/// with any other digest in the engine.
#[must_use]
pub fn feedback_bundle_digest(bytes: &[u8]) -> String {
    feedback_bundle_digest_as(FeedbackEncoding::V1, bytes)
}

/// [`feedback_bundle_digest`] under the domain of `encoding`, so the same bytes
/// labelled with two tokens never share a digest.
#[must_use]
pub fn feedback_bundle_digest_as(encoding: FeedbackEncoding, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(encoding.digest_domain());
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}
