//! Engine feedback channel: bundle wire contract, consent, dispatch, export.
//!
//! A person who hits a bug, a papercut, a confusing surface, or wants a
//! feature can hand the engine a *feedback bundle*: a small, stable,
//! deployment-independent record of what the engine looked like when the
//! problem happened. This module owns the whole in-vault half of that story
//! and nothing beyond it.
//!
//! # What ships here
//!
//! - [`FeedbackBundle`], the frozen wire contract, encoded as named
//!   MessagePack under the token [`FEEDBACK_BUNDLE_ENCODING`].
//! - The typed local verb family: [`FEEDBACK_SEND_VERB`], [`FEEDBACK_VERBS`],
//!   [`FeedbackVerb`]. The family is local to this module by design — feedback
//!   is not an agent-visible board verb and joins no shared verb allowlist.
//! - In-vault redaction ([`FeedbackRedactor`]) and preview
//!   ([`prepare_feedback_preview`]).
//! - Per-bundle, per-destination consent over the existing
//!   [`ConsentAskCard`] surface ([`feedback_approval_card`],
//!   [`validate_feedback_approval`]).
//! - An ordinary outbound send through
//!   [`Vault::dispatch_outbound_intent`](crate::Vault::dispatch_outbound_intent)
//!   ([`send_feedback`]) and an air-gapped export
//!   ([`export_feedback_bundle`]).
//!
//! # What does NOT ship here
//!
//! No collector endpoint, no issue-tracker transport, no cloud routing, no
//! receiving vault entities, no deduplication or classification, no triage
//! proposals, no digest review. The bundle bytes are the input contract those
//! future systems will consume; they are deliberately built and frozen first.
//!
//! The [`FeedbackRedactor`] seam is exposed informationally so a later
//! entity-recognition redactor can be dropped in behind it. No model, no
//! weights, and no model runtime ship in this module —
//! [`PassThroughFeedbackRedactor`] is the only implementation here, and it
//! redacts nothing.
//!
//! # Wire stability
//!
//! [`FeedbackBundle`] serializes exactly six top-level keys, in this order:
//! `category`, `engine_version`, `platform`, `config`, `healer_diagnosis`,
//! `user_note`. Absent optional values serialize as MessagePack nil; they are
//! never omitted, so the key set is identical for every bundle ever produced.
//! Every struct denies unknown fields, unordered collections are ordered maps
//! and sets, decoding rejects trailing bytes, and the encoder is always the
//! *named* MessagePack encoder. A reader written against v1 bytes today keeps
//! working; a v2 shape would take a new encoding token, not a new key.
//!
//! # Trust boundary
//!
//! [`validate_feedback_approval`] consumes a [`ConsentActionEvaluation`] as
//! HOST-TRUSTED FIELD INPUT. It is not authentication. The host authenticated
//! the owner when it evaluated the consent action; this module only checks
//! that the evaluation it was handed describes an approve-once decision on the
//! exact component id derived from this bundle and this destination. A host
//! that fabricates an evaluation is already inside its own trust boundary —
//! the same boundary the persona-snapshot export consent sits behind.
//!
//! # Consent scope
//!
//! One approval authorizes exactly one bundle to exactly one destination,
//! exactly once. The approval card is minted with an EMPTY escalator list, so
//! its only actions are approve-once and decline: there is no "always allow
//! feedback", no standing grant, and no widening. A stale bundle digest or a
//! different destination fails with [`FeedbackError::StalePreviewDigest`]
//! before any contract resolution, gate evaluation, transport call, or write.
//!
//! # Secret hygiene
//!
//! [`FeedbackConfigSnapshot`] is a whitelist projection of
//! [`VaultConfig`](crate::config::VaultConfig): it copies a fixed list of
//! non-secret tuning scalars and copies nothing else. Dictionary search roots,
//! filesystem locations, environment values, connector credentials, custody
//! references, payload bodies, hostnames, and account identifiers are all
//! absent by construction, because the projection names every field it
//! carries. This module never reads the environment, the filesystem, a socket,
//! or a subprocess; the only sink it writes to is one the caller supplies.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::genui::{
    ConsentActionDecision, ConsentActionEvaluation, ConsentAskCard, Of336ComponentKind,
};
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchError,
    OutboundDispatchGate, OutboundDispatchRequest, OutboundDispatchResult,
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent,
    OutboundIntentDraft, OutboundIntentTrigger, outbound_verb_contract,
};

/// Stable encoding token for the v1 feedback bundle wire contract.
pub const FEEDBACK_BUNDLE_ENCODING: &str = "oneiron.feedback.bundle.v1";

/// The single protocol verb of the feedback family.
pub const FEEDBACK_SEND_VERB: &str = "feedback.send";

/// Exact feedback verb family in protocol sort order.
pub const FEEDBACK_VERBS: [&str; 1] = [FEEDBACK_SEND_VERB];

/// Prefix of the content-addressed approval component id.
pub const FEEDBACK_APPROVAL_COMPONENT_PREFIX: &str = "feedback-preview:";

/// Prefix of the intent/receipt `content_ref` that carries bundle lineage.
pub const FEEDBACK_CONTENT_REF_PREFIX: &str = "feedback:";

/// Prefix of the logical send identity shared by every replay of one send.
pub const FEEDBACK_LOGICAL_SEND_PREFIX: &str = "feedback-send:";

/// Consent action id that authorizes exactly one feedback act.
pub const FEEDBACK_APPROVE_ONCE_ACTION: &str = "approve_once";

/// Receipt field naming the typed feedback verb behind an outbound effect.
pub const FEEDBACK_RECEIPT_FIELD_VERB: &str = "feedback_verb";

/// Receipt field naming the bundle encoding that crossed the wire.
pub const FEEDBACK_RECEIPT_FIELD_BUNDLE_ENCODING: &str = "feedback_bundle_encoding";

/// Receipt field carrying the lowercase hex bundle digest.
pub const FEEDBACK_RECEIPT_FIELD_BUNDLE_DIGEST: &str = "feedback_bundle_digest";

/// Receipt field referencing the approval receipt that authorized the send.
pub const FEEDBACK_RECEIPT_FIELD_APPROVAL_RECEIPT_REF: &str = "feedback_approval_receipt_ref";

/// Maximum accepted `engine_version` length in bytes.
pub const FEEDBACK_ENGINE_VERSION_MAX_BYTES: usize = 64;

/// Maximum accepted `embedding_model` length in bytes.
pub const FEEDBACK_EMBEDDING_MODEL_MAX_BYTES: usize = 128;

/// Maximum accepted free-text note length in bytes.
pub const FEEDBACK_USER_NOTE_MAX_BYTES: usize = 4096;

/// Maximum accepted length of any single reference token in bytes.
pub const FEEDBACK_REF_MAX_BYTES: usize = 256;

/// Maximum accepted length of the healer mechanism sentence in bytes.
pub const FEEDBACK_MECHANISM_MAX_BYTES: usize = 512;

/// Maximum number of hops carried by one healer diagnosis DAG.
pub const FEEDBACK_DAG_MAX_HOPS: usize = 64;

/// Maximum number of subject references carried by one healer diagnosis.
pub const FEEDBACK_MAX_SUBJECT_REFS: usize = 64;

/// Domain separator for the bundle digest preimage.
const FEEDBACK_DIGEST_DOMAIN: &[u8] = b"oneiron.feedback.bundle.v1\0";

/// Domain separator for the approval component-id preimage.
const FEEDBACK_APPROVAL_DOMAIN: &[u8] = b"oneiron.feedback.approval.v1\0";

/// Scope tag opening a Send route preimage.
const FEEDBACK_SCOPE_SEND_TAG: &[u8] = b"send\0";

/// Scope tag for the air-gapped export preimage.
const FEEDBACK_SCOPE_EXPORT_TAG: &[u8] = b"export";

/// Frame byte marking an absent optional in a scope preimage.
const FEEDBACK_FRAME_ABSENT: u8 = 0x00;

/// Frame byte marking a present optional in a scope preimage.
const FEEDBACK_FRAME_PRESENT: u8 = 0x01;

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
    /// Named relation between the two references.
    pub relation: String,
    /// Reference the hop reasons to.
    pub to_ref: String,
}

impl FeedbackDagHop {
    /// Builds one hop.
    #[must_use]
    pub fn new(
        from_ref: impl Into<String>,
        relation: impl Into<String>,
        to_ref: impl Into<String>,
    ) -> Self {
        Self {
            from_ref: from_ref.into(),
            relation: relation.into(),
            to_ref: to_ref.into(),
        }
    }

    fn validate(&self) -> Result<(), FeedbackError> {
        checked_token("dag hop from_ref", &self.from_ref, FEEDBACK_REF_MAX_BYTES)?;
        checked_token("dag hop relation", &self.relation, FEEDBACK_REF_MAX_BYTES)?;
        checked_token("dag hop to_ref", &self.to_ref, FEEDBACK_REF_MAX_BYTES)
    }
}

/// What the self-healer concluded: references, an ordered reasoning DAG, and
/// one plain-language mechanism sentence.
///
/// This is a summary, never a dump. References are opaque tokens, the DAG is
/// an ordered list of hops, and the mechanism sentence is length-capped and
/// single-line, so a raw stack trace or a configuration dump cannot ride here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackHealerDiagnosis {
    /// Reference to the diagnosis itself.
    pub diagnosis_ref: String,
    /// References the diagnosis is about. Unordered, so an ordered set.
    pub subject_refs: BTreeSet<String>,
    /// Ordered reasoning hops, first hop first.
    pub dag: Vec<FeedbackDagHop>,
    /// One-sentence mechanism, when the healer produced one.
    pub mechanism: Option<String>,
}

impl FeedbackHealerDiagnosis {
    /// Builds a diagnosis with no subjects, no hops, and no mechanism.
    #[must_use]
    pub fn new(diagnosis_ref: impl Into<String>) -> Self {
        Self {
            diagnosis_ref: diagnosis_ref.into(),
            subject_refs: BTreeSet::new(),
            dag: Vec::new(),
            mechanism: None,
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
        if let Some(mechanism) = self.mechanism.as_deref() {
            checked_sentence("healer mechanism", mechanism, FEEDBACK_MECHANISM_MAX_BYTES)?;
        }
        Ok(())
    }
}

/// The feedback wire contract.
///
/// Six top-level keys, always present, always in this order. Optional values
/// serialize as nil rather than disappearing, so the shape a reader sees never
/// depends on what the sender happened to have.
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
    /// What the person wrote, after redaction.
    pub user_note: Option<String>,
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
        Ok(())
    }
}

/// Encodes a validated bundle as named MessagePack.
///
/// The named encoder is the contract: a compact positional encoding would make
/// the key order load-bearing for readers, and it is not.
pub fn encode_feedback_bundle(bundle: &FeedbackBundle) -> Result<Vec<u8>, FeedbackError> {
    bundle.validate()?;
    rmp_serde::to_vec_named(bundle).map_err(FeedbackError::Encode)
}

/// Decodes bundle bytes, rejecting unknown fields, duplicate fields, and any
/// trailing byte after the bundle map.
///
/// Trailing bytes are rejected by reading through a positioned deserializer
/// and comparing the consumed length against the input length, because a
/// whole-slice decode would silently accept a suffix.
pub fn decode_feedback_bundle(bytes: &[u8]) -> Result<FeedbackBundle, FeedbackError> {
    let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(bytes));
    let bundle = FeedbackBundle::deserialize(&mut deserializer).map_err(FeedbackError::Decode)?;
    let consumed = deserializer.position();
    let total = bytes.len() as u64;
    if consumed != total {
        return Err(FeedbackError::TrailingBytes { consumed, total });
    }
    bundle.validate()?;
    Ok(bundle)
}

/// Lowercase hex digest binding the exact post-redaction bundle bytes.
///
/// The preimage is the encoding token, a NUL, the big-endian byte length, and
/// the bytes. Length-prefixing keeps two different bundles from colliding
/// through concatenation, and the domain tag keeps this digest from colliding
/// with any other digest in the engine.
#[must_use]
pub fn feedback_bundle_digest(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FEEDBACK_DIGEST_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

/// The content reference that carries bundle lineage on intents and receipts.
#[must_use]
pub fn feedback_content_ref(digest: &str) -> String {
    format!("{FEEDBACK_CONTENT_REF_PREFIX}{digest}")
}

/// The logical send identity shared by every replay of one approved send.
#[must_use]
pub fn feedback_logical_send_ref(digest: &str, approval_receipt_ref: &str) -> String {
    format!("{FEEDBACK_LOGICAL_SEND_PREFIX}{digest}:{approval_receipt_ref}")
}

/// Where one approved feedback bundle is allowed to go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackSendRoute {
    /// Outbound channel token.
    pub channel: String,
    /// Outbound verb token on that channel.
    pub verb: String,
    /// Destination address on that channel.
    pub target: String,
    /// Sending channel identity, when the route has a stored one.
    pub channel_identity_ref: Option<EntityId>,
    /// Counterparty reference, when the route addresses a contact.
    pub counterparty_ref: Option<String>,
}

impl FeedbackSendRoute {
    /// Builds a route with no channel identity and no counterparty.
    #[must_use]
    pub fn new(
        channel: impl Into<String>,
        verb: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            channel: channel.into(),
            verb: verb.into(),
            target: target.into(),
            channel_identity_ref: None,
            counterparty_ref: None,
        }
    }

    /// Binds the sending channel identity.
    #[must_use]
    pub fn with_channel_identity_ref(mut self, identity_ref: EntityId) -> Self {
        self.channel_identity_ref = Some(identity_ref);
        self
    }

    /// Binds the counterparty reference.
    #[must_use]
    pub fn with_counterparty_ref(mut self, counterparty_ref: impl Into<String>) -> Self {
        self.counterparty_ref = Some(counterparty_ref.into());
        self
    }

    fn validate(&self) -> Result<(), FeedbackError> {
        checked_token("send route channel", &self.channel, FEEDBACK_REF_MAX_BYTES)?;
        checked_token("send route verb", &self.verb, FEEDBACK_REF_MAX_BYTES)?;
        checked_token("send route target", &self.target, FEEDBACK_REF_MAX_BYTES)?;
        if let Some(reference) = self.counterparty_ref.as_deref() {
            checked_token(
                "send route counterparty_ref",
                reference,
                FEEDBACK_REF_MAX_BYTES,
            )?;
        }
        Ok(())
    }
}

/// The destination an approval authorizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedbackApprovalScope {
    /// One send over one exact route.
    Send(FeedbackSendRoute),
    /// One air-gapped export to a caller-supplied writer.
    Export,
}

impl FeedbackApprovalScope {
    /// Canonical, injective bytes describing this destination.
    ///
    /// Every variable-length field is length-prefixed and every optional is
    /// tag-framed, so no two different destinations — including ones crafted
    /// with embedded NUL bytes — can produce the same preimage.
    fn preimage(&self) -> Vec<u8> {
        match self {
            Self::Export => FEEDBACK_SCOPE_EXPORT_TAG.to_vec(),
            Self::Send(route) => {
                let mut out = FEEDBACK_SCOPE_SEND_TAG.to_vec();
                push_len_prefixed(&mut out, route.channel.as_bytes());
                push_len_prefixed(&mut out, route.verb.as_bytes());
                push_len_prefixed(&mut out, route.target.as_bytes());
                push_framed_identity(&mut out, route.channel_identity_ref.as_ref());
                push_framed_str(&mut out, route.counterparty_ref.as_deref());
                out
            }
        }
    }

    /// Human-readable destination token used in disclosure lines.
    #[must_use]
    pub fn destination_label(&self) -> String {
        match self {
            Self::Export => "air-gapped export to a caller-supplied writer".to_owned(),
            Self::Send(route) => format!(
                "send channel={} verb={} target={}",
                route.channel, route.verb, route.target
            ),
        }
    }
}

/// The content-addressed approval component id for one bundle at one
/// destination.
///
/// Binding the digest AND the destination into the component id is what makes
/// an approval non-transferable: approving bundle A for route A produces an id
/// that cannot validate bundle B, or bundle A for route B, or an export.
#[must_use]
pub fn feedback_approval_component_id(digest: &str, scope: &FeedbackApprovalScope) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FEEDBACK_APPROVAL_DOMAIN);
    hasher.update(digest.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(&scope.preimage());
    let component = hasher.finalize().to_hex();
    format!("{FEEDBACK_APPROVAL_COMPONENT_PREFIX}{component}")
}

/// Something went wrong inside a redactor.
#[derive(Debug, thiserror::Error)]
pub enum FeedbackRedactionError {
    /// The redactor refused this bundle.
    #[error("the feedback redactor rejected the bundle: {0}")]
    Rejected(String),
    /// The redactor could not run.
    #[error("the feedback redactor is unavailable: {0}")]
    Unavailable(String),
}

/// The in-vault redaction seam.
///
/// Everything a person sees in the preview, everything a transport receives,
/// and everything an export writes is the OUTPUT of this trait. Nothing
/// upstream of it ever reaches a destination, which is what makes the seam
/// worth having: a later entity-recognition redactor drops in here without
/// touching consent, dispatch, or the wire contract.
pub trait FeedbackRedactor {
    /// Returns the redacted bundle, or explains why it could not.
    fn redact(&self, bundle: FeedbackBundle) -> Result<FeedbackBundle, FeedbackRedactionError>;
}

/// The redactor that redacts nothing.
///
/// Present so the pipeline is complete and testable without a model. It does
/// NOT weaken consent: a pass-through bundle still requires the same
/// per-bundle, per-destination approval as any other.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassThroughFeedbackRedactor;

impl FeedbackRedactor for PassThroughFeedbackRedactor {
    fn redact(&self, bundle: FeedbackBundle) -> Result<FeedbackBundle, FeedbackRedactionError> {
        Ok(bundle)
    }
}

/// A redacted bundle, its exact encoded bytes, and their digest.
///
/// The three travel together and cannot drift: the bytes are the encoding of
/// this bundle, and the digest is the digest of those bytes. Consent, dispatch,
/// and export all read from here, so the previewed bytes are the sent bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackPreview {
    bundle: FeedbackBundle,
    bytes: Vec<u8>,
    digest: String,
}

impl FeedbackPreview {
    /// The redacted bundle.
    #[must_use]
    pub const fn bundle(&self) -> &FeedbackBundle {
        &self.bundle
    }

    /// The exact bytes a destination receives.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The lowercase hex digest of those bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The lineage reference intents and receipts carry.
    #[must_use]
    pub fn content_ref(&self) -> String {
        feedback_content_ref(&self.digest)
    }

    /// The approval component id for this bundle at one destination.
    #[must_use]
    pub fn approval_component_id(&self, scope: &FeedbackApprovalScope) -> String {
        feedback_approval_component_id(&self.digest, scope)
    }

    /// Human-readable rendering of the redacted bundle contents.
    ///
    /// This is the CONTENT view: what would be sent. It deliberately carries
    /// no digest and no destination — those are consent facts, and they belong
    /// on the approval card's disclosure lines, where a person reads them as
    /// part of the decision rather than as part of the payload.
    pub fn display_json(&self) -> Result<String, FeedbackError> {
        serde_json::to_string_pretty(&self.bundle).map_err(FeedbackError::DisplayJson)
    }
}

/// Redacts a bundle, encodes it once, and digests the result.
///
/// The bundle is validated before redaction and again after, so a redactor
/// cannot hand back a shape that violates the wire contract.
pub fn prepare_feedback_preview<R>(
    bundle: FeedbackBundle,
    redactor: &R,
) -> Result<FeedbackPreview, FeedbackError>
where
    R: FeedbackRedactor + ?Sized,
{
    bundle.validate()?;
    let redacted = redactor.redact(bundle).map_err(FeedbackError::Redaction)?;
    let bytes = encode_feedback_bundle(&redacted)?;
    let digest = feedback_bundle_digest(&bytes);
    Ok(FeedbackPreview {
        bundle: redacted,
        bytes,
        digest,
    })
}

/// The consent data lines shown under the content view on a feedback ask.
///
/// Every consent fact a person needs to decide is here: what it is, how big it
/// is, exactly where it goes, and how far the approval reaches. The content
/// itself is the redacted bundle render the card places above these lines.
#[must_use]
pub fn feedback_approval_disclosure(
    preview: &FeedbackPreview,
    scope: &FeedbackApprovalScope,
) -> String {
    let mut lines = vec![
        format!("category: {}", preview.bundle.category.as_str()),
        format!("bundle_encoding: {FEEDBACK_BUNDLE_ENCODING}"),
        format!("bundle_digest: {}", preview.digest),
        format!("bundle_bytes: {}", preview.bytes.len()),
        format!("destination: {}", scope.destination_label()),
    ];
    if let FeedbackApprovalScope::Send(route) = scope {
        let identity = match route.channel_identity_ref {
            Some(identity_ref) => identity_ref.to_hex(),
            None => "none".to_owned(),
        };
        let counterparty = match route.counterparty_ref.as_deref() {
            Some(reference) => reference.to_owned(),
            None => "none".to_owned(),
        };
        lines.push(format!("channel_identity_ref: {identity}"));
        lines.push(format!("counterparty_ref: {counterparty}"));
    }
    lines.push("scope: this exact bundle, this exact destination, once".to_owned());
    lines.push("scope: no standing feedback grant is created".to_owned());
    lines.join("\n")
}

/// Mints the consent ask for one bundle at one destination.
///
/// The card shows the person exactly two things: the redacted content that
/// would leave the vault, rendered from the same post-redaction value the
/// bytes were encoded from, and the consent data lines that say where it goes
/// and how far the approval reaches. Deciding about content you cannot see is
/// not consent, so the content view is part of the ask rather than something a
/// caller has to remember to display.
///
/// The `prompt` is the caller's: this is a generic engine, and product copy is
/// the product's to write. A blank prompt is refused rather than silently
/// replaced with engine-authored wording.
///
/// The card is built as a validated struct literal with an EMPTY escalator
/// list on purpose. Routing through the card constructor would replace an
/// empty list with the full standing/widening set, which is exactly the
/// "always allow feedback" grant this channel must never offer. With no
/// escalators the card's actions are exactly approve-once and decline.
pub fn feedback_approval_card(
    preview: &FeedbackPreview,
    principal_ref: &str,
    prompt: &str,
    scope: &FeedbackApprovalScope,
) -> Result<ConsentAskCard, FeedbackError> {
    checked_token(
        "approval principal_ref",
        principal_ref,
        FEEDBACK_REF_MAX_BYTES,
    )?;
    if prompt.trim().is_empty() {
        return Err(FeedbackError::InvalidBundle(
            "approval prompt must not be blank".to_owned(),
        ));
    }
    let content = preview.display_json()?;
    let disclosure = feedback_approval_disclosure(preview, scope);
    let channel = match scope {
        FeedbackApprovalScope::Send(route) => Some(route.channel.clone()),
        FeedbackApprovalScope::Export => None,
    };
    let counterparty_ref = match scope {
        FeedbackApprovalScope::Send(route) => route.counterparty_ref.clone(),
        FeedbackApprovalScope::Export => None,
    };
    Ok(ConsentAskCard {
        card_id: preview.approval_component_id(scope),
        principal_ref: principal_ref.to_owned(),
        prompt: prompt.to_owned(),
        preview: format!("{content}\n\n{disclosure}"),
        verb_class: FEEDBACK_SEND_VERB.to_owned(),
        counterparty_ref,
        channel,
        origin_receipt_ref: Some(preview.content_ref()),
        scope_escalators: Vec::new(),
    })
}

/// A validated one-shot approval for one bundle at one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackApproval {
    component_id: String,
    approval_receipt_ref: String,
}

impl FeedbackApproval {
    /// The content-addressed component id the approval was granted against.
    #[must_use]
    pub fn component_id(&self) -> &str {
        &self.component_id
    }

    /// The approval receipt this authorization is anchored to.
    #[must_use]
    pub fn approval_receipt_ref(&self) -> &str {
        &self.approval_receipt_ref
    }
}

/// Checks that a host-supplied consent evaluation authorizes THIS bundle at
/// THIS destination, once.
///
/// The evaluation is host-trusted field input, not authentication: the host
/// authenticated the owner when it evaluated the action. What this function
/// adds is the binding a host cannot get wrong by accident — the component id
/// is derived here from the preview digest and the scope, so an approval for
/// a different bundle or a different destination fails with
/// [`FeedbackError::StalePreviewDigest`] before anything happens.
pub fn validate_feedback_approval(
    preview: &FeedbackPreview,
    scope: &FeedbackApprovalScope,
    evaluation: &ConsentActionEvaluation,
) -> Result<FeedbackApproval, FeedbackError> {
    if evaluation.decision != ConsentActionDecision::ApprovedOnce {
        return Err(FeedbackError::ApprovalNotGranted {
            outcome: evaluation.decision.outcome(),
        });
    }
    if evaluation.grant_mint_intent.is_some() {
        return Err(FeedbackError::WideningNotPermitted);
    }
    let fields = &evaluation.receipt.fields;
    expect_field(
        fields,
        "component_kind",
        Of336ComponentKind::ConsentAsk.as_str(),
    )?;
    let expected = preview.approval_component_id(scope);
    let found = approval_field(fields, "component_id")?;
    if found != expected {
        return Err(FeedbackError::StalePreviewDigest {
            expected,
            found: found.to_owned(),
        });
    }
    expect_field(fields, "action_id", FEEDBACK_APPROVE_ONCE_ACTION)?;
    let receipt_id = evaluation.receipt.receipt_id.trim();
    if receipt_id.is_empty() {
        return Err(FeedbackError::ApprovalFieldMissing {
            field: "receipt_id",
        });
    }
    Ok(FeedbackApproval {
        component_id: expected,
        approval_receipt_ref: receipt_id.to_owned(),
    })
}

/// Everything the send needs beyond the bundle and the approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackSendContext {
    /// Where the bundle is allowed to go.
    pub route: FeedbackSendRoute,
    /// Who is dispatching.
    pub actor: OutboundDispatchActor,
    /// Principal the actor acts for, when there is one.
    pub on_behalf_of: Option<String>,
    /// When the send happens.
    pub occurred_at: u64,
    /// Delivery-window decision supplied by the caller.
    pub window_decision: OutboundDeliveryWindowDecision,
}

impl FeedbackSendContext {
    /// Builds a send context that delivers now.
    #[must_use]
    pub fn new(
        route: FeedbackSendRoute,
        actor: OutboundDispatchActor,
        occurred_at: u64,
        window_decision: OutboundDeliveryWindowDecision,
    ) -> Self {
        Self {
            route,
            actor,
            on_behalf_of: None,
            occurred_at,
            window_decision,
        }
    }

    /// Names the principal this send acts for.
    #[must_use]
    pub fn on_behalf_of(mut self, principal: impl Into<String>) -> Self {
        self.on_behalf_of = Some(principal.into());
        self
    }
}

/// What a feedback transport is handed when the pipeline reaches execution.
pub struct FeedbackTransportRequest<'a> {
    /// The ordinary outbound execution request, unmodified.
    pub execution: &'a OutboundExecutionRequest<'a>,
    /// The exact previewed bundle bytes.
    pub bundle_bytes: &'a [u8],
    /// Lowercase hex digest of those bytes.
    pub bundle_digest: &'a str,
    /// Encoding token those bytes were produced under.
    pub bundle_encoding: &'static str,
    /// Approval receipt that authorized this send.
    pub approval_receipt_ref: &'a str,
}

/// A transport that can carry feedback bundle bytes.
///
/// This is the feedback-shaped face of the ordinary outbound execution sink.
/// The adapter that wraps it is private, so a transport can never be reached
/// except through an approved, gated dispatch.
pub trait FeedbackTransport {
    /// Delivers the bundle and reports an ordinary execution outcome.
    fn send_feedback_bundle(
        &mut self,
        request: &FeedbackTransportRequest<'_>,
    ) -> OutboundExecutionOutcome;
}

/// Wraps a feedback transport as an ordinary outbound execution sink.
///
/// This is the only place the four feedback receipt fields are appended, and
/// it only runs when the pipeline actually executes. A replay that
/// short-circuits before execution never reaches here, so it never reinserts
/// transport fields onto a receipt that did not transport anything.
struct FeedbackOutboundAdapter<'a, T> {
    transport: &'a mut T,
    bundle_bytes: &'a [u8],
    bundle_digest: &'a str,
    approval_receipt_ref: &'a str,
    calls: usize,
}

impl<T: FeedbackTransport> OutboundExecutionSink for FeedbackOutboundAdapter<'_, T> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        let feedback_request = FeedbackTransportRequest {
            execution: request,
            bundle_bytes: self.bundle_bytes,
            bundle_digest: self.bundle_digest,
            bundle_encoding: FEEDBACK_BUNDLE_ENCODING,
            approval_receipt_ref: self.approval_receipt_ref,
        };
        let mut outcome = self.transport.send_feedback_bundle(&feedback_request);
        append_feedback_receipt_fields(
            &mut outcome.receipt_fields,
            self.bundle_digest,
            self.approval_receipt_ref,
        );
        outcome
    }
}

/// Appends the four feedback transport fields, if absent.
///
/// Append-if-absent with blank keys and blank values dropped, matching the
/// engine's own execution-field merge. An adapter cannot overwrite a field the
/// dispatcher already stamped.
fn append_feedback_receipt_fields(
    fields: &mut BTreeMap<String, String>,
    digest: &str,
    approval_receipt_ref: &str,
) {
    let entries = [
        (FEEDBACK_RECEIPT_FIELD_VERB, FEEDBACK_SEND_VERB),
        (
            FEEDBACK_RECEIPT_FIELD_BUNDLE_ENCODING,
            FEEDBACK_BUNDLE_ENCODING,
        ),
        (FEEDBACK_RECEIPT_FIELD_BUNDLE_DIGEST, digest),
        (
            FEEDBACK_RECEIPT_FIELD_APPROVAL_RECEIPT_REF,
            approval_receipt_ref,
        ),
    ];
    for (key, value) in entries {
        if key.trim().is_empty() || value.trim().is_empty() {
            continue;
        }
        fields
            .entry(key.to_owned())
            .or_insert_with(|| value.to_owned());
    }
}

/// Builds the outbound dispatch request for one approved feedback send.
///
/// Validates the approval FIRST, so a stale digest or a different destination
/// fails before an outbound contract is resolved, before the gate runs, and
/// before any transport exists. The route's carrier pair is then resolved
/// against the carriers this deployment already registers, so a channel and
/// verb it cannot dispatch through fails typed here instead of travelling as
/// far as the dispatch pipeline. The logical send identity is written
/// byte-for-byte into the request receipt id, the intent reference, the ledger
/// identity, and the intent idempotency key, so every replay of one approved
/// send is one send.
pub fn feedback_dispatch_request(
    preview: &FeedbackPreview,
    context: &FeedbackSendContext,
    evaluation: &ConsentActionEvaluation,
) -> Result<OutboundDispatchRequest, FeedbackError> {
    context.route.validate()?;
    let scope = FeedbackApprovalScope::Send(context.route.clone());
    let approval = validate_feedback_approval(preview, &scope, evaluation)?;
    let actor_ref = context
        .actor
        .actor_ref
        .as_deref()
        .map(str::trim)
        .filter(|reference| !reference.is_empty())
        .ok_or_else(|| {
            FeedbackError::InvalidBundle(
                "feedback send requires a dispatch actor with an actor_ref".to_owned(),
            )
        })?;
    outbound_verb_contract(&context.route.channel, &context.route.verb)
        .map_err(|capability| FeedbackError::UnsupportedRoute(capability.to_string()))?;
    let logical_send_ref =
        feedback_logical_send_ref(&preview.digest, approval.approval_receipt_ref());
    let intent = feedback_intent(preview, context, &approval, actor_ref, &logical_send_ref);
    Ok(feedback_request_envelope(context, intent, logical_send_ref))
}

fn feedback_intent(
    preview: &FeedbackPreview,
    context: &FeedbackSendContext,
    approval: &FeedbackApproval,
    actor_ref: &str,
    logical_send_ref: &str,
) -> OutboundIntent {
    let mut draft = OutboundIntentDraft::new(
        actor_ref,
        context.route.verb.clone(),
        context.route.channel.clone(),
        context.route.target.clone(),
    )
    .content_ref(preview.content_ref())
    .idempotency_key(logical_send_ref);
    if let Some(principal) = context.on_behalf_of.as_deref() {
        draft = draft.on_behalf_of(principal);
    }
    OutboundIntent::from_trigger(
        draft,
        OutboundIntentTrigger::agent_immediate(approval.approval_receipt_ref()),
    )
}

fn feedback_request_envelope(
    context: &FeedbackSendContext,
    intent: OutboundIntent,
    logical_send_ref: String,
) -> OutboundDispatchRequest {
    let mut request = OutboundDispatchRequest::new(
        logical_send_ref.clone(),
        logical_send_ref.clone(),
        intent,
        context.actor.clone(),
        OutboundDispatchGate::allow_when_policy_grants(),
        context.occurred_at,
        context.window_decision.clone(),
    );
    if let Some(identity_ref) = context.route.channel_identity_ref {
        request = request.channel_identity_ref(identity_ref);
    }
    if let Some(counterparty) = context.route.counterparty_ref.as_deref() {
        request = request.counterparty_ref(counterparty);
    }
    request.ledger_identity_ref = Some(logical_send_ref);
    request
}

/// What one feedback send produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackSendOutcome {
    /// The ordinary dispatch result, gate lineage and receipt included.
    pub dispatch: OutboundDispatchResult,
    /// The logical send identity this send was keyed by.
    pub logical_send_ref: String,
    /// Digest of the bytes that were authorized.
    pub bundle_digest: String,
    /// Approval receipt that authorized the send.
    pub approval_receipt_ref: String,
    /// How many times the transport was actually called.
    pub transport_calls: usize,
}

/// Sends one approved feedback bundle as an ordinary outbound effect.
///
/// Nothing here is a feedback-specific escape hatch. The dispatch crosses the
/// ordinary pipeline, and the gate stays authoritative: the gate facts this
/// function supplies are the host's per-bundle opt-in and permission, freshly
/// granted by the principal for this exact bundle and this exact route. Policy
/// class, opt-out where a contact is addressable, and budget arms all still
/// decide the outcome, and a held or denied dispatch never reaches the
/// transport.
pub fn send_feedback<T>(
    vault: &crate::Vault,
    preview: &FeedbackPreview,
    context: &FeedbackSendContext,
    evaluation: &ConsentActionEvaluation,
    transport: &mut T,
) -> Result<FeedbackSendOutcome, FeedbackError>
where
    T: FeedbackTransport,
{
    let request = feedback_dispatch_request(preview, context, evaluation)?;
    let logical_send_ref = request.receipt_id.clone();
    let approval_receipt_ref = request.intent.trigger_ref.clone();
    let mut adapter = FeedbackOutboundAdapter {
        transport,
        bundle_bytes: &preview.bytes,
        bundle_digest: &preview.digest,
        approval_receipt_ref: &approval_receipt_ref,
        calls: 0,
    };
    let dispatch = vault
        .dispatch_outbound_intent(request, &mut adapter)
        .map_err(|error| FeedbackError::Dispatch(Box::new(error)))?;
    let transport_calls = adapter.calls;
    Ok(FeedbackSendOutcome {
        dispatch,
        logical_send_ref,
        bundle_digest: preview.digest.clone(),
        approval_receipt_ref,
        transport_calls,
    })
}

/// What one air-gapped export produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackExportOutcome {
    /// Digest of the exported bytes.
    pub bundle_digest: String,
    /// Encoding token those bytes were produced under.
    pub bundle_encoding: &'static str,
    /// Approval receipt that authorized the export.
    pub approval_receipt_ref: String,
    /// How many bytes were written.
    pub bytes_written: usize,
}

/// Writes the exact previewed bytes to a caller-supplied writer.
///
/// This is the air-gapped path: it opens no path, no socket, and no
/// subprocess, and it acquires nothing from the ambient environment. The
/// caller owns the destination completely — a buffer, a file it already
/// opened, whatever it chose. An approval scoped to a SEND is not an approval
/// to export, and is rejected before a single byte is written.
pub fn export_feedback_bundle<W>(
    preview: &FeedbackPreview,
    evaluation: &ConsentActionEvaluation,
    writer: &mut W,
) -> Result<FeedbackExportOutcome, FeedbackError>
where
    W: std::io::Write + ?Sized,
{
    let approval = validate_feedback_approval(preview, &FeedbackApprovalScope::Export, evaluation)?;
    writer
        .write_all(&preview.bytes)
        .map_err(FeedbackError::ExportWrite)?;
    Ok(FeedbackExportOutcome {
        bundle_digest: preview.digest.clone(),
        bundle_encoding: FEEDBACK_BUNDLE_ENCODING,
        approval_receipt_ref: approval.approval_receipt_ref().to_owned(),
        bytes_written: preview.bytes.len(),
    })
}

/// Everything that can go wrong on the feedback channel.
#[derive(Debug, thiserror::Error)]
pub enum FeedbackError {
    /// A bundle field violated the wire contract.
    #[error("invalid feedback bundle: {0}")]
    InvalidBundle(String),
    /// Named MessagePack encoding failed.
    #[error("encoding the feedback bundle failed: {0}")]
    Encode(#[source] rmp_serde::encode::Error),
    /// Named MessagePack decoding failed.
    #[error("decoding the feedback bundle failed: {0}")]
    Decode(#[source] rmp_serde::decode::Error),
    /// Bytes remained after a complete bundle was decoded.
    #[error("feedback bundle carries trailing bytes: consumed {consumed} of {total}")]
    TrailingBytes {
        /// Bytes the decoder consumed.
        consumed: u64,
        /// Bytes supplied.
        total: u64,
    },
    /// Rendering the human-readable preview failed.
    #[error("rendering the feedback preview failed: {0}")]
    DisplayJson(#[source] serde_json::Error),
    /// The redactor refused or could not run.
    #[error("feedback redaction failed: {0}")]
    Redaction(#[source] FeedbackRedactionError),
    /// The consent evaluation was not an approve-once decision.
    #[error("feedback approval was not granted: consent outcome {outcome}")]
    ApprovalNotGranted {
        /// The consent outcome that was presented instead.
        outcome: &'static str,
    },
    /// The consent evaluation lacked a field the binding requires.
    #[error("feedback approval is missing the {field} field")]
    ApprovalFieldMissing {
        /// Field that was absent or blank.
        field: &'static str,
    },
    /// A consent field carried an unexpected value.
    #[error("feedback approval field {field} is {found:?}, expected {expected:?}")]
    ApprovalFieldMismatch {
        /// Field that disagreed.
        field: &'static str,
        /// Value the binding requires.
        expected: &'static str,
        /// Value that was presented.
        found: String,
    },
    /// The approval belongs to a different bundle or a different destination.
    #[error("feedback approval {found:?} does not authorize {expected:?}")]
    StalePreviewDigest {
        /// Component id this bundle and destination require.
        expected: String,
        /// Component id the approval carried.
        found: String,
    },
    /// The evaluation carried a widening grant. Feedback never widens.
    #[error("feedback approval cannot mint a standing or widening grant")]
    WideningNotPermitted,
    /// The caller-supplied export writer failed.
    #[error("writing the feedback bundle to the export writer failed: {0}")]
    ExportWrite(#[source] std::io::Error),
    /// The route names a carrier channel and verb this deployment does not
    /// register, so there is nothing to dispatch through.
    #[error("unsupported feedback carrier route: {0}")]
    UnsupportedRoute(String),
    /// The ordinary outbound dispatch failed.
    #[error("dispatching the feedback bundle failed: {0}")]
    Dispatch(#[source] Box<OutboundDispatchError>),
}

fn push_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn push_framed_identity(out: &mut Vec<u8>, value: Option<&EntityId>) {
    match value {
        None => out.push(FEEDBACK_FRAME_ABSENT),
        Some(identity_ref) => {
            out.push(FEEDBACK_FRAME_PRESENT);
            out.extend_from_slice(identity_ref.as_bytes());
        }
    }
}

fn push_framed_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => out.push(FEEDBACK_FRAME_ABSENT),
        Some(text) => {
            out.push(FEEDBACK_FRAME_PRESENT);
            push_len_prefixed(out, text.as_bytes());
        }
    }
}

fn approval_field<'a>(
    fields: &'a BTreeMap<String, String>,
    field: &'static str,
) -> Result<&'a str, FeedbackError> {
    match fields.get(field).map(String::as_str).map(str::trim) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(FeedbackError::ApprovalFieldMissing { field }),
    }
}

fn expect_field(
    fields: &BTreeMap<String, String>,
    field: &'static str,
    expected: &'static str,
) -> Result<(), FeedbackError> {
    let found = approval_field(fields, field)?;
    if found == expected {
        return Ok(());
    }
    Err(FeedbackError::ApprovalFieldMismatch {
        field,
        expected,
        found: found.to_owned(),
    })
}

/// A single-line, whitespace-free, length-bounded, already-trimmed token.
fn checked_token(label: &str, value: &str, max_bytes: usize) -> Result<(), FeedbackError> {
    if value.is_empty() {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not be blank"
        )));
    }
    if value.trim() != value {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not carry leading or trailing whitespace"
        )));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not contain whitespace"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not contain control characters"
        )));
    }
    bounded_bytes(label, value.len(), max_bytes)
}

/// A single-line, length-bounded sentence. Rejects multi-line text so a raw
/// trace or a configuration dump cannot ride in as a "mechanism".
fn checked_sentence(label: &str, value: &str, max_bytes: usize) -> Result<(), FeedbackError> {
    if value.trim().is_empty() {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not be blank"
        )));
    }
    if value.trim() != value {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not carry leading or trailing whitespace"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must be a single line without control characters"
        )));
    }
    bounded_bytes(label, value.len(), max_bytes)
}

/// Free text a person wrote. Newlines are allowed; other control characters
/// and blank-only text are not.
fn checked_note(label: &str, value: &str, max_bytes: usize) -> Result<(), FeedbackError> {
    if value.trim().is_empty() {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not be blank"
        )));
    }
    if value.chars().any(|c| c.is_control() && c != '\n') {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not contain control characters other than newline"
        )));
    }
    bounded_bytes(label, value.len(), max_bytes)
}

fn checked_embedding_model(model: &str) -> Result<String, FeedbackError> {
    checked_token("embedding_model", model, FEEDBACK_EMBEDDING_MODEL_MAX_BYTES)?;
    if model.contains("://") {
        return Err(FeedbackError::InvalidBundle(
            "embedding_model must be a model identifier, not a location".to_owned(),
        ));
    }
    Ok(model.to_owned())
}

fn bounded_bytes(label: &str, len: usize, max_bytes: usize) -> Result<(), FeedbackError> {
    if len > max_bytes {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} is {len} bytes, over the {max_bytes}-byte limit"
        )));
    }
    Ok(())
}

fn bounded(label: &str, len: usize, max_len: usize) -> Result<(), FeedbackError> {
    if len > max_len {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} carries {len} entries, over the {max_len} limit"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
