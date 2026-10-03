//! Typed serving payloads, the save configuration, and the saved tag set.
use crate::{EntityId, ModelId, affect::Vad, embed::EmbedderLocality};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, Serialize)]
pub struct EncoderMessage {
    pub id: String,
    pub text: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct EncoderInput {
    pub turn: String,
    pub messages: Vec<EncoderMessage>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NerSpan {
    pub message: usize,
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub confidence: f32,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorefLink {
    pub span: usize,
    pub antecedent: usize,
}
/// What a tagger returns for one input. A model returns what it has heads
/// for: a spans-only model sends no links and no mood.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncoderOutput {
    pub spans: Vec<NerSpan>,
    #[serde(default)]
    pub links: Vec<CorefLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vad: Option<Vad>,
}
/// Hosts own checkpoint execution. No engine implementation guesses model outputs.
pub trait ExtractionEncoder: Send + Sync {
    fn model_id(&self) -> &ModelId;
    fn locality(&self) -> EmbedderLocality;
    fn infer(&self, input: &EncoderInput) -> crate::Result<EncoderOutput>;
}
/// Not deserializable: persistence requires a locally validated shadow receipt.
#[derive(Debug, Clone, Serialize)]
pub struct ShadowTrace {
    pub(super) model: String,
    pub(super) input_hash: String,
    pub(super) output: Option<EncoderOutput>,
    pub(super) failure: Option<String>,
    #[serde(skip)]
    pub(super) input: EncoderInput,
}
impl ShadowTrace {
    pub fn output(&self) -> Option<&EncoderOutput> {
        self.output.as_ref()
    }
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
    pub fn model(&self) -> &str {
        &self.model
    }
    pub fn input_hash(&self) -> &str {
        &self.input_hash
    }
}
#[derive(Debug, Serialize)]
pub struct WitnessWithShadow {
    pub witness: super::super::WitnessReceipt,
    pub trace: ShadowTrace,
}

/// A golden comparison supplied by the host's held-out conformance fixture.
/// Without `tolerance` the served output must equal the golden exactly. With
/// it, spans, labels and links stay exact and each float (span confidence,
/// mood) may differ by at most `tolerance`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncoderGolden {
    pub model: String,
    pub input_hash: String,
    pub output: EncoderOutput,
    #[serde(default)]
    pub tolerance: Option<f32>,
}
/// A successful model-pinned parity check. Constructible only by comparison.
#[derive(Debug, Clone)]
pub struct EncoderParity {
    pub(super) model: String,
}
impl EncoderParity {
    pub fn verify(traces: &[ShadowTrace], goldens: &[EncoderGolden]) -> crate::Result<Self> {
        if traces.is_empty() || traces.len() != goldens.len() {
            return Err(crate::Error::InvalidConfig(
                "complete shadow/golden parity set required".into(),
            ));
        }
        let model = traces[0].model.clone();
        let mut seen = std::collections::BTreeSet::new();
        for (trace, golden) in traces.iter().zip(goldens) {
            if golden
                .tolerance
                .is_some_and(|tolerance| !(0.0..1.0).contains(&tolerance))
            {
                return Err(crate::Error::InvalidConfig(
                    "golden tolerance must be finite and in [0, 1)".into(),
                ));
            }
            if !seen.insert(&trace.input_hash)
                || trace.model != model
                || golden.model != model
                || trace.input_hash != golden.input_hash
                || !trace
                    .output
                    .as_ref()
                    .is_some_and(|output| outputs_agree(output, &golden.output, golden.tolerance))
                || trace.failure.is_some()
            {
                return Err(crate::Error::InvalidConfig(
                    "encoder shadow parity failed".into(),
                ));
            }
        }
        Ok(Self { model })
    }
}
fn outputs_agree(served: &EncoderOutput, golden: &EncoderOutput, tolerance: Option<f32>) -> bool {
    let Some(tolerance) = tolerance else {
        return served == golden;
    };
    let near = |a: f32, b: f32| (a - b).abs() <= tolerance;
    served.spans.len() == golden.spans.len()
        && served.spans.iter().zip(&golden.spans).all(|(a, b)| {
            a.message == b.message
                && a.start == b.start
                && a.end == b.end
                && a.label == b.label
                && near(a.confidence, b.confidence)
        })
        && served.links == golden.links
        && match (served.vad, golden.vad) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                near(a.valence, b.valence)
                    && near(a.arousal, b.arousal)
                    && near(a.dominance, b.dominance)
            }
            _ => false,
        }
}

/// Why the save path refused a tag set. Every refusal writes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractionRefusal {
    /// The parity receipt pins another model than the trace's.
    NoParity,
    /// The shadow run produced no valid output.
    NoOutput,
    /// The turn or a message is gone, has another type, or its stored text
    /// differs from the text the model read.
    SourceChanged,
    /// A span names a message the input lacks, or its byte range does not
    /// fit that message's text on character boundaries.
    BadOffsets,
    /// A span's label or confidence is out of bounds.
    BadSpan,
    /// The span and link lists disagree: a link names a span the output
    /// lacks or points forward, one span has two antecedents, or a list is
    /// over the 4,096-entry cap.
    SpanCount,
    /// The mood is outside the docs' ranges (valence -1..=1, arousal and
    /// dominance 0..=1).
    MoodOutOfRange,
    /// A label-table row maps a label to a kind with no declared identity key.
    LabelWithoutIdentityKey,
    /// The decode version, a parameter or a label is empty or over 64 bytes.
    BadEnvelope,
}
impl ExtractionRefusal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoParity => "extraction.no_parity",
            Self::NoOutput => "extraction.no_output",
            Self::SourceChanged => "extraction.source_changed",
            Self::BadOffsets => "extraction.bad_offsets",
            Self::BadSpan => "extraction.bad_span",
            Self::SpanCount => "extraction.span_count",
            Self::MoodOutOfRange => "extraction.mood_out_of_range",
            Self::LabelWithoutIdentityKey => "extraction.label_without_identity_key",
            Self::BadEnvelope => "extraction.bad_envelope",
        }
    }
}
impl std::fmt::Display for ExtractionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
/// The save path's error: a typed refusal, or an engine failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionSaveError {
    Refused(ExtractionRefusal),
    Memory(Box<crate::memory::MemoryError>),
}
impl From<crate::memory::MemoryError> for ExtractionSaveError {
    fn from(error: crate::memory::MemoryError) -> Self {
        Self::Memory(Box::new(error))
    }
}
impl From<crate::Error> for ExtractionSaveError {
    fn from(error: crate::Error) -> Self {
        crate::memory::MemoryError::from(error).into()
    }
}
impl From<ExtractionSaveError> for crate::memory::MemoryError {
    fn from(error: ExtractionSaveError) -> Self {
        match error {
            ExtractionSaveError::Refused(refusal) => Self::bad_request(refusal.as_str()),
            ExtractionSaveError::Memory(error) => *error,
        }
    }
}
impl std::fmt::Display for ExtractionSaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "extraction refused: {refusal}"),
            Self::Memory(error) => write!(f, "{}: {}", error.code, error.message),
        }
    }
}
impl std::error::Error for ExtractionSaveError {}

/// Maps a tagger's labels to entity kinds. A label the table does not name
/// stays a tag and creates nothing. A kind is admitted only when the engine
/// declares an identity key for it, so EVENT (no key; the Dreamer mints it)
/// can never be a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionLabels(BTreeMap<String, u8>);
impl ExtractionLabels {
    pub fn new(table: BTreeMap<String, u8>) -> Result<Self, ExtractionRefusal> {
        for (label, kind) in &table {
            if !(1..=64).contains(&label.len()) {
                return Err(ExtractionRefusal::BadEnvelope);
            }
            if crate::ingest::identity_fields_for_kind(*kind).is_empty() {
                return Err(ExtractionRefusal::LabelWithoutIdentityKey);
            }
        }
        Ok(Self(table))
    }
    pub fn kind(&self, label: &str) -> Option<u8> {
        self.0.get(label).copied()
    }
}
/// What a host fixes once per tagger: its label table, its decode version and
/// its decode parameters (register, window, ...). All three enter the
/// derivation envelope of every tag set saved with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionSaveConfig {
    labels: ExtractionLabels,
    decode_version: String,
    params: BTreeMap<String, String>,
}
impl ExtractionSaveConfig {
    pub fn new(
        labels: ExtractionLabels,
        decode_version: impl Into<String>,
        params: BTreeMap<String, String>,
    ) -> Result<Self, ExtractionRefusal> {
        let decode_version = decode_version.into();
        let bounded = |text: &str| (1..=64).contains(&text.len());
        if !bounded(&decode_version)
            || params
                .iter()
                .any(|(key, value)| !bounded(key) || value.len() > 64)
        {
            return Err(ExtractionRefusal::BadEnvelope);
        }
        Ok(Self {
            labels,
            decode_version,
            params,
        })
    }
    pub fn labels(&self) -> &ExtractionLabels {
        &self.labels
    }
    /// SHA-256 over the parameters and the label table, length-prefixed.
    pub fn params_hash(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"oneiron:extraction-params:v1");
        let mut field = |bytes: &[u8]| {
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        };
        for (key, value) in &self.params {
            field(key.as_bytes());
            field(value.as_bytes());
        }
        field(b"labels");
        for (label, kind) in &self.labels.0 {
            field(label.as_bytes());
            field(&[*kind]);
        }
        format!("{:x}", hash.finalize())
    }
    pub(super) fn envelope(&self, trace: &ShadowTrace) -> DerivationEnvelope {
        DerivationEnvelope {
            content_hash: trace.input_hash.clone(),
            model_id: trace.model.clone(),
            version: self.decode_version.clone(),
            params_hash: self.params_hash(),
        }
    }
}

/// The memo-key of one derived object (ARCH-0035): what it was read from,
/// which model made it, which decode made it, with which parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationEnvelope {
    pub content_hash: String,
    pub model_id: String,
    pub version: String,
    pub params_hash: String,
}
/// Where an unconfirmed mention points. None of these is a stored edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MentionLink {
    /// The label maps to no entity kind: the span stays a tag.
    Tag,
    /// The identity key returned one canonical entity.
    Sure { kind: u8, entity: EntityId },
    /// The identity key returned several; the Dreamer decides which.
    /// `provisional` names the candidates that are still provisional.
    Soft {
        kind: u8,
        candidates: Vec<EntityId>,
        provisional: Vec<EntityId>,
    },
    /// No usable candidate: a cold entity the Dreamer resolves later.
    Provisional { kind: u8, entity: EntityId },
}
impl MentionLink {
    /// The one entity this link names, when it names exactly one.
    pub fn entity(&self) -> Option<EntityId> {
        match self {
            Self::Sure { entity, .. } | Self::Provisional { entity, .. } => Some(*entity),
            Self::Tag | Self::Soft { .. } => None,
        }
    }
    pub fn kind(&self) -> Option<u8> {
        match self {
            Self::Tag => None,
            Self::Sure { kind, .. } | Self::Soft { kind, .. } | Self::Provisional { kind, .. } => {
                Some(*kind)
            }
        }
    }
}
/// One span as a derived suggestion: never a `mentions` edge, never synced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnconfirmedMention {
    pub message: EntityId,
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub confidence: f32,
    pub link: MentionLink,
    /// The span this one corefers with, when the model linked them.
    pub antecedent: Option<usize>,
}
/// A coreference link that joins two different entities. The Dreamer decides
/// whether they are one; the save path never merges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeEvidence {
    pub span: usize,
    pub antecedent: usize,
    pub entity: EntityId,
    pub antecedent_entity: EntityId,
    pub confidence: f32,
}
/// One turn's saved tags under one derivation envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionTagSet {
    pub turn: EntityId,
    pub envelope: DerivationEnvelope,
    pub mentions: Vec<UnconfirmedMention>,
    pub merge_evidence: Vec<MergeEvidence>,
    /// The turn's mood when the model returned one.
    pub mood: Option<Vad>,
    pub saved_at: u64,
}
impl ExtractionTagSet {
    /// PageRank seeds from this tag set, best weight per entity, by id. A
    /// sure link seeds at its confidence; a soft link splits its confidence
    /// over its candidates; a coreferent span seeds through the link it took
    /// from its antecedent; a provisional entity (alone or as a soft
    /// candidate) and a tag seed nothing.
    pub fn ppr_seeds(&self) -> Vec<(EntityId, f32)> {
        let mut seeds = BTreeMap::<EntityId, f32>::new();
        let mut seed = |entity: EntityId, weight: f32| {
            let best = seeds.entry(entity).or_insert(weight);
            *best = best.max(weight);
        };
        for mention in &self.mentions {
            match &mention.link {
                MentionLink::Sure { entity, .. } => seed(*entity, mention.confidence),
                MentionLink::Soft {
                    candidates,
                    provisional,
                    ..
                } => {
                    let unique: BTreeSet<_> = candidates.iter().collect();
                    for entity in unique.iter().filter(|e| !provisional.contains(e)) {
                        seed(**entity, mention.confidence / unique.len() as f32);
                    }
                }
                MentionLink::Tag | MentionLink::Provisional { .. } => {}
            }
        }
        seeds.into_iter().collect()
    }
}
/// The outcome of one save.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractionReceipt {
    pub tags: ExtractionTagSet,
    /// Provisional entities this save minted.
    pub minted: Vec<EntityId>,
    /// The turn already held a tag set under the same envelope; nothing was
    /// written and `tags` is the stored set.
    pub unchanged: bool,
}
