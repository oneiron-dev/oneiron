//! Typed serving payloads and observable extraction receipts.
use crate::{ModelId, affect::Vad, embed::EmbedderLocality};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize)]
pub struct EncoderMessage {
    pub id: String,
    pub text: String,
}
/// Which side of the conversation a turn is on, read from its messages'
/// stored author: a role, never a guess from turn order or ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpeakerRole {
    /// The user side: the owner or another human.
    #[serde(rename = "A")]
    User,
    /// The companion side: the vault's own agents.
    #[serde(rename = "B")]
    Companion,
}
/// One earlier turn the tagger reads for context and tags nothing in.
#[derive(Debug, Clone, Serialize)]
pub struct EncoderTurn {
    pub turn: String,
    pub messages: Vec<EncoderMessage>,
    /// The turn's side, when its stored authors name one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speaker: Option<SpeakerRole>,
}
#[derive(Debug, Clone, Serialize)]
pub struct EncoderInput {
    pub turn: String,
    pub messages: Vec<EncoderMessage>,
    /// Earlier turns of the same conversation, oldest first: the live
    /// register's window. Never a later turn; empty for a turn read alone.
    /// Spans index `messages` only.
    pub context: Vec<EncoderTurn>,
    /// The input's language as a lowercase ISO 639 code, only when a stored
    /// or configured fact names it; without it the tagger detects it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// The current turn's side, when its stored authors name one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speaker: Option<SpeakerRole>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NerSpan {
    pub message: usize,
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub confidence: f32,
}
/// Two spans of this turn in one entity: `antecedent` is the nearest
/// earlier mention of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorefLink {
    pub span: usize,
    pub antecedent: usize,
    /// The tagger's confidence in the decision, when it gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
}
/// A span whose antecedent is in a context turn: addressed by the turn and
/// message ids the input sent and half-open UTF-8 byte offsets into that
/// message's text as sent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextLink {
    pub span: usize,
    pub turn: String,
    pub message: String,
    pub start: usize,
    pub end: usize,
    pub confidence: f32,
}
/// Who a speaker link says a span is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpeakerTarget {
    /// Whoever speaks the span's turn.
    Speaker,
    /// Whoever the span's turn is spoken to.
    Addressee,
}
/// A span that is the speaker or the addressee of its turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpeakerLink {
    pub span: usize,
    pub target: SpeakerTarget,
    pub confidence: f32,
}
/// What a tagger returns for one input. A model returns what it has heads
/// for: a spans-only model sends no links and no mood. A span carries at
/// most one of a link, a context link and a speaker link.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EncoderOutput {
    pub spans: Vec<NerSpan>,
    #[serde(default)]
    pub links: Vec<CorefLink>,
    /// Read strictly: the three coordinates and no other field.
    #[serde(
        default,
        deserialize_with = "strict_vad",
        skip_serializing_if = "Option::is_none"
    )]
    pub vad: Option<Vad>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_links: Vec<ContextLink>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub speaker_links: Vec<SpeakerLink>,
    /// The served stack that made the answer, as its model card names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_sha16: Option<String>,
}
/// The mood as a tagger sends it. The shared [`Vad`] reads past fields it
/// does not know; an answer is refused for any field outside the contract.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireVad {
    valence: f32,
    arousal: f32,
    dominance: f32,
}
fn strict_vad<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Vad>, D::Error> {
    Ok(
        Option::<WireVad>::deserialize(deserializer)?.map(|vad| Vad {
            valence: vad.valence,
            arousal: vad.arousal,
            dominance: vad.dominance,
        }),
    )
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
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncoderGolden {
    pub model: String,
    pub input_hash: String,
    pub output: EncoderOutput,
}
/// A successful model-pinned parity check. Constructible only by comparison.
/// It names the model and the served stack its outputs named: a head swap
/// at one checkpoint keeps the model id, so the stack tells the two apart.
#[derive(Debug, Clone)]
pub struct EncoderParity {
    pub(super) model: String,
    pub(super) stack: Option<String>,
}
impl EncoderParity {
    pub fn verify(traces: &[ShadowTrace], goldens: &[EncoderGolden]) -> crate::Result<Self> {
        if traces.is_empty() || traces.len() != goldens.len() {
            return Err(crate::Error::InvalidConfig(
                "complete shadow/golden parity set required".into(),
            ));
        }
        let model = traces[0].model.clone();
        let stack = goldens[0].output.stack_sha16.clone();
        let mut seen = std::collections::BTreeSet::new();
        for (trace, golden) in traces.iter().zip(goldens) {
            if !seen.insert(&trace.input_hash)
                || trace.model != model
                || golden.model != model
                || golden.output.stack_sha16 != stack
                || trace.input_hash != golden.input_hash
                || trace.output.as_ref() != Some(&golden.output)
                || trace.failure.is_some()
            {
                return Err(crate::Error::InvalidConfig(
                    "encoder shadow parity failed".into(),
                ));
            }
        }
        Ok(Self { model, stack })
    }
}
