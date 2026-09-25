//! Typed serving payloads and observable extraction receipts.
use crate::{
    EntityId, ModelId,
    affect::{ClaimVadConsolidation, Vad},
    embed::EmbedderLocality,
};
use serde::{Deserialize, Serialize};
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncoderOutput {
    pub spans: Vec<NerSpan>,
    pub links: Vec<CorefLink>,
    pub vad: Vad,
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
#[derive(Debug)]
pub struct ExtractionReceipt {
    pub model: String,
    pub input_hash: String,
    pub turn: EntityId,
    pub mention_targets: Vec<EntityId>,
    pub annotation: crate::affect::VadAnnotation,
    pub consolidated: Vec<ClaimVadConsolidation>,
    pub coref_proposals: Vec<crate::identity_topology::IdentityOpOutcome>,
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
            if !seen.insert(&trace.input_hash)
                || trace.model != model
                || golden.model != model
                || trace.input_hash != golden.input_hash
                || trace.output.as_ref() != Some(&golden.output)
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
