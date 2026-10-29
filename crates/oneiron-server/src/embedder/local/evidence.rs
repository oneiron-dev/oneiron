//! Where vector evidence starts in a shipped model's space, and the profile
//! its floors hold for.
//!
//! A shipped model's floors were measured with its files, its shipped
//! settings and unprompted queries. They hold for a local section that runs
//! it so, and for an endpoint whose server names that model loaded and runs it
//! so ([`super::super::endpoint`]); every other profile keeps the engine's
//! default.

use oneiron::config::VectorEvidenceFloors;
use serde::{Deserialize, Serialize};

use super::model_manager::{PINNED_MODELS, ResolvedLocalRevision};
use crate::config::{EmbedderAttention, EmbedderConfig, EmbedderOutputQuantization, EmbedderQuant};

/// How a section runs its model, beyond what its transform says: each
/// setting moves where a paraphrase and noise score. `embedder serve` lists
/// its own beside its transform.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RunProfile {
    /// The files are an operator's `model_dir`, taken as they stand, rather
    /// than the repository's own at its revision, fetched and checked.
    pub(crate) model_dir: bool,
    pub(crate) quant: EmbedderQuant,
    pub(crate) attention: EmbedderAttention,
    pub(crate) output_quantization: EmbedderOutputQuantization,
    pub(crate) max_input_tokens: usize,
}

impl RunProfile {
    pub(crate) fn of(config: &EmbedderConfig) -> Self {
        Self {
            model_dir: config.local.model_dir.is_some(),
            quant: config.local.quant,
            attention: config.local.attention,
            output_quantization: config.local.output_quantization,
            max_input_tokens: config.max_input_tokens,
        }
    }

    /// Whether this is the profile a shipped model's floors were measured
    /// under: the repository's files, Q8_0 weights, the attention and output
    /// quantization the checkpoint declares, and an input cap that reads at
    /// least what the shipped one does.
    pub(crate) fn is_measured(&self) -> bool {
        !self.model_dir
            && self.quant == EmbedderQuant::Q8_0
            && self.attention == EmbedderAttention::Auto
            && self.output_quantization == EmbedderOutputQuantization::default()
            && self.max_input_tokens >= crate::config::embedder::DEFAULT_MAX_INPUT_TOKENS
    }
}

/// The floors measured for `model_id` (`org/name@revision`), when it is a
/// shipped model with floors, run with `profile`'s measured settings and
/// queried unprompted; `None` otherwise.
pub(crate) fn measured_floors(
    model_id: &str,
    profile: &RunProfile,
    unprompted: bool,
) -> Option<VectorEvidenceFloors> {
    if !unprompted || !profile.is_measured() {
        return None;
    }
    PINNED_MODELS
        .iter()
        .find(|model| model_id == format!("{}@{}", model.repo, model.revision))
        .and_then(|model| model.evidence)
}

/// Where vector evidence starts for a local section: its model's measured
/// floors when it runs the shipped profile with no query prompt.
pub(crate) fn pinned_evidence(config: &EmbedderConfig) -> Option<VectorEvidenceFloors> {
    pinned_evidence_resolved(config, None)
}

/// [`pinned_evidence`] for the commit `resolved` names when it names one,
/// else the configured revision: a ref that resolves to the shipped commit
/// takes its measured floors.
pub(crate) fn pinned_evidence_resolved(
    config: &EmbedderConfig,
    resolved: Option<&ResolvedLocalRevision>,
) -> Option<VectorEvidenceFloors> {
    // The tokenizer strips what it encodes, so an instruction of blanks puts
    // the same tokens through the model as none.
    let unprompted = config
        .query_instruction
        .as_deref()
        .map_or(config.query_prompt_name.is_none(), |instruction| {
            super::batcher::strip(instruction).is_empty()
        });
    let revision = resolved.map_or(
        config.local.revision.as_str(),
        ResolvedLocalRevision::commit,
    );
    let files = format!("{}@{}", config.local.repo, revision);
    measured_floors(&files, &RunProfile::of(config), unprompted)
}

/// Whether an endpoint section's queries reach the model unprompted: it names
/// no instruction, or one of blanks. Such a vault on a shipped model sends an
/// empty one ([`names_measured_model`]), so a server's own prompt never
/// applies to it.
pub(crate) fn endpoint_queries_unprompted(config: &EmbedderConfig) -> bool {
    config
        .query_instruction
        .as_deref()
        .is_none_or(|instruction| super::batcher::strip(instruction).is_empty())
}

/// Whether `model_id` names a shipped model with measured floors.
pub(crate) fn names_measured_model(model_id: &str) -> bool {
    PINNED_MODELS.iter().any(|model| {
        model.evidence.is_some() && model_id == format!("{}@{}", model.repo, model.revision)
    })
}
