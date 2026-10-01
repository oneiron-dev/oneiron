//! The local models this build has measured.
//!
//! A vault pins its embedding space by `model_id`, and the space is more than
//! the weights: a model trained to read an instruction before a query lands its
//! queries somewhere else without it, and one trained on raw queries lands them
//! somewhere else with one. So what a query carries is the MODEL's, looked up
//! by the space id, never the server's default — a vault pinned to one model
//! keeps that model's asymmetry whichever model new vaults default to.

/// One model the local provider has been measured against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KnownModel {
    /// The embedding space id: `repo@revision`.
    pub(crate) model_id: &'static str,
    /// Hugging Face repository holding the official files.
    pub(crate) repo: &'static str,
    /// Commit those files were measured at.
    pub(crate) revision: &'static str,
    /// Output width.
    pub(crate) dimensions: usize,
    /// `max_position_embeddings` in the model's `config.json` at that commit.
    /// The rotary tables are built to it, so a longer input has no position to
    /// sit at.
    pub(crate) max_position_embeddings: usize,
    /// Prepended to a QUERY and never to a document. Empty for a model that
    /// embeds queries and documents alike.
    pub(crate) query_instruction: &'static str,
}

/// `perplexity-ai/pplx-embed-v1-0.6b`: a bidirectional Qwen3 body, mean
/// pooled, emitting int8 tanh-quantised values compared by cosine. Queries and
/// documents are embedded raw. The model is MRL-trained, but no prefix width
/// has been measured here, so nothing truncates to one.
pub(crate) const PPLX_EMBED_V1_06: KnownModel = KnownModel {
    model_id: "perplexity-ai/pplx-embed-v1-0.6b@2c4d510dd4a732063c31a0f70193e35067b51fd8",
    repo: "perplexity-ai/pplx-embed-v1-0.6b",
    revision: "2c4d510dd4a732063c31a0f70193e35067b51fd8",
    dimensions: 1024,
    max_position_embeddings: 32_768,
    query_instruction: "",
};

/// `microsoft/harrier-oss-v1-0.6b`: a causal Qwen3 body, last-token pooled and
/// normalised, with an instruction on the query side only. No MRL.
pub(crate) const HARRIER_06: KnownModel = KnownModel {
    model_id: "microsoft/harrier-oss-v1-0.6b@f9b9dc8d367d443f2479d27aa5d8d2850c0774ee",
    repo: "microsoft/harrier-oss-v1-0.6b",
    revision: "f9b9dc8d367d443f2479d27aa5d8d2850c0774ee",
    dimensions: 1024,
    max_position_embeddings: 32_768,
    query_instruction: "Instruct: Given a question, retrieve passages that answer it\nQuery: ",
};

/// Every measured model, the default first.
pub(crate) const KNOWN_MODELS: [KnownModel; 2] = [PPLX_EMBED_V1_06, HARRIER_06];

/// The measured model a space id names, if any.
pub(crate) fn by_model_id(model_id: &str) -> Option<&'static KnownModel> {
    KNOWN_MODELS.iter().find(|model| model.model_id == model_id)
}

/// The measured model a repository and commit hold, if any.
pub(crate) fn by_repo(repo: &str, revision: &str) -> Option<&'static KnownModel> {
    KNOWN_MODELS
        .iter()
        .find(|model| model.repo == repo && model.revision == revision)
}
