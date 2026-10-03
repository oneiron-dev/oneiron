//! Host-served extraction beside witness, followed by separately authorized atomic persistence.
mod persist;
mod shadow;
mod types;
pub use types::{
    CorefLink, DerivationEnvelope, EncoderGolden, EncoderInput, EncoderMessage, EncoderOutput,
    EncoderParity, ExtractionEncoder, ExtractionLabels, ExtractionReceipt, ExtractionRefusal,
    ExtractionSaveConfig, ExtractionSaveError, ExtractionTagSet, MentionLink, MergeEvidence,
    NerSpan, ShadowTrace, UnconfirmedMention, WitnessWithShadow,
};
#[cfg(test)]
mod tests;
