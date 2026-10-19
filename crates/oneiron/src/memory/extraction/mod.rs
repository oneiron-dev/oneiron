//! Host-served extraction beside witness, followed by a separately authorized
//! save of its tags.
mod persist;
mod shadow;
mod types;
pub(crate) use shadow::hash_input;
pub use shadow::infer_encoder;
pub use types::{
    ContextLink, CorefLink, EncoderGolden, EncoderInput, EncoderMessage, EncoderOutput,
    EncoderParity, EncoderTurn, ExtractionEncoder, NerSpan, ShadowTrace, SpeakerLink, SpeakerRole,
    SpeakerTarget, WitnessWithShadow,
};
#[cfg(test)]
mod tests;
