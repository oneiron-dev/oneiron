//! Host-served extraction beside witness, followed by a separately authorized
//! save of its tags.
mod persist;
mod shadow;
mod types;
pub(crate) use shadow::hash_input;
pub use types::{
    CorefLink, EncoderGolden, EncoderInput, EncoderMessage, EncoderOutput, EncoderParity,
    EncoderTurn, ExtractionEncoder, NerSpan, ShadowTrace, WitnessWithShadow,
};
#[cfg(test)]
mod tests;
