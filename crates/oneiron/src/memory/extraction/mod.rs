//! Host-served extraction beside witness, followed by separately authorized atomic persistence.
mod persist;
mod shadow;
mod types;
pub(crate) use shadow::hash_input;
pub use types::{
    CorefLink, EncoderGolden, EncoderInput, EncoderMessage, EncoderOutput, EncoderParity,
    EncoderTurn, ExtractionEncoder, ExtractionReceipt, NerSpan, ShadowTrace, WitnessWithShadow,
};
#[cfg(test)]
mod tests;
