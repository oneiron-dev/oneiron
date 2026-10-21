//! Host-served extraction beside witness, followed by a separately authorized
//! save of its tags.
mod persist;
mod shadow;
mod types;
pub(crate) use shadow::hash_input;
pub use shadow::infer_encoder;
pub use types::{
    ContextLink, CorefLink, EncoderAttempt, EncoderExecution, EncoderGolden, EncoderInput,
    EncoderMessage, EncoderOutput, EncoderParity, EncoderTurn, ExecutionCompute, ExecutionPick,
    ExecutionRuntime, ExtractionEncoder, ExtractionWork, NerSpan, ShadowTrace, SpeakerLink,
    SpeakerRole, SpeakerTarget, WitnessWithShadow,
};
#[cfg(test)]
mod tests;
