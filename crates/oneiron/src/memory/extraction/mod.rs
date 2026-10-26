//! Host-served extraction beside witness, followed by a separately authorized
//! save of its tags.
mod persist;
mod register;
mod shadow;
mod types;
pub(crate) use register::register_turn;
pub(crate) use shadow::hash_input;
pub use shadow::{infer_encoder, infer_encoder_for};
pub use types::{
    ContextLink, CorefLink, EncoderAttempt, EncoderExecution, EncoderGolden, EncoderInput,
    EncoderMessage, EncoderOutput, EncoderParity, EncoderRegister, EncoderTurn, ExecutionCompute,
    ExecutionPick, ExecutionRuntime, ExtractionCaller, ExtractionEncoder, ExtractionWork, MoodPart,
    NerSpan, ShadowTrace, SpeakerLink, SpeakerRole, SpeakerTarget, WitnessWithShadow,
};
#[cfg(test)]
mod tests;
