//! Speech wire adapters for Oneiron's voice cascade seams, one module per
//! wire protocol (ARCH-0036 `#adapters`, MED-1 = A).
//!
//! Each module owns its protocol's frame mapping and reply checks; the host
//! owns the socket, the key, the queue and the rung. `asr::soniox` serves the
//! ASR seam (`oneiron::voice_cascade::AsrStream`); `tts::irodori_moss` serves
//! the TTS seam (`oneiron::voice_cascade::TtsSeamClient`).
//!
//! The VoxCPM2 and hosted TTS adapters stay in core
//! (`oneiron::voice_cascade::{voxcpm2, hosted_tts}`): each sends inside the
//! vault's voice consent fence, which is engine custody, not a wire.

/// Speech-to-text wires.
pub mod asr {
    pub mod soniox;
}

/// Text-to-speech wires.
pub mod tts {
    pub mod irodori_moss;
}
