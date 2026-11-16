//! Speech wire adapters for Oneiron's voice cascade seams, one module per
//! wire protocol (ARCH-0036 `#adapters`, MED-1 = A).
//!
//! Each module owns its protocol's frame mapping and reply checks; the host
//! owns the socket, the key, the queue, the permit, the spool and the rung.
//! `asr::soniox` serves the ASR seam (`oneiron::voice_cascade::AsrStream`);
//! `tts::irodori_moss` serves the TTS seam
//! (`oneiron::voice_cascade::TtsSeamClient`). The server's media rungs speak
//! `tts::hosted` (Cartesia and ElevenLabs, `tts::{cartesia, elevenlabs}`) and
//! `tts::voxcpm2` (the VoxCPM2 worker's render framing), and its voice
//! cloner `design::hosted` (`design::{cartesia, elevenlabs}`). An
//! OpenAI-compatible provider's speech and transcription calls are
//! `tts::openai_compat` and `asr::openai_compat`, each a media backend
//! (`oneiron::llm::media::MediaBackend`) over the provider's shared
//! `oneiron_llm::openai_compat::OpenAiMediaClient`.
//!
//! The VoxCPM2 and hosted TTS adapters stay in core
//! (`oneiron::voice_cascade::{voxcpm2, hosted_tts}`): each sends inside the
//! vault's voice consent fence, which is engine custody, not a wire.

/// Speech-to-text wires.
pub mod asr {
    pub mod openai_compat;
    pub mod soniox;
}

/// Text-to-speech wires.
pub mod tts {
    pub mod cartesia;
    pub mod elevenlabs;
    pub mod hosted;
    pub mod irodori_moss;
    pub mod openai_compat;
    pub mod voxcpm2;
}

/// Voice design wires: a provider voice cloned from a banked identity's refs.
pub mod design {
    pub mod cartesia;
    pub mod elevenlabs;
    pub mod hosted;
}
