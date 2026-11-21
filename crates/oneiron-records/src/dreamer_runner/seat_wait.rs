//! Moved from `crates/oneiron/src/dreamer_runner/seat_wait.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Whether a model seat may take work now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelSeatAvailability {
    /// A refusal parked tries on the seat; its available write has not landed.
    Unavailable,
    /// The seat's available write answered its current generation.
    Available,
}

/// What moved a model seat's row last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelSeatSource {
    /// A refusal parked a try on the seat.
    Refused,
    /// The reported reset passed.
    ResetPassed,
    /// A completed run proved the seat's login works again.
    LoginRestored,
}

/// What a seat-available write answers with: a passed reset or a restored login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelSeatAvailableSource {
    /// The reported reset passed.
    ResetPassed,
    /// A completed run proved the seat's login works again.
    LoginRestored,
}

impl From<ModelSeatAvailableSource> for ModelSeatSource {
    fn from(source: ModelSeatAvailableSource) -> Self {
        match source {
            ModelSeatAvailableSource::ResetPassed => Self::ResetPassed,
            ModelSeatAvailableSource::LoginRestored => Self::LoginRestored,
        }
    }
}

/// One model seat's durable state: whether it may take work, the refusal generation its parks
/// name, the latest refusal's reset, when it last moved, and what moved it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSeatState {
    /// Whether the seat may take work now.
    pub availability: ModelSeatAvailability,
    /// The latest refusal's generation; every park of the seat names one at most this.
    pub generation: u64,
    /// The latest refusal's vendor-reported reset, when it named one.
    pub reset_at_s: Option<u64>,
    /// When the row last moved, in store-clock seconds.
    pub changed_at_s: u64,
    /// What moved the row last.
    pub source: ModelSeatSource,
}
