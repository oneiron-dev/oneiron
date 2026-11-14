//! Moved from `crates/oneiron/src/surface_event/handoff.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_id::AttemptId;
use oneiron_store::attempt_state::AttemptState;
pub use oneiron_store::dispatch_attempt_kind::SURFACE_EVENT_ATTEMPT_KIND;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

/// Public reference to the durable attempt backing one admitted event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SurfaceEventAttemptRef(String);

impl SurfaceEventAttemptRef {
    pub fn from_attempt_id(id: AttemptId) -> Self {
        let bytes = id.as_bytes();
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            hex.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
            hex.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
        }
        Self(hex)
    }

    /// Lowercase 32-hex attempt id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Durable lifecycle of an admitted surface event, in public spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceEventHandoffState {
    Queued,
    Leased,
    Paused,
    Completed,
    Failed,
    Cancelled,
    /// The executor stopped carrying the handoff without delivering and
    /// without anyone stopping it. Its own token rather than a fold onto
    /// `Failed` (nothing reported a fault) or `Cancelled` (nobody asked): a
    /// caller polling this surface is owed the true reason its event never
    /// landed.
    Abandoned,
}

impl SurfaceEventHandoffState {
    pub const fn from_attempt_state(state: AttemptState) -> Self {
        match state {
            AttemptState::Queued => Self::Queued,
            // A landing attempt still holds its lease and its runtime, so the
            // handoff surface reads it as leased: live work, not a handoff that
            // completed or was cancelled.
            AttemptState::Leased | AttemptState::Landing => Self::Leased,
            // A deferred retry is not runnable-now, same as a pause.
            AttemptState::Scheduled | AttemptState::Paused => Self::Paused,
            AttemptState::Completed => Self::Completed,
            AttemptState::Failed => Self::Failed,
            AttemptState::Cancelled => Self::Cancelled,
            AttemptState::Abandoned => Self::Abandoned,
        }
    }

    /// Stable wire spelling, matching the serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Abandoned => "abandoned",
        }
    }
}

/// Ack returned the moment an inbound event is durably committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceEventAck {
    pub correlation_id: String,
    pub attempt_ref: SurfaceEventAttemptRef,
    pub state: SurfaceEventHandoffState,
    /// `true` when this correlation id already had an attempt row.
    pub replayed: bool,
    /// When the attempt backing this correlation id was admitted. A replay
    /// carries the original admission, matching the status snapshot's
    /// `created_at`, never the replay's own clock.
    pub accepted_at: u64,
    pub status_path: String,
    /// The identity the event addresses. The ack itself never names it; a
    /// host that keeps the ack for a replay re-admits it.
    #[serde(skip)]
    pub receiving_identity_ref: String,
}

/// Durable snapshot of an admitted event's handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceEventHandoffStatus {
    pub correlation_id: String,
    pub attempt_ref: SurfaceEventAttemptRef,
    pub state: SurfaceEventHandoffState,
    pub attempt_count: u32,
    pub last_error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

pub const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
