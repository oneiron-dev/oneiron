//! Moved from `crates/oneiron/src/ingest/meeting_audio/command.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use std::time::Duration;

pub const PROTOCOL: &str = "oneiron.meeting_audio.host.v3";

/// How long a native host process may write nothing (no unit, progress,
/// end or reply) before its stage faults (CALLS, FIX 3765). A recording runs
/// as long as its units progress.
pub const UNIT_PROGRESS_TIMEOUT: Duration = Duration::from_secs(600);
