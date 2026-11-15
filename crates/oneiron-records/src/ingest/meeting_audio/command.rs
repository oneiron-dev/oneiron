//! Moved from `crates/oneiron/src/ingest/meeting_audio/command.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde_json::Value;
use serde_json::json;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

pub const PROTOCOL: &str = "oneiron.meeting_audio.host.v3";

/// How long a native host process may write nothing (no unit, progress,
/// end or reply) before its stage faults (CALLS, FIX 3765). A recording runs
/// as long as its units progress.
pub const UNIT_PROGRESS_TIMEOUT: Duration = Duration::from_secs(600);
