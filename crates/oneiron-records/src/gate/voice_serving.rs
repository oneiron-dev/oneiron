//! Moved from `crates/oneiron/src/gate/voice_serving.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use rmpv::Value;

pub const FIELDS: [&str; 7] = [
    "max_text_bytes",
    "max_ref_bytes",
    "max_queued_renders",
    "max_inflight_uploads",
    "upload_read_deadline_ms",
    "http_deadline_ms",
    "max_header_bytes",
];
