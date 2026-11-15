//! Moved from `crates/oneiron/src/ingest/history/ledger.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::ingest::history::HistoryMessage;
use crate::ingest::history::HistoryRole;
use crate::ingest::history::UNKNOWN_SPEAKER;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;

/// Whether `landed`, the [`content_hash`]es of what landed of one message,
/// holds `message`. Words of an unknown speaker are held by the same words
/// with the speaker known too, so a later copy never lands them as unknown
/// again; words with the speaker known are not held by the same words of an
/// unknown speaker, so the import that knows who said them lands them, as a
/// revision the Dreamer reads.
pub fn holds(landed: &[String], message: &HistoryMessage) -> bool {
    let held = |unknown| landed.contains(&hash(message, unknown));
    held(false) || (message.said_by == Some(UNKNOWN_SPEAKER) && held(true))
}

pub fn hash(message: &HistoryMessage, unknown_speaker: bool) -> String {
    let mut hasher = blake3::Hasher::new();
    if unknown_speaker {
        hasher.update(b"unknown\0");
    }
    hasher.update(match message.role {
        HistoryRole::User => b"user\0",
        HistoryRole::Assistant => b"asst\0",
    });
    hasher.update(message.text.as_bytes());
    hasher.finalize().to_hex().to_string()
}
