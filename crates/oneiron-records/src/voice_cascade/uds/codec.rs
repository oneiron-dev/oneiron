//! Moved from `crates/oneiron/src/voice_cascade/uds/codec.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::voice_cascade::protocol::RetrievalContext;
use serde::Deserialize;
use serde::Serialize;
use std::io;
use std::io::BufRead;
use std::io::Write;
use std::time::Duration;
use std::time::Instant;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Open {
        utterance_id: String,
    },
    Partial {
        handle: String,
        revision: u64,
        text: String,
    },
    Final {
        handle: String,
        revision: u64,
        text: String,
    },
    Close {
        handle: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Response {
    Opened {
        handle: String,
    },
    Partial {
        decision: &'static str,
        context: Option<RetrievalContext>,
    },
    Final {
        context: RetrievalContext,
    },
    Closed,
    Error {
        code: &'static str,
    },
}

impl Response {
    pub fn error(code: &'static str) -> Self {
        Self::Error { code }
    }
}
