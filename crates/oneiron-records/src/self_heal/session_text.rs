//! Moved from `crates/oneiron/src/self_heal/session_text.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use rmpv::Value;
use serde::Serialize;
use std::collections::BTreeMap;

/// The readable text of a session window's conversations.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SessionText {
    /// Every readable line: conversation by conversation in the order the
    /// window first names them, each in transcript order, a turn's own words
    /// before its messages.
    pub lines: Vec<SessionLine>,
}

/// One readable line of a session: who said it, where, when, and all of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionLine {
    /// 32-hex conversation id; `None` for a turn that belongs to none.
    pub conversation: Option<String>,
    /// 32-hex turn id.
    pub turn: String,
    /// 32-hex message id; `None` for the words a TURN carries itself.
    pub message: Option<String>,
    /// Who said it, as its writer recorded them.
    pub role: Option<String>,
    /// When it occurred (Unix seconds).
    pub occurred: u64,
    /// What it says, whole.
    pub text: String,
    /// The result attachment the message carries, whole or marked
    /// unavailable (FIX 6113); `None` for a line that carries none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SessionResult>,
}

/// A message's result attachment as its session line carries it (FIX 6113):
/// the whole body, or why this reader cannot read it whole now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionResult {
    /// A text body, whole.
    Text {
        /// The body, as its reads show text.
        text: String,
        /// Bytes of the body that are not UTF-8 are shown replaced.
        lossy: bool,
    },
    /// A binary body, whole.
    Binary {
        /// The body's bytes, as base64.
        base64: String,
    },
    /// Not readable whole by this reader now: withheld, refused or gone.
    Unavailable {
        /// The read's own code: a refusal's, a withholding's or an error's.
        reason: String,
    },
}
