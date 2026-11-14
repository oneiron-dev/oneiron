//! Moved from `crates/oneiron/src/verbs/scratchpad.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `self.focus.scratchpad.recall`'s input: the session whose pad is searched
/// and the words to search it for.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScratchpadRecallRequest {
    /// The run's session id whose pad is searched, live or sealed.
    pub session_id: String,
    /// The words every answered line holds, case-folded: 1 to
    /// `SCRATCHPAD_LINE_MAX_BYTES` bytes.
    pub query: String,
}

/// A pad line's mark: after the seal `keep` lines extract and `scratch`
/// lines never do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScratchpadRecallMark {
    Keep,
    Scratch,
}

/// `self.focus.scratchpad.append`'s input: one line for the bound actor's
/// session pad, which the session's first line opens.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScratchpadAppendRequest {
    /// The run's session id; one live pad per session.
    pub session_id: String,
    /// The line: 1 to `SCRATCHPAD_LINE_MAX_BYTES`
    /// bytes once folded onto one line and trimmed.
    pub text: String,
    /// Optional line mark.
    #[serde(default)]
    pub mark: Option<ScratchpadRecallMark>,
    /// Keep the line in full on the board however old it gets.
    #[serde(default)]
    pub pin: bool,
}

/// `self.focus.scratchpad.seal`'s input: the session whose pad is sealed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScratchpadSealRequest {
    /// The run's session id.
    pub session_id: String,
}
