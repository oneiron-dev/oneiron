//! The door of `self.focus.scratchpad.recall` (OF-548, ARCH-0032
//! `#scratchpad-marks`: "a recall searches the whole pad"): the bound
//! actor's search over its own session pad, live or sealed, answering each
//! matching line in full, the ones the board folds included. It is the read
//! `POST /v1/core/context-board/scratchpad/recall` serves, in that door's
//! reply shape. The pad is the handle's own: the engine keys it by the
//! handle's actor and the session, never by a field naming someone else.
//!
//! `self.focus.scratchpad.append` and `self.focus.scratchpad.seal` are the
//! writes `POST /v1/core/context-board/scratchpad` serves, over the same
//! engine methods ([`Memory::scratchpad_append`], [`Memory::scratchpad_seal`])
//! and their checks, answering that door's reply ([`ScratchpadWriteReply`]).
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::context_board::{ScratchpadMark, ScratchpadRecall, ScratchpadRecallLine};
use crate::memory::{Memory, MemoryResult};

/// `self.focus.scratchpad.recall`'s input: the session whose pad is searched
/// and the words to search it for.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScratchpadRecallRequest {
    /// The run's session id whose pad is searched, live or sealed.
    pub session_id: String,
    /// The words every answered line holds, case-folded: 1 to
    /// [`crate::context_board::SCRATCHPAD_LINE_MAX_BYTES`] bytes.
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

impl From<ScratchpadRecallMark> for ScratchpadMark {
    fn from(mark: ScratchpadRecallMark) -> Self {
        match mark {
            ScratchpadRecallMark::Keep => Self::Keep,
            ScratchpadRecallMark::Scratch => Self::Scratch,
        }
    }
}

/// `self.focus.scratchpad.append`'s input: one line for the bound actor's
/// session pad, which the session's first line opens.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScratchpadAppendRequest {
    /// The run's session id; one live pad per session.
    pub session_id: String,
    /// The line: 1 to [`crate::context_board::SCRATCHPAD_LINE_MAX_BYTES`]
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

/// What a scratchpad write did to the session's pad.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScratchpadWriteReply {
    /// The pad NOTE written or sealed; absent when a seal found no pad.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pad: Option<EntityId>,
    /// Whether the pad is now sealed.
    pub sealed: bool,
    /// The actor's prior pad, sealed because this line opened a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_prior: Option<EntityId>,
}

/// One pad line a recall matched, in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScratchpadRecallReplyLine {
    /// The line's place in the pad, from 0 for the oldest.
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark: Option<ScratchpadRecallMark>,
    pub pin: bool,
    pub text: String,
}

/// What the recall found in the session's pad.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScratchpadRecallReply {
    /// The pad searched; absent when the session has no pad.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pad: Option<EntityId>,
    /// Whether the pad is sealed.
    pub sealed: bool,
    /// How many lines matched; `lines` holds the newest
    /// [`crate::context_board::SCRATCHPAD_RECALL_LINES`] of them.
    pub matched: usize,
    /// The newest matching lines in full, newest first.
    pub lines: Vec<ScratchpadRecallReplyLine>,
}

impl From<ScratchpadRecallLine> for ScratchpadRecallReplyLine {
    fn from(line: ScratchpadRecallLine) -> Self {
        Self {
            index: line.index,
            mark: line.mark.map(|mark| match mark {
                ScratchpadMark::Keep => ScratchpadRecallMark::Keep,
                ScratchpadMark::Scratch => ScratchpadRecallMark::Scratch,
            }),
            pin: line.pin,
            text: line.text,
        }
    }
}

impl From<Option<ScratchpadRecall>> for ScratchpadRecallReply {
    /// A session with no pad answers no pad, unsealed, with nothing matched.
    fn from(recall: Option<ScratchpadRecall>) -> Self {
        match recall {
            Some(recall) => Self {
                pad: Some(recall.pad),
                sealed: recall.sealed,
                matched: recall.matched,
                lines: recall.lines.into_iter().map(Into::into).collect(),
            },
            None => Self {
                pad: None,
                sealed: false,
                matched: 0,
                lines: Vec::new(),
            },
        }
    }
}

/// `self.focus.scratchpad.recall`: the lines of the bound actor's session
/// pad that hold every query word, through the engine's own recall
/// ([`Memory::scratchpad_recall`]), which checks the session and the query.
pub fn scratchpad_recall_reply(
    memory: &Memory<'_>,
    input: &ScratchpadRecallRequest,
) -> MemoryResult<ScratchpadRecallReply> {
    memory
        .scratchpad_recall(&input.session_id, &input.query)
        .map(ScratchpadRecallReply::from)
}

/// `self.focus.scratchpad.append`: one line on the bound actor's session
/// pad through [`Memory::scratchpad_append`], which checks the session and
/// the line, refuses a sealed pad, and opens the pad (sealing the actor's
/// prior one) on the session's first line.
pub fn scratchpad_append_reply(
    memory: &Memory<'_>,
    input: &ScratchpadAppendRequest,
) -> MemoryResult<ScratchpadWriteReply> {
    let receipt = memory.scratchpad_append(
        &input.session_id,
        &input.text,
        input.mark.map(ScratchpadMark::from),
        input.pin,
    )?;
    Ok(ScratchpadWriteReply {
        pad: Some(receipt.pad),
        sealed: false,
        sealed_prior: receipt.sealed_prior,
    })
}

/// `self.focus.scratchpad.seal`: seals the bound actor's session pad
/// through [`Memory::scratchpad_seal`], which ends the run's pad; a session
/// with no pad answers no pad, unsealed.
pub fn scratchpad_seal_reply(
    memory: &Memory<'_>,
    input: &ScratchpadSealRequest,
) -> MemoryResult<ScratchpadWriteReply> {
    let pad = memory.scratchpad_seal(&input.session_id)?;
    Ok(ScratchpadWriteReply {
        pad,
        sealed: pad.is_some(),
        sealed_prior: None,
    })
}
