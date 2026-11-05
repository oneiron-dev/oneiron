//! Folds (ARCH-0067 §2.2): an agent marks spans of its own run's log at any
//! time, `self.compact` folds every pending mark in one batch, each fold
//! leaves one stub where its span was, and `self.unfold` appends a fold's raw
//! turns back at the end of the log. The vault keeps every turn: a fold is a
//! typed record over steps, never a rewrite of them, and no code path parses
//! a stub back.
//!
//! One ledger per run holds its marks, the agent's compact ask, its folds and
//! its unfold appends. The run's own verbs write it; the executor applies the
//! marks at a step boundary, through the run's compaction seat.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;

/// `self.fold`: marks steps `from..=through` of this run's log. The mark
/// waits as pending; the log does not change until `self.compact`, or the
/// next compaction breakpoint, folds it.
///
/// The guest call is positional, `self.fold(span, {note?})` (ARCH-0067
/// #folds, Docs Q25): its wire input is the span alone, `[from, through]`, or
/// the span and its options, `[[from, through], {note?}]`. This struct is the
/// normalized mark both decode into.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "FoldMarkWire")]
pub struct FoldMarkInput {
    pub from: u64,
    pub through: u64,
    /// What the fold's summary must keep.
    #[serde(default)]
    pub note: Option<String>,
}

/// The two positional wire spellings of one `self.fold` call.
#[derive(Deserialize)]
#[serde(untagged)]
enum FoldMarkWire {
    Span([u64; 2]),
    SpanWithOptions([u64; 2], FoldMarkOptions),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FoldMarkOptions {
    #[serde(default)]
    pub note: Option<String>,
}

impl TryFrom<FoldMarkWire> for FoldMarkInput {
    type Error = std::convert::Infallible;

    fn try_from(wire: FoldMarkWire) -> std::result::Result<Self, Self::Error> {
        let ([from, through], note) = match wire {
            FoldMarkWire::Span(span) => (span, None),
            FoldMarkWire::SpanWithOptions(span, options) => (span, options.note),
        };
        Ok(Self {
            from,
            through,
            note,
        })
    }
}

/// `self.compact`: folds every pending mark in one batch, and compacts the
/// run's settled steps, at the next step boundary.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldCompactInput {
    /// What the summaries must keep.
    #[serde(default)]
    pub note: Option<String>,
}

/// `self.unfold`: appends one fold's raw turns at the end of the log.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldUnfoldInput {
    /// The fold's handle, such as `f1`.
    pub fold: String,
}

/// `self.folds`: the run's folds and its pending marks.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldsInput {}

/// One fold verb call. Run and step come from the host binding, never from
/// the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum SelfFoldCall {
    Mark {
        from: u64,
        through: u64,
        note: Option<String>,
    },
    Compact {
        note: Option<String>,
    },
    Unfold {
        fold: u64,
    },
    List,
    /// `describe({fold})`.
    Describe {
        fold: u64,
    },
}

/// What a fold verb answers under `output`: its typed answer, or the
/// ledger's refusal, which changes nothing and which the agent can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum FoldReply<T> {
    Answer(T),
    Refused { error: String },
}

/// `self.fold`'s answer: the pending mark it made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldMarked {
    pub fold: String,
    pub from: u64,
    pub through: u64,
    /// Always true: the log does not change until a pass folds it.
    pub pending: bool,
}

/// `self.compact`'s answer: the marks its batch folds, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldCompactAsked {
    pub pending: Vec<String>,
    pub applies: String,
}

/// `self.unfold`'s answer: the fold whose raw turns come back after this
/// step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldUnfolded {
    pub fold: String,
    pub from: u64,
    pub through: u64,
    pub unfolded_after_step: u64,
}

/// `self.folds`' answer: the run's folds, its pending marks, and whether a
/// compact is asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldList {
    pub folds: Vec<FoldSpan>,
    pub pending: Vec<FoldPending>,
    pub compact_asked: bool,
}

/// One fold in [`FoldList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldSpan {
    pub fold: String,
    pub from: u64,
    pub through: u64,
}

/// One pending mark in [`FoldList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldPending {
    pub fold: String,
    pub from: u64,
    pub through: u64,
    pub note: Option<String>,
    /// Why its last pass did not fold it.
    pub failed: Option<String>,
}

/// `describe({fold})`'s answer: a fold whole, or a mark still pending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum FoldDescription {
    Folded {
        fold: String,
        from: u64,
        through: u64,
        /// The stub the log shows in the span's place.
        stub: String,
        source: String,
        /// Every id the span's turns name.
        ids: Vec<String>,
        /// Every result handle the span covers.
        handles: Vec<String>,
    },
    Pending {
        fold: String,
        from: u64,
        through: u64,
        /// Always true.
        pending: bool,
        note: Option<String>,
        failed: Option<String>,
    },
}

impl SelfFoldCall {
    /// Whether the call changes the run's ledger.
    #[must_use]
    pub const fn writes(&self) -> bool {
        matches!(
            self,
            Self::Mark { .. } | Self::Compact { .. } | Self::Unfold { .. }
        )
    }
}

/// A fold's handle as the agent reads it: `f1`.
#[must_use]
pub fn fold_handle(fold: u64) -> String {
    format!("f{fold}")
}

/// The fold a handle names: `f1`, or a bare `1`.
pub fn parse_fold_handle(handle: &str) -> oneiron_base::error::Result<u64> {
    let digits = handle.trim().strip_prefix('f').unwrap_or(handle.trim());
    digits
        .parse::<u64>()
        .ok()
        .filter(|fold| *fold > 0)
        .ok_or_else(|| {
            oneiron_base::error::Error::InvalidConfig(format!("`{handle}` names no fold"))
        })
}

/// A pending mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldMark {
    pub fold: u64,
    pub from: u64,
    pub through: u64,
    pub note: Option<String>,
    /// Why its last pass did not fold it. A failed mark waits for the
    /// agent's next `self.compact`, not for the next breakpoint.
    pub failed: Option<String>,
}

/// `self.compact`'s ask, until a pass takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldCompactAsk {
    pub note: Option<String>,
}

/// The most ids a stub lists itself; `describe({fold})` lists them all.
pub const STUB_IDS: usize = 64;

/// Frame marks a summary may not forge: the record marks and the compacted
/// frame.
pub fn escape_compacted_text(text: &str) -> String {
    text.replace("<exec>", r"<\exec>")
        .replace("</exec>", r"<\/exec>")
        .replace("<console>", r"<\console>")
        .replace("</console>", r"<\/console>")
        .replace("<compacted", r"<\compacted")
        .replace("</compacted", r"<\/compacted")
}

/// One unfold: the fold's raw turns render just before step `at`, where the
/// end of the log was when the agent unfolded it, and stay there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldUnfold {
    pub fold: u64,
    pub at: u64,
}
