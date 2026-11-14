//! Moved from `crates/oneiron/src/compaction/folds.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::compaction::fold_kinds::FoldByKind;
use crate::compaction::fold_kinds::FoldKind;
use crate::compaction::fold_kinds::FoldedOutput;
use serde::Deserialize;
use serde::Serialize;

/// `self.fold`: marks steps `from..=through` of this run's log. The mark
/// waits as pending; the log does not change until `self.compact`, or the
/// next compaction breakpoint, folds it.
///
/// The guest call is positional, `self.fold(span, {note?})` (ARCH-0067
/// #folds, Docs Q25): its wire input is the span alone, `[from, through]`, or
/// the span and its options, `[[from, through], {note?}]`. A fold by kind
/// (owner 2026-11-03) is one object, `{kind, before?, from?, through?,
/// note?}`: it folds only that kind of content in each step of its span,
/// such as `self.fold({kind: "repl_output", before: "t40"})`. This struct is
/// the normalized mark every spelling decodes into.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "FoldMarkWire")]
pub struct FoldMarkInput {
    pub from: u64,
    /// The last step; a fold by kind with no bound reaches the current step.
    pub through: u64,
    /// What the fold's summary must keep; on a fold by kind, the agent's
    /// own note on it.
    #[serde(default)]
    pub note: Option<String>,
    /// The one kind of content the fold folds in each step; `None` folds
    /// whole steps.
    #[serde(default)]
    pub kind: Option<FoldKind>,
}

/// The wire spellings of one `self.fold` call.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum FoldMarkWire {
    Span([u64; 2]),
    SpanWithOptions([u64; 2], FoldMarkOptions),
    Kind(FoldByKind),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoldMarkOptions {
    #[serde(default)]
    note: Option<String>,
}

impl TryFrom<FoldMarkWire> for FoldMarkInput {
    type Error = String;

    fn try_from(wire: FoldMarkWire) -> std::result::Result<Self, Self::Error> {
        let ([from, through], note) = match wire {
            FoldMarkWire::Span(span) => (span, None),
            FoldMarkWire::SpanWithOptions(span, options) => (span, options.note),
            FoldMarkWire::Kind(wire) => return wire.normalize(),
        };
        Ok(Self {
            from,
            through,
            note,
            kind: None,
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

/// What a fold verb answers under `output`: its typed answer, or the
/// ledger's refusal, which changes nothing and which the agent can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum FoldReply<T> {
    Answer(T),
    Refused { error: String },
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
    /// The kind it folds; absent on a whole-step fold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<FoldKind>,
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
    /// The kind it folds; absent on a whole-step mark.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<FoldKind>,
}

/// `describe({fold})`'s answer: a fold whole, or a mark still pending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum FoldDescription {
    Folded {
        fold: String,
        from: u64,
        through: u64,
        /// The stub the log shows in the span's place; for a fold by kind,
        /// its head line, and `outputs` the stub each folded step shows.
        stub: String,
        source: String,
        /// Every id the span's turns name.
        ids: Vec<String>,
        /// Every result handle the span covers.
        handles: Vec<String>,
        /// The kind it folds; absent on a whole-step fold.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<FoldKind>,
        /// The agent's own note on a fold by kind.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        /// Each step a fold by kind folded, with what its stub keeps.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        outputs: Vec<FoldedOutput>,
    },
    Pending {
        fold: String,
        from: u64,
        through: u64,
        /// Always true.
        pending: bool,
        note: Option<String>,
        failed: Option<String>,
        /// The kind it folds; absent on a whole-step mark.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<FoldKind>,
    },
}

/// One unfold: the fold's raw turns render just before step `at`, where the
/// end of the log was when the agent unfolded it, and stay there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldUnfold {
    pub fold: u64,
    pub at: u64,
}
