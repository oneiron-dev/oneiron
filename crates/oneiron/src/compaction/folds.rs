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
    note: Option<String>,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
pub fn parse_fold_handle(handle: &str) -> crate::Result<u64> {
    let digits = handle.trim().strip_prefix('f').unwrap_or(handle.trim());
    digits
        .parse::<u64>()
        .ok()
        .filter(|fold| *fold > 0)
        .ok_or_else(|| crate::Error::InvalidConfig(format!("`{handle}` names no fold")))
}

/// One run's folds, in the order they were made.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldLedger {
    /// The last handle number given out; a mark keeps its number as a fold.
    pub last: u64,
    pub marks: Vec<FoldMark>,
    /// The agent asked for a compaction that has not started yet.
    pub compact: Option<FoldCompactAsk>,
    pub folds: Vec<FoldRecord>,
    pub unfolds: Vec<FoldUnfold>,
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

/// One fold, written once when its batch landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldRecord {
    pub fold: u64,
    pub from: u64,
    pub through: u64,
    /// The one stub the log shows in the span's place, byte for byte.
    pub stub: String,
    /// The accepted summary: model output, written from the span's own turns.
    pub summary: String,
    /// The ids the span's turns name.
    pub ids: Vec<String>,
    /// The result handles the span covers: each step's output and every
    /// stored result its turns name.
    pub handles: Vec<String>,
}

/// One unfold: the fold's raw turns render just before step `at`, where the
/// end of the log was when the agent unfolded it, and stay there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldUnfold {
    pub fold: u64,
    pub at: u64,
}

impl FoldLedger {
    /// The fold that covers step `seq`, if one does.
    #[must_use]
    pub fn covering(&self, seq: u64) -> Option<&FoldRecord> {
        self.folds
            .iter()
            .find(|fold| fold.from <= seq && seq <= fold.through)
    }

    #[must_use]
    pub fn fold(&self, fold: u64) -> Option<&FoldRecord> {
        self.folds.iter().find(|record| record.fold == fold)
    }

    /// Whether nothing folds, is marked or is unfolded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.folds.is_empty() && self.marks.is_empty() && self.unfolds.is_empty()
    }

    /// The marks a pass at this boundary folds: each whose steps have all run
    /// and are not already in the compacted prefix, cut to its steps past
    /// that prefix. A failed mark waits for the agent's next ask.
    #[must_use]
    pub fn applicable(
        &self,
        completed: u64,
        prefix_end: Option<u64>,
        asked: bool,
    ) -> Vec<FoldMark> {
        self.marks
            .iter()
            .filter(|mark| mark.through < completed && (asked || mark.failed.is_none()))
            .filter_map(|mark| {
                let from = prefix_end.map_or(mark.from, |end| mark.from.max(end.saturating_add(1)));
                (from <= mark.through).then(|| FoldMark {
                    from,
                    ..mark.clone()
                })
            })
            .collect()
    }

    /// One landed batch: each accepted fold replaces its mark, each failed
    /// mark keeps why. Every fold of the batch becomes visible at once.
    pub fn land(&mut self, landed: Vec<FoldRecord>, failed: &[(u64, String)]) {
        for record in landed {
            self.marks.retain(|mark| mark.fold != record.fold);
            if self.fold(record.fold).is_none() {
                self.folds.push(record);
            }
        }
        for (fold, why) in failed {
            if let Some(mark) = self.marks.iter_mut().find(|mark| mark.fold == *fold) {
                mark.failed = Some(why.clone());
            }
        }
    }

    /// Ends every pending ask this run cannot answer, saying why.
    pub fn refuse_pending(&mut self, why: &str) -> bool {
        let mut changed = self.compact.take().is_some();
        for mark in self.marks.iter_mut().filter(|mark| mark.failed.is_none()) {
            mark.failed = Some(why.to_owned());
            changed = true;
        }
        changed
    }

    /// The dynamic line the log's tail carries: only fold handles, spans and
    /// pending marks, never a summary (the stubs hold those, in the cached
    /// log).
    #[must_use]
    pub fn board_line(&self) -> Option<String> {
        if self.folds.is_empty() && self.marks.is_empty() {
            return None;
        }
        let span = |fold: u64, from: u64, through: u64| {
            format!("{} t{from}–t{through}", fold_handle(fold))
        };
        let mut line = String::from("Folds:");
        if self.folds.is_empty() {
            line.push_str(" none");
        }
        for fold in &self.folds {
            line.push(' ');
            line.push_str(&span(fold.fold, fold.from, fold.through));
            line.push(';');
        }
        if !self.marks.is_empty() {
            line.push_str(" pending marks:");
            for mark in &self.marks {
                line.push(' ');
                line.push_str(&span(mark.fold, mark.from, mark.through));
                if mark.failed.is_some() {
                    line.push_str(" (failed)");
                }
                line.push(';');
            }
            if self.compact.is_some() {
                line.push_str(" folding at the next step.");
            }
        }
        Some(line.trim_end_matches(';').to_owned())
    }

    /// Answers one call made during step `step`, with the run's compacted
    /// prefix ending at `prefix_end`. A call the ledger refuses changes
    /// nothing and answers `{"error": ...}`, which the agent can act on.
    pub fn answer(&mut self, call: &SelfFoldCall, step: u64, prefix_end: Option<u64>) -> Value {
        match self.try_answer(call, step, prefix_end) {
            Ok(value) => value,
            Err(error) => json!({ "error": error }),
        }
    }

    fn try_answer(
        &mut self,
        call: &SelfFoldCall,
        step: u64,
        prefix_end: Option<u64>,
    ) -> Result<Value, String> {
        match call {
            SelfFoldCall::Mark {
                from,
                through,
                note,
            } => {
                let (from, through) = (*from, *through);
                if from > through {
                    return Err(format!("a span runs forward: t{from}–t{through} is empty"));
                }
                if through > step {
                    return Err(format!(
                        "step {through} has not run yet; this is step {step}"
                    ));
                }
                if prefix_end.is_some_and(|end| through <= end) {
                    return Err(format!(
                        "steps t0–t{} are already compacted",
                        prefix_end.unwrap_or_default()
                    ));
                }
                let overlap = self
                    .folds
                    .iter()
                    .map(|fold| (fold.fold, fold.from, fold.through))
                    .chain(
                        self.marks
                            .iter()
                            .map(|mark| (mark.fold, mark.from, mark.through)),
                    )
                    .find(|(_, first, last)| from <= *last && *first <= through);
                if let Some((fold, first, last)) = overlap {
                    return Err(format!(
                        "t{from}–t{through} overlaps {} (t{first}–t{last})",
                        fold_handle(fold)
                    ));
                }
                self.last = self.last.saturating_add(1);
                self.marks.push(FoldMark {
                    fold: self.last,
                    from,
                    through,
                    note: note.clone(),
                    failed: None,
                });
                Ok(json!({
                    "fold": fold_handle(self.last),
                    "from": from,
                    "through": through,
                    "pending": true,
                }))
            }
            SelfFoldCall::Compact { note } => {
                let note = match (self.compact.take().and_then(|ask| ask.note), note) {
                    (Some(earlier), Some(note)) => Some(format!("{earlier}\n{note}")),
                    (earlier, note) => note.clone().or(earlier),
                };
                self.compact = Some(FoldCompactAsk { note });
                Ok(json!({
                    "pending": self.marks.iter().map(|mark| fold_handle(mark.fold)).collect::<Vec<_>>(),
                    "applies": "at the next step boundary",
                }))
            }
            SelfFoldCall::Unfold { fold } => {
                let Some(record) = self.fold(*fold) else {
                    return Err(if self.marks.iter().any(|mark| mark.fold == *fold) {
                        format!(
                            "{} is a pending mark; nothing is folded yet",
                            fold_handle(*fold)
                        )
                    } else {
                        format!("no fold {}", fold_handle(*fold))
                    });
                };
                let (from, through) = (record.from, record.through);
                let at = step.saturating_add(1);
                if !self
                    .unfolds
                    .iter()
                    .any(|append| append.fold == *fold && append.at == at)
                {
                    self.unfolds.push(FoldUnfold { fold: *fold, at });
                }
                Ok(json!({
                    "fold": fold_handle(*fold),
                    "from": from,
                    "through": through,
                    "unfolded_after_step": step,
                }))
            }
            SelfFoldCall::List => Ok(json!({
                "folds": self.folds.iter().map(|fold| json!({
                    "fold": fold_handle(fold.fold),
                    "from": fold.from,
                    "through": fold.through,
                })).collect::<Vec<_>>(),
                "pending": self.marks.iter().map(|mark| json!({
                    "fold": fold_handle(mark.fold),
                    "from": mark.from,
                    "through": mark.through,
                    "note": mark.note,
                    "failed": mark.failed,
                })).collect::<Vec<_>>(),
                "compact_asked": self.compact.is_some(),
            })),
            SelfFoldCall::Describe { fold } => {
                if let Some(record) = self.fold(*fold) {
                    return Ok(json!({
                        "fold": fold_handle(record.fold),
                        "from": record.from,
                        "through": record.through,
                        "stub": record.stub,
                        "ids": record.ids,
                        "handles": record.handles,
                    }));
                }
                let mark = self
                    .marks
                    .iter()
                    .find(|mark| mark.fold == *fold)
                    .ok_or_else(|| format!("no fold {}", fold_handle(*fold)))?;
                Ok(json!({
                    "fold": fold_handle(mark.fold),
                    "from": mark.from,
                    "through": mark.through,
                    "pending": true,
                    "note": mark.note,
                    "failed": mark.failed,
                }))
            }
        }
    }
}
