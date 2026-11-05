//! Core half of `compaction::folds`: its store-layer items live in `oneiron_store::compaction::folds` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::compaction::folds::*;

use crate::entity_id::EntityId;
use oneiron_contracts::claim::ClaimSource;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

/// One fold, written once when its batch landed. Its summary is the only
/// copy of its words (Docs Q23, Q24): the stub is rendered from it, and it
/// goes once a record it came from is withdrawn, while the fold keeps its
/// span and references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldRecord {
    pub fold: u64,
    pub from: u64,
    pub through: u64,
    /// The accepted summary: model output, written from the span's own
    /// turns. `None` once withdrawn.
    pub summary: Option<String>,
    /// Always [`ClaimSource::Generated`]: the host stamps the summary as
    /// model output it wrote, and no guest call sets it.
    pub source: ClaimSource,
    /// The host's byline on the summary.
    pub actor: EntityId,
    /// Every record whose words could reach the span, from the sealed
    /// request: what the summary is derived from.
    pub sources: Vec<EntityId>,
    /// The ids the span's turns name.
    pub ids: Vec<String>,
    /// The result handles the span covers: each step's output and every
    /// stored result its turns name.
    pub handles: Vec<String>,
    /// What ran a self-written fold (FIX 4465): its writer, the model, the
    /// provider's usage, the home it wore and its admitted packet's
    /// snapshot. `None` for every other writer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<super::CompactionExecution>,
}

impl FoldRecord {
    /// The one stub the log shows in the span's place: its handle and span,
    /// the accepted summary (model output), the ids its turns name that the
    /// summary does not, and a handle to every result the span covers. The
    /// same bytes at every render, so the cached log holds, until the
    /// summary is withdrawn; then it keeps only the references.
    #[must_use]
    pub fn stub(&self) -> String {
        let mut stub = format!(
            "⟨{} · t{}–t{}⟩ ",
            fold_handle(self.fold),
            self.from,
            self.through
        );
        let summary = self.summary.as_deref().unwrap_or_default();
        match &self.summary {
            Some(summary) => stub.push_str(&escape_compacted_text(summary)),
            None => stub.push_str("(summary withdrawn)"),
        }
        let ids: Vec<&str> = self
            .ids
            .iter()
            .map(String::as_str)
            .filter(|id| !summary.contains(id))
            .collect();
        if !ids.is_empty() {
            stub.push_str("\nids: ");
            stub.push_str(&ids[..ids.len().min(STUB_IDS)].join(", "));
            if ids.len() > STUB_IDS {
                stub.push_str(&format!(
                    " and {} more (describe({{fold: \"{}\"}}))",
                    ids.len() - STUB_IDS,
                    fold_handle(self.fold)
                ));
            }
        }
        for handle in &self.handles {
            stub.push('\n');
            stub.push_str(handle);
        }
        stub
    }
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
            Err(error) => json!(FoldReply::<Value>::Refused { error }),
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
                Ok(json!(FoldMarked {
                    fold: fold_handle(self.last),
                    from,
                    through,
                    pending: true,
                }))
            }
            SelfFoldCall::Compact { note } => {
                let note = match (self.compact.take().and_then(|ask| ask.note), note) {
                    (Some(earlier), Some(note)) => Some(format!("{earlier}\n{note}")),
                    (earlier, note) => note.clone().or(earlier),
                };
                self.compact = Some(FoldCompactAsk { note });
                Ok(json!(FoldCompactAsked {
                    pending: self
                        .marks
                        .iter()
                        .map(|mark| fold_handle(mark.fold))
                        .collect(),
                    applies: "at the next step boundary".to_owned(),
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
                Ok(json!(FoldUnfolded {
                    fold: fold_handle(*fold),
                    from,
                    through,
                    unfolded_after_step: step,
                }))
            }
            SelfFoldCall::List => Ok(json!(FoldList {
                folds: self
                    .folds
                    .iter()
                    .map(|fold| FoldSpan {
                        fold: fold_handle(fold.fold),
                        from: fold.from,
                        through: fold.through,
                    })
                    .collect(),
                pending: self
                    .marks
                    .iter()
                    .map(|mark| FoldPending {
                        fold: fold_handle(mark.fold),
                        from: mark.from,
                        through: mark.through,
                        note: mark.note.clone(),
                        failed: mark.failed.clone(),
                    })
                    .collect(),
                compact_asked: self.compact.is_some(),
            })),
            SelfFoldCall::Describe { fold } => {
                if let Some(record) = self.fold(*fold) {
                    return Ok(json!(FoldDescription::Folded {
                        fold: fold_handle(record.fold),
                        from: record.from,
                        through: record.through,
                        stub: record.stub(),
                        source: record.source.as_str().to_owned(),
                        ids: record.ids.clone(),
                        handles: record.handles.clone(),
                    }));
                }
                let mark = self
                    .marks
                    .iter()
                    .find(|mark| mark.fold == *fold)
                    .ok_or_else(|| format!("no fold {}", fold_handle(*fold)))?;
                Ok(json!(FoldDescription::Pending {
                    fold: fold_handle(mark.fold),
                    from: mark.from,
                    through: mark.through,
                    pending: true,
                    note: mark.note.clone(),
                    failed: mark.failed.clone(),
                }))
            }
        }
    }
}
