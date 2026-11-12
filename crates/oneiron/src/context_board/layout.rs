//! The agent's own board layout (BOARD-LAYOUT = A, owner 2026-11-03 20:25).
//!
//! The owner or harness sets the board cap; the agent lays its board out
//! inside it. Each section may take a share of the cap, fold to one line the
//! engine builds from live typed state, and filter its rows. A layout belongs
//! to one actor and persists across sessions; a new fork starts from its
//! parent's layout and keeps its own changes. Changes stage as one pending
//! batch and apply at the next turn, so the board's cache breaks at most once
//! per batch (ARCH-0067 §2.2).
//!
//! A fold is a view setting, not a removal: the section stays live, its
//! summary is recomputed every render, and `describe` still opens it. PINNED
//! rows and the legend never fold, and a pinned section takes no layout.
//! Shares never sum past the cap; when the board still overflows, the
//! canonical shed order applies unchanged (ARCH-0067 §3).
//!
//! Applying a layout is a pure function of typed sections plus the layout:
//! no store, cache, session or clock is read, and no rendered text is
//! parsed. Kept rows are matched by the typed ids their producer set.

use super::frame::BoardSection;
use crate::EntityId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[doc(hidden)]
pub use oneiron_verb_wire::context_board::layout::{
    BOARD_FILTER_STATUSES_MAX, BOARD_FOLD_KEEP_MAX, BOARD_FOLD_NOTE_MAX_BYTES,
    BOARD_LAYOUT_SECTIONS_MAX, BOARD_SECTION_KEY_MAX_BYTES, BoardActorClass, BoardLayout,
    BoardLayoutError, BoardWhoFilter, FoldBaseline, FoldCounts, SectionFilter, SectionFold,
    SectionLayout, is_section_key,
};

/// Rows a fold summary names beside one count before it adds `+N`.
pub const FOLD_ATTENTION_ROWS_MAX: usize = 3;

/// The layout key of a section named `name`: its first word, lower case.
pub(crate) fn section_layout_key(name: &str) -> String {
    name.split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// A section's live state as its fold line shows it, built by its producer
/// from typed state every render, with no model call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FoldSummary {
    /// Rows the live section holds, before any window or filter.
    pub total: usize,
    /// Counts by status or kind, in line order; a zero count is not shown.
    pub counts: Vec<FoldCount>,
}

/// One count on a fold line, with the few rows that need attention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldCount {
    /// What is counted: `running`, `failed`, `asks you`, `active`.
    pub label: String,
    pub count: usize,
    /// Short mentions of rows that need attention (`<id> <label>`), shown
    /// after the count; empty for a plain count.
    pub rows: Vec<String>,
}

impl FoldSummary {
    /// A plain summary of `total` rows.
    #[must_use]
    pub fn total(total: usize) -> Self {
        Self {
            total,
            counts: Vec::new(),
        }
    }

    /// The summary with one more count.
    #[must_use]
    pub fn count(mut self, label: impl Into<String>, count: usize) -> Self {
        self.counts.push(FoldCount {
            label: label.into(),
            count,
            rows: Vec::new(),
        });
        self
    }

    /// The summary with one more count and its attention rows.
    #[must_use]
    pub fn count_rows(mut self, label: impl Into<String>, count: usize, rows: Vec<String>) -> Self {
        self.counts.push(FoldCount {
            label: label.into(),
            count,
            rows,
        });
        self
    }

    /// The counts a fold baseline keeps of this summary.
    #[must_use]
    pub fn baseline(&self) -> FoldBaseline {
        FoldBaseline {
            total: self.total as u64,
            counts: self
                .counts
                .iter()
                .map(|count| (count.label.clone(), count.count as u64))
                .collect(),
        }
    }
}

/// The open command a fold line names for `key`.
#[must_use]
pub fn unfold_command(key: &str) -> String {
    format!("open: self.board.unfold({{section: {key:?}}})")
}

/// One fold line: the section's total with its change since `baseline`
/// (the section's counts when the fold applied), each non-zero count with
/// its change and attention rows, the open command, then the agent's note.
/// The renderer escapes the whole line as one leaf.
#[must_use]
pub fn fold_line(
    key: &str,
    summary: &FoldSummary,
    fold: &SectionFold,
    baseline: Option<&FoldBaseline>,
) -> String {
    let mut parts = Vec::with_capacity(summary.counts.len() + 3);
    let mut head = summary.total.to_string();
    if let Some(baseline) = baseline {
        let delta = summary.total as i128 - i128::from(baseline.total);
        if delta != 0 {
            head.push_str(&format!(" ({delta:+} since fold)"));
        }
    }
    parts.push(head);
    for count in summary.counts.iter().filter(|count| count.count > 0) {
        let mut part = format!("{} {}", count.count, count.label);
        if let Some(before) = baseline.and_then(|baseline| baseline.counts.get(&count.label)) {
            let delta = count.count as i128 - i128::from(*before);
            if delta != 0 {
                part.push_str(&format!(" ({delta:+})"));
            }
        }
        if !count.rows.is_empty() {
            let shown: Vec<&str> = count
                .rows
                .iter()
                .take(FOLD_ATTENTION_ROWS_MAX)
                .map(String::as_str)
                .collect();
            part.push_str(": ");
            part.push_str(&shown.join(", "));
            let more = count.count.saturating_sub(shown.len());
            if more > 0 {
                part.push_str(&format!(" +{more}"));
            }
        }
        parts.push(part);
    }
    parts.push(unfold_command(key));
    if let Some(note) = fold.note.as_deref().filter(|note| !note.is_empty()) {
        parts.push(format!("note: {note}"));
    }
    parts.join(" · ")
}

/// A board with its actor's layout applied, and what applying it saw.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LaidOutBoard {
    /// The sections to render, in their original order.
    pub sections: Vec<BoardSection>,
    /// The keys whose sections render folded, in order.
    pub folded: Vec<String>,
    /// The keys whose sections a share fitted, in order.
    pub fitted: Vec<String>,
    /// Each folded key's live counts, for the baseline its fold keeps when
    /// its batch applies.
    pub fold_counts: BTreeMap<String, FoldCounts>,
}

/// Applies `layout` to `sections` under the board cap `cap_tok`. A folded
/// section renders one line beside its pinned floor and kept rows; a sized
/// section is fitted to its share (one share across every section of one
/// key, in order). A pinned section takes no layout. The canonical shed
/// order still runs over the result.
#[must_use]
pub fn apply_board_layout(
    sections: &[BoardSection],
    layout: &BoardLayout,
    cap_tok: usize,
) -> LaidOutBoard {
    let mut board = LaidOutBoard::default();
    if layout.sections.is_empty() {
        board.sections = sections.to_vec();
        return board;
    }
    let mut remaining: BTreeMap<&str, usize> = BTreeMap::new();
    for section in sections {
        let key = section.layout_key();
        if section.policy().pinned {
            board.sections.push(section.clone());
            continue;
        }
        if let Some(fold) = layout.fold(key) {
            let summary = section
                .fold_summary()
                .cloned()
                .unwrap_or_else(|| FoldSummary::total(section.detail_rows().len()));
            let counts = board.fold_counts.entry(key.to_owned()).or_default();
            counts.total.total += summary.total as u64;
            for count in &summary.counts {
                *counts.total.counts.entry(count.label.clone()).or_default() += count.count as u64;
            }
            let own = summary.baseline();
            match counts.sections.get_mut(section.name()) {
                // Two sections of one name sum, as the key's total does.
                Some(same) => {
                    same.total += own.total;
                    for (label, count) in own.counts {
                        *same.counts.entry(label).or_default() += count;
                    }
                }
                None => {
                    counts.sections.insert(section.name().to_owned(), own);
                }
            }
            // Each section compares with its own counts when the fold
            // applied; a section absent then had none. A baseline that names
            // no section compares with the key's sum.
            let absent = FoldBaseline::default();
            let baseline = if fold.section_baselines.is_empty() {
                fold.baseline.as_ref()
            } else {
                fold.baseline.as_ref().map(|_| {
                    fold.section_baselines
                        .get(section.name())
                        .unwrap_or(&absent)
                })
            };
            board
                .sections
                .push(section.folded(fold_line(key, &summary, fold, baseline), &fold.keep));
            if !board.folded.iter().any(|folded| folded == key) {
                board.folded.push(key.to_owned());
            }
            continue;
        }
        if let Some(share) = layout.share_tok(key, cap_tok) {
            let left = remaining.entry(key).or_insert(share);
            let fitted = section.fitted(*left);
            *left = left.saturating_sub(fitted.full_view_tok());
            if fitted != *section && !board.fitted.iter().any(|done| done == key) {
                board.fitted.push(key.to_owned());
            }
            board.sections.push(fitted);
            continue;
        }
        board.sections.push(section.clone());
    }
    board
}
