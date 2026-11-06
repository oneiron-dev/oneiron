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

/// Most bytes of the note an agent attaches to a fold.
pub const BOARD_FOLD_NOTE_MAX_BYTES: usize = 512;
/// Most rows one fold keeps open.
pub const BOARD_FOLD_KEEP_MAX: usize = 64;
/// Most sections one layout names.
pub const BOARD_LAYOUT_SECTIONS_MAX: usize = 32;
/// Longest section key a layout may name.
pub const BOARD_SECTION_KEY_MAX_BYTES: usize = 32;
/// Most statuses one section filter names.
pub const BOARD_FILTER_STATUSES_MAX: usize = 8;
/// Rows a fold summary names beside one count before it adds `+N`.
pub const FOLD_ATTENTION_ROWS_MAX: usize = 3;

/// The layout key of a section named `name`: its first word, lower case.
pub(crate) fn section_layout_key(name: &str) -> String {
    name.split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// One actor's board layout: the sections it sized, folded or filtered, by
/// layout key. A section the layout does not name renders as the engine
/// lays it out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardLayout {
    /// Each laid-out section by its key (`tasks`, `memories`, `worlds`,
    /// `skills`, `room`, `inbox`, `scratchpad`, `readers`, `packs`, or a
    /// plugin section's first name word, lower case).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sections: BTreeMap<String, SectionLayout>,
}

/// How one section renders on its actor's board.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SectionLayout {
    /// The percent of the board cap this section may fill, 0-100. Absent,
    /// the section has no share of its own and renders as the engine lays
    /// it out. `0` is a literal zero: the section shows its count line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_pct: Option<u8>,
    /// The section is folded to one summary line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fold: Option<SectionFold>,
    /// Which rows the section shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<SectionFilter>,
}

impl SectionLayout {
    fn is_empty(&self) -> bool {
        self.share_pct.is_none() && self.fold.is_none() && self.filter.is_none()
    }
}

/// One folded section: the agent's note, the rows it keeps open, and the
/// section's counts when the fold applied.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SectionFold {
    /// The agent's own note, shown on the fold line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Rows kept open under the fold line, by their typed id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keep: Vec<EntityId>,
    /// The section's counts when this fold applied, summed over every
    /// section of its key. The engine sets it when the fold's batch applies;
    /// a staged fold carries none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<FoldBaseline>,
    /// Each section's own counts when this fold applied, by section name
    /// (one key, such as `memories`, can span one section per world). Each
    /// fold line compares its section with its own entry; a section with no
    /// entry had no rows then. The engine sets it with `baseline`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub section_baselines: BTreeMap<String, FoldBaseline>,
}

/// A section's counts at one moment: its row total and each status count.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldBaseline {
    pub total: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counts: BTreeMap<String, u64>,
}

/// Which rows one section shows (ARCH-0067 §5: any read view filters by who
/// made its rows). A filter narrows the view only: it never widens a read,
/// and a row it hides still counts in the section's fold summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SectionFilter {
    /// Whose rows the section shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub who: Option<BoardWhoFilter>,
    /// The row statuses the section shows, such as TASKS' `running`,
    /// `scheduled`, `queued`, `done` and `failed`. Empty shows every status.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status: Vec<String>,
}

/// Whose rows a section shows: one actor, one actor class, or one group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BoardWhoFilter {
    /// Rows that are the layout actor's own.
    Mine,
    /// Rows of one actor.
    Actor { actor: EntityId },
    /// Rows of one actor class.
    Class { class: BoardActorClass },
    /// Rows of the members of one group: a role or a project roster.
    Group { group: EntityId },
}

impl BoardWhoFilter {
    /// Whether a row of `who` passes this filter on `actor`'s board.
    /// `members` holds a group filter's roster; `class_of` names the class
    /// of a person (`None` for an id no person row names, which counts as a
    /// system actor). A row with no `who` passes no `who` filter.
    pub fn matches(
        &self,
        who: Option<EntityId>,
        actor: Option<EntityId>,
        members: &std::collections::BTreeSet<EntityId>,
        class_of: impl Fn(EntityId) -> Option<BoardActorClass>,
    ) -> bool {
        let Some(who) = who else {
            return false;
        };
        match self {
            Self::Mine => actor == Some(who),
            Self::Actor { actor } => *actor == who,
            Self::Class { class } => class_of(who).unwrap_or(BoardActorClass::System) == *class,
            Self::Group { .. } => members.contains(&who),
        }
    }

    /// The group this filter names, if it is a group filter.
    #[must_use]
    pub fn group(&self) -> Option<EntityId> {
        match self {
            Self::Group { group } => Some(*group),
            _ => None,
        }
    }
}

/// The actor classes a board filter names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BoardActorClass {
    Human,
    Agent,
    System,
}

impl BoardActorClass {
    /// The edge actor class this filter class names.
    #[must_use]
    pub const fn edge_class(self) -> crate::EdgeActorClass {
        match self {
            Self::Human => crate::EdgeActorClass::Human,
            Self::Agent => crate::EdgeActorClass::Agent,
            Self::System => crate::EdgeActorClass::System,
        }
    }
}

/// Why a staged layout was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BoardLayoutError {
    #[error("a board layout names at most {max} sections")]
    TooManySections { max: usize },
    #[error("board section key {key:?} is not a section key")]
    InvalidKey { key: String },
    #[error("board section shares sum to {total}%, past the cap")]
    SharesPastCap { total: u32 },
    #[error("board section {key:?} share {share}% is past 100%")]
    SharePastCap { key: String, share: u8 },
    #[error("board fold note of {key:?} is {bytes} bytes, past {max}")]
    NoteTooLong {
        key: String,
        bytes: usize,
        max: usize,
    },
    #[error("board fold of {key:?} keeps {count} rows, past {max}")]
    TooManyKept {
        key: String,
        count: usize,
        max: usize,
    },
    #[error("board filter of {key:?} names {count} statuses, past {max}")]
    TooManyStatuses {
        key: String,
        count: usize,
        max: usize,
    },
    #[error("board filter of {key:?} names status {status:?}, not a status token")]
    InvalidStatus { key: String, status: String },
}

/// Whether `key` is a section key: 1-32 bytes of lower-case ASCII letters,
/// digits, `_`, `-` or `.`, starting with a letter.
#[must_use]
pub fn is_section_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= BOARD_SECTION_KEY_MAX_BYTES
        && key.starts_with(|c: char| c.is_ascii_lowercase())
        && key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.'))
}

impl BoardLayout {
    /// Checks the layout's shape: its keys, its shares (which never sum
    /// past the cap), each fold's note and kept rows, and each filter.
    pub fn validate(&self) -> Result<(), BoardLayoutError> {
        if self.sections.len() > BOARD_LAYOUT_SECTIONS_MAX {
            return Err(BoardLayoutError::TooManySections {
                max: BOARD_LAYOUT_SECTIONS_MAX,
            });
        }
        let mut total: u32 = 0;
        for (key, section) in &self.sections {
            if !is_section_key(key) {
                return Err(BoardLayoutError::InvalidKey { key: key.clone() });
            }
            if let Some(share) = section.share_pct {
                if share > 100 {
                    return Err(BoardLayoutError::SharePastCap {
                        key: key.clone(),
                        share,
                    });
                }
                total += u32::from(share);
            }
            if let Some(fold) = &section.fold {
                if let Some(note) = &fold.note
                    && note.len() > BOARD_FOLD_NOTE_MAX_BYTES
                {
                    return Err(BoardLayoutError::NoteTooLong {
                        key: key.clone(),
                        bytes: note.len(),
                        max: BOARD_FOLD_NOTE_MAX_BYTES,
                    });
                }
                if fold.keep.len() > BOARD_FOLD_KEEP_MAX {
                    return Err(BoardLayoutError::TooManyKept {
                        key: key.clone(),
                        count: fold.keep.len(),
                        max: BOARD_FOLD_KEEP_MAX,
                    });
                }
            }
            if let Some(filter) = &section.filter {
                if filter.status.len() > BOARD_FILTER_STATUSES_MAX {
                    return Err(BoardLayoutError::TooManyStatuses {
                        key: key.clone(),
                        count: filter.status.len(),
                        max: BOARD_FILTER_STATUSES_MAX,
                    });
                }
                if let Some(status) = filter.status.iter().find(|status| !is_section_key(status)) {
                    return Err(BoardLayoutError::InvalidStatus {
                        key: key.clone(),
                        status: status.clone(),
                    });
                }
            }
        }
        if total > 100 {
            return Err(BoardLayoutError::SharesPastCap { total });
        }
        Ok(())
    }

    /// The layout of one section, if the layout names it.
    #[must_use]
    pub fn section(&self, key: &str) -> Option<&SectionLayout> {
        self.sections.get(key)
    }

    /// The token share of `key` under `cap_tok`, when the layout gives it one.
    #[must_use]
    pub fn share_tok(&self, key: &str, cap_tok: usize) -> Option<usize> {
        let share = self.section(key)?.share_pct?;
        Some(cap_tok.saturating_mul(usize::from(share)) / 100)
    }

    /// The fold of `key`, when the layout folds it.
    #[must_use]
    pub fn fold(&self, key: &str) -> Option<&SectionFold> {
        self.section(key)?.fold.as_ref()
    }

    /// The filter of `key`, when the layout filters it.
    #[must_use]
    pub fn filter(&self, key: &str) -> Option<&SectionFilter> {
        self.section(key)?.filter.as_ref()
    }

    /// The rows a producer should project for `key`: `default_rows` when
    /// the section has no share, else enough rows to fill its share at one
    /// token a row, never fewer than `default_rows`. The frame then fits
    /// the projected rows to the share exactly.
    #[must_use]
    pub fn row_allotment(&self, key: &str, cap_tok: usize, default_rows: usize) -> usize {
        self.share_tok(key, cap_tok)
            .map_or(default_rows, |share| share.max(default_rows))
    }

    /// Edits one section's layout in place; a section left with no share,
    /// fold or filter leaves the layout.
    pub fn edit(&mut self, key: &str, edit: impl FnOnce(&mut SectionLayout)) {
        let section = self.sections.entry(key.to_owned()).or_default();
        edit(section);
        if section.is_empty() {
            self.sections.remove(key);
        }
    }

    /// This layout with each named fold that carries no baseline given the
    /// counts `counts` holds for its key: the key's sum and each section's
    /// own.
    #[must_use]
    pub fn with_fold_baselines(mut self, counts: &BTreeMap<String, FoldCounts>) -> Self {
        for (key, section) in &mut self.sections {
            if let Some(fold) = &mut section.fold
                && fold.baseline.is_none()
            {
                let counts = counts.get(key);
                fold.baseline = counts.map(|counts| counts.total.clone());
                fold.section_baselines = counts
                    .map(|counts| counts.sections.clone())
                    .unwrap_or_default();
            }
        }
        self
    }
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

/// One folded key's live counts at one render: summed over its sections,
/// and each section's own by name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FoldCounts {
    /// The counts summed over every section of the key.
    pub total: FoldBaseline,
    /// Each section's own counts, by section name.
    pub sections: BTreeMap<String, FoldBaseline>,
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
