//! The pad line format (OF-548, ARCH-0032 #scratchpad-marks): each stored
//! line's engine-owned header read back, the SCRATCHPAD board rows, the
//! sealed pad's review and re-ask texts, and the one recall match rule.

use super::{HEADERS, SCRATCHPAD_LINE_MAX_BYTES, ScratchpadMark, clip};
use crate::context_board::{BoardFrameError, BoardSection, SectionPolicy, ShedRank, quoted_leaf};
use crate::entity_id::EntityId;
use std::ops::Range;

/// The newest unpinned lines the board shows in full.
const NEWEST_FULL: usize = 8;
/// Older lines the board folds to their first words; the rest are counted.
const FOLDED_SHOWN: usize = 16;
/// The words an older line folds to.
const FOLD_WORDS: usize = 6;

/// One stored pad line.
pub(super) struct PadLine<'a> {
    pub(super) mark: Option<ScratchpadMark>,
    pub(super) pin: bool,
    pub(super) text: &'a str,
}

pub(super) fn parse_line(line: &str) -> PadLine<'_> {
    line.strip_prefix('[')
        .and_then(|rest| rest.split_once("] "))
        .and_then(|(head, text)| {
            HEADERS
                .iter()
                .find(|(name, _, _)| *name == head)
                .map(|&(_, mark, pin)| PadLine { mark, pin, text })
        })
        .unwrap_or(PadLine {
            mark: None,
            pin: false,
            text: line,
        })
}

/// A sealed pad's markdown as the Dreamer's after-seal review reads it
/// (ARCH-0032 #scratchpad-marks): every `scratch` line blanked to spaces, so
/// it never reaches the model and every byte offset still indexes the stored
/// markdown. With it, the byte range of each `keep` line's text (after its
/// header) that holds any text.
pub(crate) fn sealed_pad_review_text(markdown: &str) -> (String, Vec<Range<usize>>) {
    let mut text = String::with_capacity(markdown.len());
    let mut keep = Vec::new();
    let mut at = 0;
    for line in markdown.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let parsed = parse_line(body);
        match parsed.mark {
            Some(ScratchpadMark::Scratch) => {
                text.extend(std::iter::repeat_n(' ', body.len()));
                text.push_str(&line[body.len()..]);
            }
            mark => {
                if mark == Some(ScratchpadMark::Keep) && !parsed.text.trim().is_empty() {
                    keep.push(at + body.len() - parsed.text.len()..at + body.len());
                }
                text.push_str(line);
            }
        }
        at += line.len();
    }
    (text, keep)
}

/// A sealed pad's markdown as the review's one re-ask reads it (FIX 2240):
/// only the lines holding a `missed` range stay; every other line is
/// blanked to spaces, so every byte offset still indexes the stored
/// markdown.
pub(crate) fn sealed_pad_reask_text(markdown: &str, missed: &[Range<usize>]) -> String {
    let mut text = String::with_capacity(markdown.len());
    let mut at = 0;
    for line in markdown.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let end = at + body.len();
        if missed
            .iter()
            .any(|range| at <= range.start && range.end <= end)
        {
            text.push_str(line);
        } else {
            text.extend(std::iter::repeat_n(' ', body.len()));
            text.push_str(&line[body.len()..]);
        }
        at += line.len();
    }
    text
}

fn mark_token(mark: Option<ScratchpadMark>) -> &'static str {
    match mark {
        None => "",
        Some(ScratchpadMark::Keep) => " keep",
        Some(ScratchpadMark::Scratch) => " scratch",
    }
}

fn full_row(kind: &str, line: &PadLine<'_>) -> String {
    format!(
        "{kind}{} {}",
        mark_token(line.mark),
        quoted_leaf(clip(line.text, SCRATCHPAD_LINE_MAX_BYTES))
    )
}

fn fold_row(line: &PadLine<'_>) -> String {
    let mut words = line.text.split_whitespace();
    let mut head = words
        .by_ref()
        .take(FOLD_WORDS)
        .collect::<Vec<_>>()
        .join(" ");
    if words.next().is_some() {
        head.push('…');
    }
    format!(
        "fold{} {}",
        mark_token(line.mark),
        quoted_leaf(clip(&head, SCRATCHPAD_LINE_MAX_BYTES))
    )
}

/// Every pinned line in full in the section's never-shed floor, beside the
/// reader line, so the agent always sees who can read its pad and what it
/// pinned (FIX 8146). Of the unpinned lines, the newest show in full, older
/// ones fold to their first words and the rest count as `older: +N`.
pub(super) fn pad_section(
    pad: EntityId,
    text: &str,
    readers: String,
) -> Result<BoardSection, BoardFrameError> {
    let lines: Vec<PadLine<'_>> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_line)
        .collect();
    let mut floor = vec![readers];
    floor.extend(
        lines
            .iter()
            .filter(|line| line.pin)
            .map(|line| full_row("pin", line)),
    );
    let unpinned: Vec<&PadLine<'_>> = lines.iter().filter(|line| !line.pin).collect();
    let newest = unpinned.len().saturating_sub(NEWEST_FULL);
    let hidden = newest.saturating_sub(FOLDED_SHOWN);
    let mut rows = vec![format!("pad: {} lines: {}", pad.to_hex(), lines.len())];
    if hidden > 0 {
        rows.push(format!("older: +{hidden}"));
    }
    rows.extend(unpinned[hidden..newest].iter().map(|line| fold_row(line)));
    rows.extend(unpinned[newest..].iter().map(|line| full_row("line", line)));
    BoardSection::new(
        "SCRATCHPAD",
        floor,
        rows,
        vec![format!("count: {}", lines.len())],
        SectionPolicy {
            pinned: false,
            shed_rank: Some(ShedRank::PluginSections),
        },
    )
}

/// The words a recall query asks for: case-folded, each once.
pub(super) fn recall_words(query: &str) -> Vec<String> {
    let mut words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    words.sort();
    words.dedup();
    words
}

/// Whether a pad line answers a recall: its text holds every query word,
/// case-folded. The one match rule, so a later ruling (ranked, any-word)
/// changes it here.
pub(super) fn recall_matches(text: &str, words: &[String]) -> bool {
    let text = text.to_lowercase();
    words.iter().all(|word| text.contains(word.as_str()))
}
