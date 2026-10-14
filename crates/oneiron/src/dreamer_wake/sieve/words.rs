//! The prose under the sieve's rules: code, sentences, words, and runs of
//! capitalized words and of katakana, each read from the state the text
//! before leaves.

use super::rules::{Carry, INLINE_CODE_BYTES, RuleClass, RuleSpan};

/// A code range: a fenced block or an inline code span.
#[derive(Debug, Clone, Copy)]
pub(super) struct CodeRange {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) fenced: bool,
}

/// Words a capitalized run never starts with or holds: sentence openers and
/// the calendar's own words, which the date rules read.
const NOT_NAMES: &[&str] = &[
    "a",
    "an",
    "and",
    "but",
    "he",
    "how",
    "i",
    "i'll",
    "i'm",
    "i've",
    "i'd",
    "if",
    "it",
    "it's",
    "my",
    "no",
    "ok",
    "she",
    "so",
    "that",
    "that's",
    "the",
    "then",
    "there",
    "there's",
    "they",
    "this",
    "we",
    "we'll",
    "we've",
    "what",
    "when",
    "why",
    "you",
    "you'll",
    "you're",
    "yes",
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
    "january",
    "february",
    "march",
    "april",
    "june",
    "july",
    "august",
    "september",
];

/// Whether a sentence is open at the end of `text`: a word came after the
/// last character that ends one. `carried` when `text` holds neither.
pub(super) fn in_sentence_at(text: &str, carried: bool) -> bool {
    text.chars()
        .rev()
        .find_map(|ch| {
            if ch.is_alphanumeric() {
                Some(true)
            } else if opens_next(ch) {
                Some(false)
            } else {
                None
            }
        })
        .unwrap_or(carried)
}

/// Whether the word after `ch` opens a sentence.
const fn opens_next(ch: char) -> bool {
    matches!(ch, '.' | '!' | '?' | '\n' | '。' | '！' | '？')
}

/// The fenced code blocks and inline code spans of `text`, in order, from
/// the state `carry` leaves it, and the fence lines, each with whether it
/// closes a block. Only a whole line opens or closes a fence: a text that
/// starts mid-line (not `line_start`) does not on its first. An inline span
/// carried open runs to the next backtick, or to its line's end.
pub(super) fn code_ranges(
    text: &str,
    carry: Carry,
    line_start: bool,
) -> (Vec<CodeRange>, Vec<(usize, usize, bool)>) {
    let mut ranges = Vec::new();
    let mut fences = Vec::new();
    let mut fence = carry.in_fence.then_some(0);
    let mut offset = 0;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let first = index == 0;
        let fenced = (first && carry.closing_fence)
            || ((line_start || !first) && line.trim_start().starts_with("```"));
        if fenced {
            fences.push((offset, offset + line.len(), fence.is_some()));
        }
        match (fence, fenced) {
            (None, true) => fence = Some(offset),
            (Some(start), true) => {
                ranges.push(CodeRange {
                    start,
                    end: offset + line.len(),
                    fenced: true,
                });
                fence = None;
            }
            (Some(_), false) => {}
            (None, false) => {
                let mut carried = first && carry.in_code;
                let mut open: Option<usize> = carried.then_some(0);
                for (at, ch) in line.char_indices() {
                    if ch != '`' {
                        continue;
                    }
                    let here = offset + at;
                    match open {
                        // A span carried in closes at the first backtick: the
                        // window before saw it close within reach.
                        Some(start) if carried || here + 1 - start <= INLINE_CODE_BYTES => {
                            ranges.push(CodeRange {
                                start,
                                end: here + 1,
                                fenced: false,
                            });
                            open = None;
                            carried = false;
                        }
                        // None open, or the open one has no close in reach
                        // and is plain text: this one opens.
                        _ => open = Some(here),
                    }
                }
                if carried && open == Some(0) {
                    ranges.push(CodeRange {
                        start: 0,
                        end: line.len(),
                        fenced: false,
                    });
                }
            }
        }
        offset += line.len();
    }
    if let Some(start) = fence {
        ranges.push(CodeRange {
            start,
            end: text.len(),
            fenced: true,
        });
    }
    (ranges, fences)
}

/// One word of running text: letters and digits, with an apostrophe or a
/// hyphen inside it.
pub(super) struct Word {
    pub(super) start: usize,
    pub(super) end: usize,
    /// The word opens a sentence: nothing but space and punctuation stands
    /// between it and the start of the text or a sentence end.
    opens: bool,
}

pub(super) fn words(text: &str, in_sentence: bool) -> Vec<Word> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut words = Vec::new();
    let mut opens = !in_sentence;
    let mut index = 0;
    while index < chars.len() {
        let (at, ch) = chars[index];
        if !ch.is_alphanumeric() {
            if opens_next(ch) {
                opens = true;
            }
            index += 1;
            continue;
        }
        let start = at;
        let mut end = index + 1;
        while end < chars.len() {
            let ch = chars[end].1;
            let joins = matches!(ch, '\'' | '’' | '-')
                && chars
                    .get(end + 1)
                    .is_some_and(|(_, next)| next.is_alphanumeric());
            if ch.is_alphanumeric() || joins {
                end += 1;
            } else {
                break;
            }
        }
        let stop = chars.get(end).map_or(text.len(), |(at, _)| *at);
        words.push(Word {
            start,
            end: stop,
            opens,
        });
        opens = false;
        index = end;
    }
    words
}

fn capitalized(word: &str) -> bool {
    let mut chars = word.chars();
    chars
        .next()
        .is_some_and(|first| first.is_uppercase() && first.is_alphabetic())
        && chars.next().is_some()
        && !NOT_NAMES.contains(&word.to_lowercase().as_str())
}

/// How the first word of a window stands to the text before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Opening {
    /// A word of its own.
    Fresh,
    /// The rest of a word a cut split, in no run: it opens none.
    Rest,
    /// The rest of a run of capitalized words a cut split: it goes on with
    /// the run, whatever its case.
    Continues,
}

/// Runs of capitalized `words` of `text`, the first word standing as
/// `opening` says.
pub(super) fn capitalized_runs(text: &str, words: &[Word], opening: Opening) -> Vec<RuleSpan> {
    let capitalized_at = |index: usize| capitalized(&text[words[index].start..words[index].end]);
    let mut spans = Vec::new();
    let mut index = 0;
    while index < words.len() {
        let opens_run = match (index, opening) {
            (0, Opening::Continues) => true,
            (0, Opening::Rest) => false,
            _ => capitalized_at(index),
        };
        if !opens_run {
            index += 1;
            continue;
        }
        let first = index;
        // A run continues over adjacent capitalized words joined by one space.
        while index + 1 < words.len()
            && capitalized_at(index + 1)
            && !words[index + 1].opens
            && &text[words[index].end..words[index + 1].start] == " "
        {
            index += 1;
        }
        let class = if words[first].opens && first == index {
            RuleClass::InitialName
        } else {
            RuleClass::Name
        };
        spans.push(RuleSpan {
            start: words[first].start,
            end: words[index].end,
            class,
        });
        index += 1;
    }
    spans
}

fn katakana(ch: char) -> bool {
    matches!(ch, '\u{30A1}'..='\u{30FA}' | '\u{30FC}' | '\u{30FB}')
}

pub(super) fn katakana_runs(text: &str) -> Vec<RuleSpan> {
    let mut spans = Vec::new();
    let mut run: Option<(usize, usize)> = None;
    for (at, ch) in text.char_indices() {
        if katakana(ch) {
            let start = run.map_or(at, |(start, _)| start);
            let count = run.map_or(0, |(_, count)| count);
            run = Some((start, count + 1));
            continue;
        }
        if let Some((start, count)) = run.take()
            && count >= 2
        {
            spans.push(RuleSpan {
                start,
                end: at,
                class: RuleClass::KatakanaName,
            });
        }
    }
    if let Some((start, count)) = run
        && count >= 2
    {
        spans.push(RuleSpan {
            start,
            end: text.len(),
            class: RuleClass::KatakanaName,
        });
    }
    spans
}
