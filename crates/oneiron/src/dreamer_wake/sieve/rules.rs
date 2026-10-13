//! The sieve's rules: the date and name spans of one chunk of text, as byte
//! ranges, each with the rule class that sets its confidence row.
//!
//! Rules flag; they do not judge. A span a rule is unsure of keeps its place
//! with a lower confidence, and the policy row's band sends it to the typing
//! rung. Text inside code (a fenced block or an inline code span) is not
//! prose and is never read for names or dates.
//!
//! A long text is read one segment at a time, so one pass's work stays
//! within its bound. Where a segment ends depends on the text alone: a
//! reading is the same whether one pass or many read it.

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::temporal::temporal_phrase_spans;

/// Which rule flagged a span. Each class has its own confidence on the sieve
/// policy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleClass {
    /// A calendar date with its numbers: `2026-10-12`, `Oct 12`, `10月12日`.
    AbsoluteDate,
    /// A time relative to the turn that the parser resolves: `last week`,
    /// `3 days ago`, `明日`.
    RelativeDate,
    /// A time the rules cannot pin: `last several weeks`, a bare weekday, a
    /// slash pair such as `3/4`.
    VagueDate,
    /// A run of capitalized words inside a sentence, or of two or more words.
    Name,
    /// One capitalized word opening a sentence: as often a plain word.
    InitialName,
    /// A katakana run: a foreign name or a loanword.
    KatakanaName,
}

impl RuleClass {
    pub(super) const fn is_date(self) -> bool {
        matches!(
            self,
            Self::AbsoluteDate | Self::RelativeDate | Self::VagueDate
        )
    }
}

/// One flagged span: byte offsets into the chunk's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RuleSpan {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) class: RuleClass,
}

/// Where a segment of a longer text may end at the latest. Part of the
/// rules: a later value is a later rules version.
pub(super) const SEGMENT_BYTES: usize = 4096;
/// How far past [`SEGMENT_BYTES`] a segment's rules read, so its end falls
/// outside every span they see across it.
pub(super) const SEGMENT_REACH: usize = 512;
/// The most text one segment's rules read.
pub(super) const SEGMENT_WINDOW: usize = SEGMENT_BYTES + SEGMENT_REACH;

/// What the text before a segment leaves its reading: whether the segment
/// starts inside a sentence (its first word opens none), inside a fenced
/// code block, or inside an inline code span.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Carry {
    pub(super) in_sentence: bool,
    pub(super) in_fence: bool,
    pub(super) in_code: bool,
}

/// One segment's reading.
pub(super) struct Segment {
    /// Where the segment ends, and the next starts.
    pub(super) end: usize,
    /// Its spans, as offsets into the whole text.
    pub(super) spans: Vec<RuleSpan>,
    /// What it leaves the next segment.
    pub(super) carry: Carry,
    /// The bytes its rules read.
    pub(super) read: usize,
}

/// A code range: a fenced block or an inline code span.
#[derive(Debug, Clone, Copy)]
struct CodeRange {
    start: usize,
    end: usize,
    fenced: bool,
}

/// The rules' reading of one window: its spans, and every extent a rule
/// considered or an inline code span holds, which a cut must not split.
struct Seen {
    spans: Vec<RuleSpan>,
    cover: Vec<(usize, usize)>,
}

const MONTHS: &str = "jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?";

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

/// The compiled date patterns, built once per sieve pass.
pub(super) struct Rules {
    dates: Vec<(Regex, RuleClass)>,
}

impl Rules {
    pub(super) fn new() -> Self {
        let digit = "[0-9０-９]";
        let patterns = [
            (
                r"\b\d{4}[-/.]\d{1,2}[-/.]\d{1,2}\b".to_owned(),
                RuleClass::AbsoluteDate,
            ),
            (
                format!(r"(?i)\b(?:{MONTHS})\.?\s+\d{{1,2}}(?:st|nd|rd|th)?\b(?:,?\s+\d{{4}}\b)?"),
                RuleClass::AbsoluteDate,
            ),
            (
                format!(
                    r"(?i)\b\d{{1,2}}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:{MONTHS})\b\.?(?:,?\s+\d{{4}}\b)?"
                ),
                RuleClass::AbsoluteDate,
            ),
            (
                r"(?i)\b(?:january|february|march|april|june|july|august|september|october|november|december)\s+\d{4}\b".to_owned(),
                RuleClass::AbsoluteDate,
            ),
            (
                format!("(?:{digit}{{2,4}}年)?{digit}{{1,2}}月(?:{digit}{{1,2}}日)?|{digit}{{4}}年"),
                RuleClass::AbsoluteDate,
            ),
            (
                "明後日|一昨日|今日|明日|昨日|今週|来週|先週|今月|来月|先月|今年|来年|去年|昨年|今朝|今夜|今晩"
                    .to_owned(),
                RuleClass::RelativeDate,
            ),
            (
                "[月火水木金土日]曜日?".to_owned(),
                RuleClass::VagueDate,
            ),
            (
                r"(?i)\b(?:mon|tues|wednes|thurs|fri|satur|sun)day\b".to_owned(),
                RuleClass::VagueDate,
            ),
            (
                r"\b\d{1,2}/\d{1,2}(?:/\d{2,4})?\b".to_owned(),
                RuleClass::VagueDate,
            ),
        ];
        Self {
            dates: patterns
                .into_iter()
                .filter_map(|(pattern, class)| Some((Regex::new(&pattern).ok()?, class)))
                .collect(),
        }
    }

    /// The segment of `text` from `at` (a character boundary), read with
    /// what the text before it leaves. A rest that fits in
    /// [`SEGMENT_WINDOW`] is one segment. A longer one is read to the window
    /// and ends in the second half of [`SEGMENT_BYTES`], after a line break,
    /// else a sentence end, else a space, else any character, where no
    /// extent its rules considered, no inline code span and no fence line
    /// runs across; the segment keeps the spans that end by then. Only an
    /// extent that fills the whole half is cut at [`SEGMENT_BYTES`], and
    /// each side reads its piece.
    pub(super) fn segment(&self, text: &str, at: usize, carry: Carry) -> Segment {
        let line_start = at == 0 || text.as_bytes().get(at - 1) == Some(&b'\n');
        let rest = &text[at..];
        let shift = |spans: Vec<RuleSpan>| -> Vec<RuleSpan> {
            spans
                .into_iter()
                .map(|span| RuleSpan {
                    start: at + span.start,
                    end: at + span.end,
                    ..span
                })
                .collect()
        };
        if rest.len() <= SEGMENT_WINDOW {
            let (code, _) = code_ranges(rest, carry, line_start);
            return Segment {
                end: text.len(),
                spans: shift(self.read(rest, &code, carry.in_sentence).spans),
                carry: Carry::default(),
                read: rest.len(),
            };
        }
        let window = &rest[..floor_boundary(rest, SEGMENT_WINDOW)];
        let (code, fences) = code_ranges(window, carry, line_start);
        let seen = self.read(window, &code, carry.in_sentence);
        let (cut, clean) = cut_in(window, &merged([seen.cover, fences].concat()));
        let spans = if clean {
            seen.spans
                .into_iter()
                .filter(|span| span.end <= cut)
                .collect()
        } else {
            let clipped: Vec<CodeRange> = code
                .iter()
                .filter(|range| range.start < cut)
                .map(|range| CodeRange {
                    end: range.end.min(cut),
                    ..*range
                })
                .collect();
            self.read(&window[..cut], &clipped, carry.in_sentence).spans
        };
        let inside = |fenced: bool| {
            code.iter()
                .any(|range| range.fenced == fenced && range.start < cut && cut < range.end)
        };
        Segment {
            end: at + cut,
            spans: shift(spans),
            carry: Carry {
                in_sentence: in_sentence_at(&window[..cut], carry.in_sentence),
                in_fence: inside(true),
                in_code: inside(false),
            },
            read: window.len(),
        }
    }

    /// Every date and name span of `text`, in text order, none overlapping,
    /// and none inside `code` (its code ranges, in order); its first word
    /// opens a sentence unless `in_sentence`. Each list is filtered against
    /// the next in one ordered sweep, so a flood of spans costs its length,
    /// not its square.
    fn read(&self, text: &str, code: &[CodeRange], in_sentence: bool) -> Seen {
        let mut dates: Vec<RuleSpan> = self
            .dates
            .iter()
            .flat_map(|(pattern, class)| {
                pattern.find_iter(text).map(|found| RuleSpan {
                    start: found.start(),
                    end: found.end(),
                    class: *class,
                })
            })
            .chain(
                temporal_phrase_spans(text)
                    .into_iter()
                    .map(|phrase| RuleSpan {
                        start: phrase.start,
                        end: phrase.end,
                        class: if phrase.resolved {
                            RuleClass::RelativeDate
                        } else {
                            RuleClass::VagueDate
                        },
                    }),
            )
            .collect();
        dates.sort_by_key(|span| (span.start, std::cmp::Reverse(span.end)));
        let mut names = name_spans(text, in_sentence);
        names.sort_by_key(|span| (span.start, span.end));
        let cover = dates
            .iter()
            .chain(&names)
            .map(|span| (span.start, span.end))
            .chain(
                code.iter()
                    .filter(|range| !range.fenced)
                    .map(|range| (range.start, range.end)),
            )
            .collect();
        let blocks: Vec<(usize, usize)> =
            code.iter().map(|range| (range.start, range.end)).collect();
        let mut spans = longest_first(&mut clear_of(dates, &blocks));
        let held: Vec<_> = spans.iter().map(|date| (date.start, date.end)).collect();
        spans.extend(clear_of(clear_of(names, &blocks), &held));
        spans.sort_by_key(|span| (span.start, span.end));
        Seen { spans, cover }
    }
}

/// The last character boundary of `text` at or before `at`, past its first
/// character.
fn floor_boundary(text: &str, at: usize) -> usize {
    let mut at = at.min(text.len());
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    if at == 0 {
        text.chars().next().map_or(0, char::len_utf8)
    } else {
        at
    }
}

/// `extents` sorted, with every overlapping pair joined: a cut may fall
/// where two of them only touch.
fn merged(mut extents: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    extents.sort_unstable();
    let mut joined: Vec<(usize, usize)> = Vec::with_capacity(extents.len());
    for (start, end) in extents {
        match joined.last_mut() {
            Some(last) if start < last.1 => last.1 = last.1.max(end),
            _ => joined.push((start, end)),
        }
    }
    joined
}

/// Where a segment of `window` ends, and whether that end is clean: the
/// last point in the second half of [`SEGMENT_BYTES`] after a line break,
/// else a sentence end, else a space, else any character, inside none of
/// `cover` (sorted, disjoint). With none, it ends at [`SEGMENT_BYTES`].
fn cut_in(window: &str, cover: &[(usize, usize)]) -> (usize, bool) {
    let limit = floor_boundary(window, SEGMENT_BYTES);
    let clear = |cut: usize| {
        let next = cover.partition_point(|&(_, end)| end <= cut);
        cover.get(next).is_none_or(|&(start, _)| cut <= start)
    };
    let points = || {
        window[..limit]
            .char_indices()
            .rev()
            .map(|(index, ch)| (index, ch, index + ch.len_utf8()))
            .take_while(|&(_, _, cut)| cut > SEGMENT_BYTES / 2)
    };
    let ends: [&dyn Fn(usize, char) -> bool; 4] = [
        &|_, ch| ch == '\n',
        &|index, ch| ends_sentence(window, index, ch),
        &|_, ch| ch.is_whitespace(),
        &|_, _| true,
    ];
    for ends in ends {
        if let Some((_, _, cut)) = points().find(|&(index, ch, cut)| ends(index, ch) && clear(cut))
        {
            return (cut, true);
        }
    }
    (limit, false)
}

/// Whether the character at `index` of `text` ends a sentence: a CJK full
/// stop, or `.`, `!` or `?` before a space.
fn ends_sentence(text: &str, index: usize, ch: char) -> bool {
    matches!(ch, '。' | '！' | '？')
        || (matches!(ch, '.' | '!' | '?') && text[index + 1..].starts_with(char::is_whitespace))
}

/// Whether a sentence is open at the end of `text`: a word came after the
/// last character that ends one. `carried` when `text` holds neither.
fn in_sentence_at(text: &str, carried: bool) -> bool {
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

/// Keeps, of overlapping spans, the one that starts first and then the
/// longest.
fn longest_first(spans: &mut [RuleSpan]) -> Vec<RuleSpan> {
    spans.sort_by_key(|span| (span.start, std::cmp::Reverse(span.end)));
    let mut kept: Vec<RuleSpan> = Vec::with_capacity(spans.len());
    for span in &*spans {
        if kept.last().is_none_or(|last| last.end <= span.start) {
            kept.push(*span);
        }
    }
    kept
}

/// The spans, sorted by start, that overlap none of `blocks` (sorted and
/// disjoint), in one pass over both.
fn clear_of(spans: Vec<RuleSpan>, blocks: &[(usize, usize)]) -> Vec<RuleSpan> {
    let mut next = 0;
    spans
        .into_iter()
        .filter(|span| {
            while blocks.get(next).is_some_and(|&(_, end)| end <= span.start) {
                next += 1;
            }
            blocks.get(next).is_none_or(|&(start, _)| span.end <= start)
        })
        .collect()
}

/// The fenced code blocks and inline code spans of `text`, in order, from
/// the state `carry` leaves it, and the fence lines that open or close a
/// block. Only a whole line opens or closes a fence: a text that starts
/// mid-line (not `line_start`) does not on its first. An inline span carried
/// open runs to the next backtick, or to its line's end.
fn code_ranges(
    text: &str,
    carry: Carry,
    line_start: bool,
) -> (Vec<CodeRange>, Vec<(usize, usize)>) {
    let mut ranges = Vec::new();
    let mut fences = Vec::new();
    let mut fence = carry.in_fence.then_some(0);
    let mut offset = 0;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let first = index == 0;
        let fenced = (line_start || !first) && line.trim_start().starts_with("```");
        if fenced {
            fences.push((offset, offset + line.len()));
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
                let carried = first && carry.in_code;
                let mut open: Option<usize> = carried.then_some(0);
                for (at, ch) in line.char_indices() {
                    if ch == '`' {
                        match open {
                            None => open = Some(offset + at),
                            Some(start) => {
                                ranges.push(CodeRange {
                                    start,
                                    end: offset + at + 1,
                                    fenced: false,
                                });
                                open = None;
                            }
                        }
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
struct Word {
    start: usize,
    end: usize,
    /// The word opens a sentence: nothing but space and punctuation stands
    /// between it and the start of the text or a sentence end.
    opens: bool,
}

fn words(text: &str, in_sentence: bool) -> Vec<Word> {
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

/// Runs of capitalized words, and katakana runs.
fn name_spans(text: &str, in_sentence: bool) -> Vec<RuleSpan> {
    let mut spans = Vec::new();
    let words = words(text, in_sentence);
    let mut index = 0;
    while index < words.len() {
        if !capitalized(&text[words[index].start..words[index].end]) {
            index += 1;
            continue;
        }
        let first = index;
        // A run continues over adjacent capitalized words joined by one space.
        while index + 1 < words.len()
            && capitalized(&text[words[index + 1].start..words[index + 1].end])
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
    spans.extend(katakana_runs(text));
    spans.sort_by_key(|span| span.start);
    spans
}

fn katakana(ch: char) -> bool {
    matches!(ch, '\u{30A1}'..='\u{30FA}' | '\u{30FC}' | '\u{30FB}')
}

fn katakana_runs(text: &str) -> Vec<RuleSpan> {
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
