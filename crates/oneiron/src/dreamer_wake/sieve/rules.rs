//! The sieve's rules: the date and name spans of one chunk of text, as byte
//! ranges, each with the rule class that sets its confidence row.
//!
//! Rules flag; they do not judge. A span a rule is unsure of keeps its place
//! with a lower confidence, and the policy row's band sends it to the typing
//! rung. Text inside code (a fenced block or an inline code span) is not
//! prose and is never read for names or dates. An inline code span runs from
//! a backtick to the next on its line within [`INLINE_CODE_BYTES`]; a
//! backtick with none in reach is plain text.
//!
//! A long text is read one segment at a time, so one pass's work stays
//! within its bound. Where a segment ends depends on the text alone: a
//! reading is the same whether one pass or many read it. Every span a rule
//! flags is short: a run of space inside a date holds at most 8 characters,
//! and a temporal phrase longer than [`PHRASE_BYTES`] is no date, a run of
//! capitalized words or of katakana longer than [`NAME_BYTES`] no name. So a
//! window sees each span whole, and a segment ends where none runs across.

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
/// The longest inline code span, backticks included: well inside
/// [`SEGMENT_REACH`], so a window always sees whether a backtick before its
/// cut opens one.
const INLINE_CODE_BYTES: usize = 256;
/// The longest temporal phrase read as a date, for the same reason.
const PHRASE_BYTES: usize = 256;
/// The longest name: a longer run of capitalized words or of katakana is
/// running text, not a name.
const NAME_BYTES: usize = 256;

/// What the text before a segment leaves its reading: whether the segment
/// starts inside a sentence (its first word opens none), inside a fenced
/// code block (and inside the line that closes it), inside an inline code
/// span, and, after a cut inside an extent too long to be a span, inside a
/// word, a run of capitalized words or a katakana run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Carry {
    pub(super) in_sentence: bool,
    pub(super) in_fence: bool,
    pub(super) closing_fence: bool,
    pub(super) in_code: bool,
    pub(super) in_word: bool,
    pub(super) in_name: bool,
    pub(super) in_kana: bool,
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

/// The rules' reading of one window, in offsets into it: its spans, its
/// code, its words, runs of capitalized words and katakana runs, each name
/// or not, and every extent a rule considered, inline code span and fence
/// line, which a cut must not split.
struct Seen {
    spans: Vec<RuleSpan>,
    code: Vec<CodeRange>,
    /// Fence lines, each with whether it closes a block.
    fences: Vec<(usize, usize, bool)>,
    words: Vec<(usize, usize)>,
    names: Vec<(usize, usize)>,
    kana: Vec<(usize, usize)>,
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
                format!(r"(?i)\b(?:{MONTHS})\.?\s{{1,8}}\d{{1,2}}(?:st|nd|rd|th)?\b(?:,?\s{{1,8}}\d{{4}}\b)?"),
                RuleClass::AbsoluteDate,
            ),
            (
                format!(
                    r"(?i)\b\d{{1,2}}(?:st|nd|rd|th)?\s{{1,8}}(?:of\s{{1,8}})?(?:{MONTHS})\b\.?(?:,?\s{{1,8}}\d{{4}}\b)?"
                ),
                RuleClass::AbsoluteDate,
            ),
            (
                r"(?i)\b(?:january|february|march|april|june|july|august|september|october|november|december)\s{1,8}\d{4}\b".to_owned(),
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
    /// word, no extent its rules considered, no inline code span and no
    /// fence line runs across; the segment keeps the spans that end by then.
    /// Where only an extent too long to be a span fills the half (a word, a
    /// run, a phrase or a fence line of half a segment or more), the cut
    /// falls inside it, outside every shorter one, and the next segment reads
    /// on inside the word or run, starting none there. Only shorter extents
    /// that overlap across the whole half are cut at [`SEGMENT_BYTES`], and
    /// the spans across that cut are dropped.
    pub(super) fn segment(&self, text: &str, at: usize, carry: Carry) -> Segment {
        let rest = &text[at..];
        let end = if rest.len() <= SEGMENT_WINDOW {
            text.len()
        } else {
            at + floor_boundary(rest, SEGMENT_WINDOW)
        };
        let seen = self.read(text, (at, end), carry);
        let shift = |spans: Vec<RuleSpan>, cut: usize| -> Vec<RuleSpan> {
            spans
                .into_iter()
                .filter(|span| span.end <= cut)
                .map(|span| RuleSpan {
                    start: at + span.start,
                    end: at + span.end,
                    ..span
                })
                .collect()
        };
        if end == text.len() {
            return Segment {
                end,
                spans: shift(seen.spans, end - at),
                carry: Carry::default(),
                read: end - at,
            };
        }
        let window = &text[at..end];
        let short: Vec<(usize, usize)> = seen
            .cover
            .iter()
            .copied()
            .filter(|&(start, end)| end - start < SEGMENT_BYTES / 2)
            .collect();
        let cut = cut_in(window, &merged(seen.cover))
            .or_else(|| cut_in(window, &merged(short)))
            .unwrap_or_else(|| floor_boundary(window, SEGMENT_BYTES));
        let inside = |fenced: bool| {
            seen.code
                .iter()
                .any(|range| range.fenced == fenced && range.start < cut && cut < range.end)
        };
        let closing_fence = seen
            .fences
            .iter()
            .any(|&(start, end, closes)| closes && start < cut && cut < end);
        let splits = |extents: &[(usize, usize)]| {
            extents.iter().any(|&(start, end)| start < cut && cut < end)
        };
        Segment {
            end: at + cut,
            carry: Carry {
                in_sentence: in_sentence_at(&window[..cut], carry.in_sentence),
                in_fence: inside(true),
                closing_fence,
                in_code: inside(false),
                in_word: splits(&seen.words),
                in_name: splits(&seen.names),
                in_kana: splits(&seen.kana),
            },
            spans: shift(seen.spans, cut),
            read: window.len(),
        }
    }

    /// The rules' reading of `text[from..to]` from the state `carry` leaves
    /// it: every date and name span, in text order, none overlapping and none
    /// inside code, and what a cut must not split. A run a cut split goes on
    /// from the text before, the rest of one too long to be a name, and the
    /// rest of a word a cut split opens no run. Each list is filtered against
    /// the next in one ordered sweep, so a flood of spans costs its length,
    /// not its square.
    fn read(&self, text: &str, (from, to): (usize, usize), carry: Carry) -> Seen {
        let window = &text[from..to];
        let line_start = from == 0 || text.as_bytes().get(from - 1) == Some(&b'\n');
        let (code, fences) = code_ranges(window, carry, line_start);
        let (mut dates, phrases) = self.dates_in(text, (from, to));
        dates.sort_by_key(|span| (span.start, std::cmp::Reverse(span.end)));
        let parsed = words(window, carry.in_sentence);
        let opening = if carry.in_name {
            Opening::Continues
        } else if carry.in_word {
            Opening::Rest
        } else {
            Opening::Fresh
        };
        let runs = capitalized_runs(window, &parsed, opening);
        let kana = katakana_runs(window);
        let mut names: Vec<RuleSpan> = runs
            .iter()
            .skip(usize::from(carry.in_name))
            .chain(kana.iter().filter(|run| !carry.in_kana || run.start > 0))
            .filter(|name| name.end - name.start <= NAME_BYTES)
            .copied()
            .collect();
        names.sort_by_key(|span| (span.start, span.end));
        let extents = |spans: &[RuleSpan]| -> Vec<(usize, usize)> {
            spans.iter().map(|span| (span.start, span.end)).collect()
        };
        let (runs, kana) = (extents(&runs), extents(&kana));
        let words: Vec<(usize, usize)> = parsed.iter().map(|word| (word.start, word.end)).collect();
        let cover = extents(&dates)
            .into_iter()
            .chain(extents(&phrases))
            .chain(runs.iter().copied())
            .chain(kana.iter().copied())
            .chain(words.iter().copied())
            .chain(
                code.iter()
                    .filter(|range| !range.fenced)
                    .map(|range| (range.start, range.end)),
            )
            .chain(fences.iter().map(|&(start, end, _)| (start, end)))
            .collect();
        let blocks: Vec<(usize, usize)> =
            code.iter().map(|range| (range.start, range.end)).collect();
        let mut spans = longest_first(&mut clear_of(dates, &blocks));
        let held: Vec<_> = spans.iter().map(|date| (date.start, date.end)).collect();
        spans.extend(clear_of(clear_of(names, &blocks), &held));
        spans.sort_by_key(|span| (span.start, span.end));
        Seen {
            spans,
            code,
            fences,
            words,
            names: runs,
            kana,
            cover,
        }
    }

    /// The date candidates of `text[from..to]`, in offsets into it, and apart
    /// every temporal phrase, the ones too long to be a date as well. The
    /// patterns and the phrase reader read the character before `from` too,
    /// so the window's start is a word edge only where the text has one; a
    /// candidate that starts in that character is the text before's.
    fn dates_in(&self, text: &str, (from, to): (usize, usize)) -> (Vec<RuleSpan>, Vec<RuleSpan>) {
        let context = text[..from].chars().next_back().map_or(0, char::len_utf8);
        let hay = &text[from - context..to];
        let into = |start: usize, end: usize, class: RuleClass| {
            start.checked_sub(context).map(|start| RuleSpan {
                start,
                end: end - context,
                class,
            })
        };
        let phrases: Vec<RuleSpan> = temporal_phrase_spans(hay)
            .into_iter()
            .filter_map(|phrase| {
                let class = if phrase.resolved {
                    RuleClass::RelativeDate
                } else {
                    RuleClass::VagueDate
                };
                into(phrase.start, phrase.end, class)
            })
            .collect();
        let dates = self
            .dates
            .iter()
            .flat_map(|(pattern, class)| {
                pattern
                    .find_iter(hay)
                    .filter_map(move |found| into(found.start(), found.end(), *class))
            })
            .chain(
                phrases
                    .iter()
                    .copied()
                    .filter(|phrase| phrase.end - phrase.start <= PHRASE_BYTES),
            )
            .collect();
        (dates, phrases)
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

/// Where a segment of `window` may end: the last point in the second half
/// of [`SEGMENT_BYTES`] after a line break, else a sentence end, else a
/// space, else any character, inside none of `cover` (sorted, disjoint).
fn cut_in(window: &str, cover: &[(usize, usize)]) -> Option<usize> {
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
    ends.into_iter().find_map(|ends| {
        points()
            .find(|&(index, ch, cut)| ends(index, ch) && clear(cut))
            .map(|(_, _, cut)| cut)
    })
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
/// the state `carry` leaves it, and the fence lines, each with whether it
/// closes a block. Only a whole line opens or closes a fence: a text that
/// starts mid-line (not `line_start`) does not on its first. An inline span
/// carried open runs to the next backtick, or to its line's end.
fn code_ranges(
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

/// How the first word of a window stands to the text before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opening {
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
fn capitalized_runs(text: &str, words: &[Word], opening: Opening) -> Vec<RuleSpan> {
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
