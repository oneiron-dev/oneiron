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
//! within its bound. Every span a rule flags is short: a run of space inside
//! a date holds at most 8 characters, the phrase reader reads at most
//! [`PHRASE_BYTES`] a step, and a run of capitalized words or of katakana
//! longer than [`NAME_BYTES`] is no name. So a segment's window sees whole
//! every span that starts in the segment, and each rule reads on in the next
//! segment from where it stood: a text reads the same, span for span, in one
//! segment or many, and in one pass or many.

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::words::{
    CodeRange, Opening, capitalized_runs, code_ranges, in_sentence_at, katakana_runs, words,
};
use crate::temporal::temporal_phrase_steps;

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
pub(super) const INLINE_CODE_BYTES: usize = 256;
/// The most text one step of the phrase reader reads, for the same reason:
/// no temporal phrase is longer.
const PHRASE_BYTES: usize = 256;
/// The longest name: a longer run of capitalized words or of katakana is
/// running text, not a name.
const NAME_BYTES: usize = 256;
/// The date patterns, each its own scan.
const DATE_PATTERNS: usize = 9;

/// What the text before a segment leaves its reading, so the segment reads
/// on as one reading of the whole text would: whether it starts inside a
/// sentence (its first word opens none), inside a fenced code block (and
/// inside the line that closes it), inside an inline code span, on a line
/// that holds only space so far, and inside a word, a run of capitalized
/// words or a katakana run a cut split; and where each date pattern, the
/// phrase reader and the dates kept read on from, in bytes into it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Carry {
    pub(super) in_sentence: bool,
    pub(super) in_fence: bool,
    pub(super) closing_fence: bool,
    pub(super) in_code: bool,
    pub(super) blank_line: bool,
    pub(super) in_word: bool,
    pub(super) in_name: bool,
    pub(super) in_kana: bool,
    /// Where each date pattern's last match before the segment ends.
    pub(super) dates: [u16; DATE_PATTERNS],
    /// Where the phrase reader's last step before it ends.
    pub(super) phrase: u16,
    /// Where the last date kept before it ends: no span starts before.
    pub(super) held: u16,
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

/// The rules' reading of one window, in offsets into it: its spans; its
/// code; its words, runs of capitalized words and katakana runs, names or
/// not; each date pattern's matches, the phrase reader's steps and the dates
/// kept; and every extent a rule considered, inline code span and fence
/// line, which a cut does best not to split.
struct Seen {
    spans: Vec<RuleSpan>,
    code: Vec<CodeRange>,
    /// Fence lines, each with whether it closes a block.
    fences: Vec<(usize, usize, bool)>,
    words: Vec<(usize, usize)>,
    names: Vec<(usize, usize)>,
    kana: Vec<(usize, usize)>,
    /// Each match with its pattern's index.
    matches: Vec<(usize, usize, usize)>,
    steps: Vec<(usize, usize)>,
    kept: Vec<(usize, usize)>,
    cover: Vec<(usize, usize)>,
}

const MONTHS: &str = "jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?";

/// The compiled date patterns, built once per sieve pass.
pub(super) struct Rules {
    dates: [(Regex, RuleClass); DATE_PATTERNS],
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
            dates: patterns.map(|(pattern, class)| {
                (
                    Regex::new(&pattern).expect("a fixed pattern compiles"),
                    class,
                )
            }),
        }
    }

    /// The segment of `text` from `at` (a character boundary), read with
    /// what the text before it leaves. A rest that fits in
    /// [`SEGMENT_WINDOW`] is one segment. A longer one is read to the window
    /// and ends in the second half of [`SEGMENT_BYTES`], after a line break,
    /// else a sentence end, else a space, else any character: where no word,
    /// no extent its rules considered, no inline code span and no fence line
    /// runs across, else where none shorter than half a segment does, else
    /// at [`SEGMENT_BYTES`]. The segment keeps every span that starts before
    /// its end, whole, since no span is longer than the window reads past
    /// it, and its carry tells the next segment where each rule stood.
    pub(super) fn segment(&self, text: &str, at: usize, carry: Carry) -> Segment {
        let rest = &text[at..];
        let end = if rest.len() <= SEGMENT_WINDOW {
            text.len()
        } else {
            at + floor_boundary(rest, SEGMENT_WINDOW)
        };
        let line_start = at == 0 || text.as_bytes().get(at - 1) == Some(&b'\n') || carry.blank_line;
        let seen = self.read(text, (at, end), carry, line_start);
        let shift = |spans: Vec<RuleSpan>, cut: usize| -> Vec<RuleSpan> {
            spans
                .into_iter()
                .filter(|span| span.start < cut)
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
        let before = &window[..cut];
        let blank = |line: &str| line.chars().all(char::is_whitespace);
        let blank_line = before
            .rfind('\n')
            .map_or(line_start && blank(before), |newline| {
                blank(&before[newline + 1..])
            });
        let dates = std::array::from_fn(|pattern| {
            past(
                seen.matches
                    .iter()
                    .filter(|&&(of, ..)| of == pattern)
                    .map(|&(_, start, end)| (start, end)),
                cut,
            )
        });
        Segment {
            end: at + cut,
            carry: Carry {
                in_sentence: in_sentence_at(before, carry.in_sentence),
                in_fence: inside(true),
                closing_fence,
                in_code: inside(false),
                blank_line,
                in_word: splits(&seen.words),
                in_name: splits(&seen.names),
                in_kana: splits(&seen.kana),
                dates,
                phrase: past(seen.steps.iter().copied(), cut),
                held: past(seen.kept.iter().copied(), cut),
            },
            spans: shift(seen.spans, cut),
            read: window.len(),
        }
    }

    /// The rules' reading of `text[from..to]` from the state `carry` leaves
    /// it: every date and name span, in text order, none overlapping and none
    /// inside code, and what a cut does best not to split. A run a cut split
    /// goes on from the text before, the rest of one too long to be a name,
    /// and the rest of a word a cut split opens no run. Each list is filtered
    /// against the next in one ordered sweep, so a flood of spans costs its
    /// length, not its square.
    fn read(&self, text: &str, (from, to): (usize, usize), carry: Carry, line_start: bool) -> Seen {
        let window = &text[from..to];
        let (code, fences) = code_ranges(window, carry, line_start);
        let (matches, steps) = self.scan(text, (from, to), carry);
        let mut dates: Vec<RuleSpan> = matches
            .iter()
            .map(|&(_, span)| span)
            .chain(steps.iter().filter_map(|&(start, end, class)| {
                class.map(|class| RuleSpan { start, end, class })
            }))
            .collect();
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
        let matches: Vec<(usize, usize, usize)> = matches
            .iter()
            .map(|&(pattern, span)| (pattern, span.start, span.end))
            .collect();
        let steps: Vec<(usize, usize)> =
            steps.iter().map(|&(start, end, _)| (start, end)).collect();
        let cover = matches
            .iter()
            .map(|&(_, start, end)| (start, end))
            .chain(steps.iter().copied())
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
        let held = usize::from(carry.held);
        let mut spans = longest_first(&mut clear_of(dates, &blocks), held);
        let kept = extents(&spans);
        // A date the segment before kept runs into this one: no span here
        // overlaps it.
        let taken: Vec<(usize, usize)> = (held > 0)
            .then_some((0, held))
            .into_iter()
            .chain(kept.iter().copied())
            .collect();
        spans.extend(clear_of(clear_of(names, &blocks), &taken));
        spans.sort_by_key(|span| (span.start, span.end));
        Seen {
            spans,
            code,
            fences,
            words,
            names: runs,
            kana,
            matches,
            steps,
            kept,
            cover,
        }
    }

    /// Each date pattern's matches in `text[from..to]`, with the pattern's
    /// index, and the phrase reader's steps, each with its class if it is a
    /// phrase, in offsets into the window. Each reads on from where `carry`
    /// says it stood. A pattern reads its word edges in the text itself. The
    /// phrase reader reads the character before `from` too, so the rest of a
    /// word is no token, and starts at the first token past where it stood.
    fn scan(
        &self,
        text: &str,
        (from, to): (usize, usize),
        carry: Carry,
    ) -> (
        Vec<(usize, RuleSpan)>,
        Vec<(usize, usize, Option<RuleClass>)>,
    ) {
        let hay = &text[..to];
        let mut matches = Vec::new();
        for (index, (pattern, class)) in self.dates.iter().enumerate() {
            let mut at = (from + usize::from(carry.dates[index])).min(to);
            while let Some(found) = pattern.find_at(hay, at) {
                if found.end() == found.start() {
                    break;
                }
                matches.push((
                    index,
                    RuleSpan {
                        start: found.start() - from,
                        end: found.end() - from,
                        class: *class,
                    },
                ));
                at = found.end();
            }
        }
        let context = text[..from].chars().next_back().map_or(0, char::len_utf8);
        let steps = temporal_phrase_steps(
            &text[from - context..to],
            context + usize::from(carry.phrase),
            PHRASE_BYTES,
        )
        .into_iter()
        .map(|step| {
            let class = step.phrase.map(|resolved| {
                if resolved {
                    RuleClass::RelativeDate
                } else {
                    RuleClass::VagueDate
                }
            });
            (step.start - context, step.end - context, class)
        })
        .collect();
        (matches, steps)
    }
}

#[cfg(test)]
impl Rules {
    /// The spans of `text` read in one window: what a segmented reading of
    /// it gives.
    pub(super) fn read_whole(&self, text: &str) -> Vec<RuleSpan> {
        self.read(text, (0, text.len()), Carry::default(), true)
            .spans
    }

    /// The spans of `text` read a segment at a time.
    pub(super) fn read_segmented(&self, text: &str) -> Vec<RuleSpan> {
        let (mut at, mut carry, mut spans) = (0, Carry::default(), Vec::new());
        while at < text.len() {
            let segment = self.segment(text, at, carry);
            spans.extend(segment.spans);
            (at, carry) = (segment.end, segment.carry);
        }
        spans
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

/// Keeps, of overlapping spans, the one that starts first and then the
/// longest, none starting before `held`.
fn longest_first(spans: &mut [RuleSpan], held: usize) -> Vec<RuleSpan> {
    spans.sort_by_key(|span| (span.start, std::cmp::Reverse(span.end)));
    let mut end = held;
    let mut kept: Vec<RuleSpan> = Vec::with_capacity(spans.len());
    for span in &*spans {
        if end <= span.start {
            kept.push(*span);
            end = span.end;
        }
    }
    kept
}

/// How far past `cut` the extent of `extents` that runs across it reaches;
/// 0 for none.
fn past(extents: impl IntoIterator<Item = (usize, usize)>, cut: usize) -> u16 {
    extents
        .into_iter()
        .filter(|&(start, end)| start < cut && cut < end)
        .map(|(_, end)| u16::try_from(end - cut).unwrap_or(u16::MAX))
        .max()
        .unwrap_or(0)
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
