//! The sieve's rules: the date and name spans of one chunk of text, as byte
//! ranges, each with the rule class that sets its confidence row.
//!
//! Rules flag; they do not judge. A span a rule is unsure of keeps its place
//! with a lower confidence, and the policy row's band sends it to the typing
//! rung. Text inside code (a fenced block or an inline code span) is not
//! prose and is never read for names or dates.

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

const MONTHS: &str = "jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?";

/// Words a capitalized run never starts with or holds: sentence openers and
/// the calendar's own words, which the date rules read.
const NOT_NAMES: &[&str] = &[
    "a", "an", "and", "but", "he", "how", "i", "i'll", "i'm", "i've", "i'd", "if", "it", "it's",
    "my", "no", "ok", "she", "so", "that", "that's", "the", "then", "there", "there's", "they",
    "this", "we", "we'll", "we've", "what", "when", "why", "you", "you'll", "you're", "yes",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "january",
    "february", "march", "april", "june", "july", "august", "september",
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

    /// Every date and name span of `text`, in text order, none overlapping.
    pub(super) fn spans(&self, text: &str) -> Vec<RuleSpan> {
        let code = code_ranges(text);
        let outside = |start: usize, end: usize| {
            !code
                .iter()
                .any(|&(from, to)| start < to && from < end)
        };
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
            .chain(temporal_phrase_spans(text).into_iter().map(|phrase| RuleSpan {
                start: phrase.start,
                end: phrase.end,
                class: if phrase.resolved {
                    RuleClass::RelativeDate
                } else {
                    RuleClass::VagueDate
                },
            }))
            .filter(|span| outside(span.start, span.end))
            .collect();
        let mut spans = longest_first(&mut dates);
        let names: Vec<_> = name_spans(text)
            .into_iter()
            .filter(|name| {
                outside(name.start, name.end)
                    && !spans
                        .iter()
                        .any(|date| name.start < date.end && date.start < name.end)
            })
            .collect();
        spans.extend(names);
        spans.sort_by_key(|span| (span.start, span.end));
        spans
    }
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

/// The byte ranges of fenced code blocks and inline code spans.
fn code_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut fence: Option<usize> = None;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let fenced = line.trim_start().starts_with("```");
        match (fence, fenced) {
            (None, true) => fence = Some(offset),
            (Some(start), true) => {
                ranges.push((start, offset + line.len()));
                fence = None;
            }
            (Some(_), false) => {}
            (None, false) => {
                let mut open: Option<usize> = None;
                for (at, ch) in line.char_indices() {
                    if ch == '`' {
                        match open {
                            None => open = Some(offset + at),
                            Some(start) => {
                                ranges.push((start, offset + at + 1));
                                open = None;
                            }
                        }
                    }
                }
            }
        }
        offset += line.len();
    }
    if let Some(start) = fence {
        ranges.push((start, text.len()));
    }
    ranges
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

fn words(text: &str) -> Vec<Word> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut words = Vec::new();
    let mut opens = true;
    let mut index = 0;
    while index < chars.len() {
        let (at, ch) = chars[index];
        if !ch.is_alphanumeric() {
            if matches!(ch, '.' | '!' | '?' | '\n' | '。' | '！' | '？') {
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
                && chars.get(end + 1).is_some_and(|(_, next)| next.is_alphanumeric());
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
fn name_spans(text: &str) -> Vec<RuleSpan> {
    let mut spans = Vec::new();
    let words = words(text);
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
