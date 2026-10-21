//! The FIX6 verbatim-span guard: an invented example shares no run of words
//! with the real chat it was drawn from. Text is NFKC-folded and lowercased
//! and split at every character that is not a letter or digit, so case,
//! punctuation and spacing cannot hide a copied run. A CJK, kana or hangul
//! character is a word of its own and weighs half a word.

use std::collections::{BTreeSet, HashSet};

use unicode_normalization::UnicodeNormalization;

/// A run of this many words shared with any source turn withholds the
/// example.
pub const CODE_FIX_SPAN_WORDS: usize = 5;
/// A source line at least this many words long withholds the example when
/// it appears whole in it, though shorter than a span.
pub const CODE_FIX_LINE_WORDS: usize = 3;

/// Weights in half words, so a CJK character can weigh half a word.
const WORD: usize = 2;
const CHAR: usize = 1;

type Word = (String, usize);

/// Every span of `export` that copies one of `sources` (OF-380 L1): each
/// shortest run of [`CODE_FIX_SPAN_WORDS`] words' weight it shares with one,
/// and each line of one at least [`CODE_FIX_LINE_WORDS`] words long that it
/// holds whole, spelled as its folded words. Empty when it copies none.
pub(super) fn verbatim_spans(sources: &[&str], export: &str) -> BTreeSet<String> {
    let target = words(export);
    let span = CODE_FIX_SPAN_WORDS * WORD;
    // Every shared run at least `span` long starts with the same shortest
    // window of that weight on both sides, so comparing those windows finds
    // every such run.
    let seen: HashSet<&[Word]> = windows(&target, span).collect();
    let mut copied = BTreeSet::new();
    for source in sources {
        let source_words = words(source);
        for window in windows(&source_words, span) {
            if seen.contains(window) {
                copied.insert(spell(window));
            }
        }
        for line in source.lines() {
            let line = words(line);
            let weight: usize = line.iter().map(|(_, weight)| weight).sum();
            if weight >= CODE_FIX_LINE_WORDS * WORD
                && target.windows(line.len()).any(|run| run == line.as_slice())
            {
                copied.insert(spell(&line));
            }
        }
    }
    copied
}

/// A run of words as one text, a space between each two.
fn spell(run: &[Word]) -> String {
    run.iter()
        .map(|(word, _)| word.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The shortest run from each start that weighs at least `span`.
fn windows(words: &[Word], span: usize) -> impl Iterator<Item = &[Word]> {
    (0..words.len()).map_while(move |start| {
        let mut weight = 0;
        for (end, (_, w)) in words[start..].iter().enumerate() {
            weight += w;
            if weight >= span {
                return Some(&words[start..=start + end]);
            }
        }
        None
    })
}

fn words(text: &str) -> Vec<Word> {
    let mut out = Vec::new();
    let mut word = String::new();
    for ch in text.nfkc().flat_map(char::to_lowercase) {
        if is_cjk(ch) {
            flush(&mut word, &mut out);
            out.push((ch.to_string(), CHAR));
        } else if ch.is_alphanumeric() {
            word.push(ch);
        } else {
            flush(&mut word, &mut out);
        }
    }
    flush(&mut word, &mut out);
    out
}

fn flush(word: &mut String, out: &mut Vec<Word>) {
    if !word.is_empty() {
        out.push((std::mem::take(word), WORD));
    }
}

fn is_cjk(ch: char) -> bool {
    matches!(
        u32::from(ch),
        0x3040..=0x30FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xAC00..=0xD7AF
            | 0xF900..=0xFAFF
            | 0xFF66..=0xFF9F
            | 0x20000..=0x2FA1F
    )
}
