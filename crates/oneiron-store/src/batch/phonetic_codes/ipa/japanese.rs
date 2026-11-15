//! The Japanese reading (`jpn`): Hepburn romaji read syllable by syllable.
//! Kana are first romanized by the romaji key's own reader, so a kana name
//! and its Hepburn spelling read alike by construction.

use super::super::features::{Segment, ipa_segments};

/// Syllable onsets in Hepburn spelling, longest first, with their IPA. The
/// empty onset is a syllable of a vowel alone.
const ONSETS: [(&str, &str); 35] = [
    ("ch", "t͡ɕ"),
    ("sh", "ɕ"),
    ("ts", "t͡s"),
    ("ky", "kj"),
    ("gy", "ɡj"),
    ("ny", "nj"),
    ("hy", "hj"),
    ("by", "bj"),
    ("py", "pj"),
    ("my", "mj"),
    ("ry", "ɾj"),
    ("kw", "kw"),
    ("gw", "ɡw"),
    ("ty", "tj"),
    ("dy", "dj"),
    ("fy", "ɸj"),
    ("vy", "vj"),
    ("k", "k"),
    ("g", "ɡ"),
    ("s", "s"),
    ("z", "z"),
    ("j", "d͡ʑ"),
    ("t", "t"),
    ("d", "d"),
    ("n", "n"),
    ("h", "h"),
    ("f", "ɸ"),
    ("b", "b"),
    ("p", "p"),
    ("m", "m"),
    ("y", "j"),
    ("r", "ɾ"),
    ("w", "w"),
    ("v", "v"),
    ("", ""),
];

/// The five vowels; `u` is unrounded.
const VOWELS: [(char, &str); 5] = [('a', "a"), ('i', "i"), ('u', "ɯ"), ('e', "e"), ('o', "o")];

/// Vowels read twice in a row, and o followed by u, are one long vowel.
const LONG_VOWELS: [(&str, &str, &str); 6] = [
    ("a", "a", "aː"),
    ("i", "i", "iː"),
    ("ɯ", "ɯ", "ɯː"),
    ("e", "e", "eː"),
    ("o", "o", "oː"),
    ("o", "ɯ", "oː"),
];

/// The reading of a run of hiragana (katakana already folded), through its
/// Hepburn romaji.
pub(super) fn kana_reading(kana: &str) -> Option<Vec<Segment>> {
    let romaji = super::super::romanize(kana)?;
    latin_reading(&[romaji.as_str()])
}

/// The reading of Latin words when every one of them parses as Hepburn
/// syllables, `None` otherwise.
pub(super) fn latin_reading(words: &[&str]) -> Option<Vec<Segment>> {
    let mut segments = Vec::new();
    for word in words {
        segments.extend(lengthen_vowels(&word_reading(word)?));
    }
    (!segments.is_empty()).then_some(segments)
}

/// One word's IPA, syllable by syllable. Each position takes the longest
/// syllable after which the rest of the word still parses: a consonant and a
/// vowel, a doubled consonant (っ), or a syllabic n (ん).
fn word_reading(word: &str) -> Option<String> {
    if !word.is_ascii() {
        return None;
    }
    // parsed[i]: the IPA of word[i..], when it parses.
    let mut parsed: Vec<Option<String>> = vec![None; word.len() + 1];
    parsed[word.len()] = Some(String::new());
    for start in (0..word.len()).rev() {
        parsed[start] = syllables_at(&word[start..])
            .into_iter()
            .find_map(|(length, ipa)| Some(format!("{ipa}{}", parsed[start + length].as_ref()?)));
    }
    parsed[0].take().filter(|ipa| !ipa.is_empty())
}

/// The syllables `rest` can begin with, longest first, as (length in bytes,
/// IPA).
fn syllables_at(rest: &str) -> Vec<(usize, String)> {
    let mut syllables = Vec::new();
    for (onset, onset_ipa) in ONSETS {
        let Some(after) = rest.strip_prefix(onset) else {
            continue;
        };
        if let Some(vowel) = after.chars().next()
            && let Some((_, vowel_ipa)) = VOWELS.iter().find(|(letter, _)| *letter == vowel)
        {
            syllables.push((onset.len() + 1, format!("{onset_ipa}{vowel_ipa}")));
        }
    }
    if let Some(geminate) = geminate_ipa(rest) {
        syllables.push((1, geminate.to_owned()));
    }
    if rest.starts_with('n') {
        syllables.push((1, "n".to_owned()));
    }
    syllables
}

/// A doubled consonant (`kk`, `ss`, `tt`, and `t` before `ch`): the first
/// segment of the onset it doubles.
fn geminate_ipa(rest: &str) -> Option<&'static str> {
    let first = rest.chars().next()?;
    if matches!(first, 'a' | 'i' | 'u' | 'e' | 'o' | 'n') {
        return None;
    }
    let after = &rest[first.len_utf8()..];
    let &(_, ipa) = ONSETS.iter().find(|(onset, _)| {
        !onset.is_empty()
            && after.starts_with(*onset)
            && (onset.starts_with(first) || (first == 't' && *onset == "ch"))
    })?;
    let length = ipa_segments(ipa)?.first()?.symbol().len();
    Some(&ipa[..length])
}

/// Long vowels: a vowel read twice in a row, or o before u, is one long
/// vowel (さとう, Satou: [satoː]).
fn lengthen_vowels(ipa: &str) -> Vec<Segment> {
    let mut segments: Vec<Segment> = Vec::new();
    for segment in ipa_segments(ipa).unwrap_or_default() {
        let long = segments.last().and_then(|previous| {
            LONG_VOWELS
                .iter()
                .find(|(first, second, _)| {
                    *first == previous.symbol() && *second == segment.symbol()
                })
                .and_then(|(_, _, long)| ipa_segments(long))
        });
        match long {
            Some(long) => {
                segments.pop();
                segments.extend(long);
            }
            None => segments.push(segment),
        }
    }
    segments
}
