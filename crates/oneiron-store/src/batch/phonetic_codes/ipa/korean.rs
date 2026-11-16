//! The Korean reading (`kor`): each Hangul syllable split into its jamo,
//! each jamo read as one sound. No sound change across syllables (v1).

use super::super::features::{Segment, ipa_segments};

/// The first precomposed Hangul syllable, 가.
const FIRST_SYLLABLE: u32 = 0xAC00;
/// The last precomposed Hangul syllable, 힣.
const LAST_SYLLABLE: u32 = 0xD7A3;

/// The 19 initial consonants, in Unicode order: lenis plain, tense voiceless,
/// aspirated with `ʰ`; ㅇ is silent.
const INITIALS: [&str; 19] = [
    "ɡ", "k", "n", "d", "t", "ɾ", "m", "b", "p", "s", "s", "", "d͡ʑ", "t͡ɕ", "t͡ɕʰ", "kʰ", "tʰ", "pʰ",
    "h",
];

/// The 21 vowels, in Unicode order.
const MEDIALS: [&str; 21] = [
    "a", "ɛ", "ja", "jɛ", "ʌ", "e", "jʌ", "je", "o", "wa", "wɛ", "we", "jo", "u", "wʌ", "we", "wi",
    "ju", "ɯ", "ɯi", "i",
];

/// No final, then the 27 finals in Unicode order, each read as the one sound
/// it has at the end of a syllable.
const FINALS: [&str; 28] = [
    "", "k", "k", "k", "n", "n", "n", "t", "l", "k", "m", "l", "l", "l", "p", "l", "m", "p", "p",
    "t", "t", "ŋ", "t", "t", "k", "t", "p", "t",
];

/// Whether `c` is a precomposed Hangul syllable.
pub(super) fn is_hangul_syllable(c: char) -> bool {
    (FIRST_SYLLABLE..=LAST_SYLLABLE).contains(&u32::from(c))
}

/// The reading of a run of Hangul syllables.
pub(super) fn hangul_reading(hangul: &str) -> Option<Vec<Segment>> {
    let mut ipa = String::new();
    for syllable in hangul.chars().filter(|c| is_hangul_syllable(*c)) {
        let index = (u32::from(syllable) - FIRST_SYLLABLE) as usize;
        ipa.push_str(INITIALS[index / 588]);
        ipa.push_str(MEDIALS[index % 588 / 28]);
        ipa.push_str(FINALS[index % 28]);
    }
    ipa_segments(&ipa)
}
