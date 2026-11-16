//! Khmer syllable canonicalization (ONE-COENG, ARCH-0031 `#deferred`).
//!
//! Khmer lets one visual syllable be typed in several orders: the subscript
//! consonants (COENG U+17D2 + consonant), ROBAT, the register shifters, the
//! vowels and the signs after a base all render the same in any order, so the
//! same word can reach the index as different bytes. UTN #61 "Khmer Encoding
//! Structure" (M. Hosken, v2 2025-02-06), the published form of L2/22-290,
//! fixes one order. This is a port of the core of its MIT-licensed reference
//! normalizer `khnormal` (Copyright (c) 2021-2024, SIL Global) for modern
//! Khmer:
//!
//! 1. each character takes a category; a base or COENG right after COENG or
//!    ZWJ takes the category of the character before it, so a subscript
//!    consonant travels with its COENG;
//! 2. a syllable is a base followed by every character of a later category;
//!    its characters are sorted by category, stably, so characters of one
//!    category keep the order they were typed in;
//! 3. inside a sorted syllable, the reference's fixed folds: repeated
//!    invisible characters after COENG collapse, the "do not use" vowel
//!    sequences become their single vowels, COENG RO moves after the other
//!    subscript, and COENG DA becomes COENG TA (the two render the same).
//!
//! Two of the reference's folds are left out. Its lunar-date folds read Khmer
//! digits, which never stand inside a syllable. Its "-u + upper vowel ->
//! shifter" fold passes `re.X` as `re.sub`'s count argument, so its verbose
//! pattern is matched literally and never fires; leaving it out keeps this
//! output equal to the reference's.
//!
//! [`super::normalize::normalize_with_offset_map`] runs this before NFKC and
//! casefold. It hands over whole syllables: [`SyllableScanner`] joins a
//! grapheme to the previous one while a syllable runs across them, because
//! the consonant after COENG starts a new grapheme.

use std::borrow::Cow;

const COENG: char = '\u{17D2}';
const ZWJ: char = '\u{200D}';
const ZWNJ: char = '\u{200C}';
const RO: char = '\u{179A}';
const DA: char = '\u{178A}';
const TA: char = '\u{178F}';
/// The vowel sign E (U+17C1), the first half of the "do not use" sequences.
const VOWEL_E: char = '\u{17C1}';
/// The vowel sign OE (U+17BE).
const VOWEL_OE: char = '\u{17BE}';
/// The vowel sign OO (U+17C4).
const VOWEL_OO: char = '\u{17C4}';
/// The vowel sign AA (U+17B6).
const VOWEL_AA: char = '\u{17B6}';
/// The vowel sign II (U+17B8).
const VOWEL_II: char = '\u{17B8}';
/// The vowel sign U (U+17BB).
const VOWEL_U: char = '\u{17BB}';

/// A character's place in a canonical syllable, in sort order (the
/// reference's `Cats`, same values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Category {
    Other = 0,
    Base = 1,
    Robat = 2,
    Coeng = 3,
    Shifter = 4,
    ZeroWidthNonJoiner = 5,
    VowelPre = 6,
    VowelBelow = 7,
    VowelAbove = 8,
    VowelPost = 9,
    Modifier = 10,
    FinalModifier = 11,
    /// ZWJ: it marks a final COENG, which sorts last.
    FinalCoeng = 12,
}

fn category(c: char) -> Category {
    match u32::from(c) {
        0x1780..=0x17A2 | 0x17A5..=0x17B3 => Category::Base,
        0x17B6 => Category::VowelPost,
        0x17B7..=0x17BA => Category::VowelAbove,
        0x17BB..=0x17BD => Category::VowelBelow,
        0x17BE..=0x17C5 => Category::VowelPre,
        0x17C6 | 0x17CB | 0x17CD..=0x17D1 | 0x17D3 | 0x17DD => Category::Modifier,
        0x17C7..=0x17C8 => Category::FinalModifier,
        0x17C9..=0x17CA => Category::Shifter,
        0x17CC => Category::Robat,
        0x17D2 => Category::Coeng,
        0x200C => Category::ZeroWidthNonJoiner,
        0x200D => Category::FinalCoeng,
        _ => Category::Other,
    }
}

/// Step 1: the category `c` takes after `previous` (the character before it
/// and the category that one took).
fn category_after(previous: Option<(char, Category)>, c: char) -> (Category, bool) {
    let own = category(c);
    match previous {
        Some((COENG | ZWJ, taken)) if matches!(own, Category::Base | Category::Coeng) => {
            (taken, true)
        }
        _ => (own, false),
    }
}

/// Tracks the syllable a run of graphemes leaves open, so the caller cuts
/// units only where a syllable cannot continue.
#[derive(Debug, Default)]
pub(crate) struct SyllableScanner {
    previous: Option<(char, Category)>,
    open: bool,
}

impl SyllableScanner {
    /// Feeds the next grapheme. True when its first character belongs with
    /// the previous grapheme: it continues the open syllable, or it takes
    /// its category from the character before it. Canonicalizing the two
    /// apart would then differ from canonicalizing them together.
    pub(crate) fn joins_previous(&mut self, grapheme: &str) -> bool {
        let mut chars = grapheme.chars();
        let Some(head) = chars.next() else {
            return false;
        };
        let joins = self.advance(head);
        for c in chars {
            self.advance(c);
        }
        joins
    }

    fn advance(&mut self, c: char) -> bool {
        let (taken, recategorized) = category_after(self.previous, c);
        let continues = self.open && taken > Category::Base;
        self.open = taken == Category::Base || continues;
        self.previous = Some((c, taken));
        continues || recategorized
    }
}

/// `unit` with every Khmer syllable in UTN #61 order. Borrowed when nothing
/// changes, which is every unit without a Khmer character.
pub(crate) fn canonical_order(unit: &str) -> Cow<'_, str> {
    if !unit
        .chars()
        .any(|c| matches!(u32::from(c), 0x1780..=0x17FF))
    {
        return Cow::Borrowed(unit);
    }
    let chars: Vec<char> = unit.chars().collect();
    let mut categories = Vec::with_capacity(chars.len());
    let mut previous = None;
    for &c in &chars {
        let (taken, _) = category_after(previous, c);
        categories.push(taken);
        previous = Some((c, taken));
    }

    let mut out: Vec<char> = Vec::with_capacity(chars.len());
    let mut start = 0;
    while start < chars.len() {
        if categories[start] != Category::Base {
            out.push(chars[start]);
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < chars.len() && categories[end] > Category::Base {
            end += 1;
        }
        let mut order: Vec<usize> = (start..end).collect();
        // Stable: characters of one category keep their typed order.
        order.sort_by_key(|&index| categories[index]);
        let syllable: Vec<char> = order.into_iter().map(|index| chars[index]).collect();
        out.extend(fold_syllable(&syllable));
        start = end;
    }

    if out == chars {
        Cow::Borrowed(unit)
    } else {
        Cow::Owned(out.into_iter().collect())
    }
}

/// Step 3, in the reference's order, on one sorted syllable.
fn fold_syllable(syllable: &[char]) -> Vec<char> {
    let folded = collapse_invisibles_after_coeng(syllable);
    let folded = replace_pair(&folded, [VOWEL_OE, VOWEL_AA], [VOWEL_OO, VOWEL_II]);
    let folded = fold_vowel_e(&folded, VOWEL_II, VOWEL_OE);
    let folded = fold_vowel_e(&folded, VOWEL_AA, VOWEL_OO);
    let folded = replace_pair(&folded, [VOWEL_OE, VOWEL_U], [VOWEL_U, VOWEL_OE]);
    let folded = coeng_ro_second(&folded);
    replace_pair(&folded, [COENG, DA], [COENG, TA])
}

/// `(ZWJ? COENG)[COENG ZWNJ ZWJ]+` -> `ZWJ? COENG`.
fn collapse_invisibles_after_coeng(chars: &[char]) -> Vec<char> {
    let mut out = Vec::with_capacity(chars.len());
    let mut index = 0;
    while index < chars.len() {
        let prefix = match (chars[index], chars.get(index + 1)) {
            (ZWJ, Some(&COENG)) => 2,
            (COENG, _) => 1,
            _ => 0,
        };
        if prefix > 0 {
            let mut end = index + prefix;
            while end < chars.len() && matches!(chars[end], COENG | ZWNJ | ZWJ) {
                end += 1;
            }
            if end > index + prefix {
                out.extend_from_slice(&chars[index..index + prefix]);
                index = end;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

/// Every non-overlapping `from`, left to right, becomes `to`.
fn replace_pair(chars: &[char], from: [char; 2], to: [char; 2]) -> Vec<char> {
    let mut out = Vec::with_capacity(chars.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index..].starts_with(&from) {
            out.extend_from_slice(&to);
            index += 2;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

/// `E ([U-UA]?) <tail>` -> `<vowel> $1`: the two-part spellings of OE and OO.
fn fold_vowel_e(chars: &[char], tail: char, vowel: char) -> Vec<char> {
    let mut out = Vec::with_capacity(chars.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == VOWEL_E {
            match (chars.get(index + 1), chars.get(index + 2)) {
                (Some(&below), Some(&next))
                    if matches!(u32::from(below), 0x17BB..=0x17BD) && next == tail =>
                {
                    out.extend([vowel, below]);
                    index += 3;
                    continue;
                }
                (Some(&next), _) if next == tail => {
                    out.push(vowel);
                    index += 2;
                    continue;
                }
                _ => {}
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

/// `(COENG RO)(COENG [U+1780-U+17B3])` -> `$2$1`.
fn coeng_ro_second(chars: &[char]) -> Vec<char> {
    let mut out = Vec::with_capacity(chars.len());
    let mut index = 0;
    while index < chars.len() {
        if let [COENG, RO, COENG, other, ..] = &chars[index..]
            && matches!(u32::from(*other), 0x1780..=0x17B3)
        {
            out.extend([COENG, *other, COENG, RO]);
            index += 4;
            continue;
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ស្ត្រី ("woman") in UTN #61 order: SA, COENG TA, COENG RO, II.
    const CANONICAL: &str = "\u{179F}\u{17D2}\u{178F}\u{17D2}\u{179A}\u{17B8}";

    #[test]
    fn coeng_ro_moves_after_the_other_subscript() {
        let typed = "\u{179F}\u{17D2}\u{179A}\u{17D2}\u{178F}\u{17B8}";
        assert_eq!(canonical_order(typed), CANONICAL);
    }

    #[test]
    fn a_vowel_typed_before_its_subscripts_sorts_after_them() {
        let typed = "\u{179F}\u{17B8}\u{17D2}\u{178F}\u{17D2}\u{179A}";
        assert_eq!(canonical_order(typed), CANONICAL);
    }

    #[test]
    fn coeng_da_becomes_coeng_ta() {
        let typed = "\u{179F}\u{17D2}\u{178A}\u{17D2}\u{179A}\u{17B8}";
        assert_eq!(canonical_order(typed), CANONICAL);
    }

    #[test]
    fn the_two_part_vowel_spellings_fold() {
        // KA + E + II -> KA + OE; KA + E + AA -> KA + OO; KA + OE + AA -> KA + OO + II.
        assert_eq!(
            canonical_order("\u{1780}\u{17C1}\u{17B8}"),
            "\u{1780}\u{17BE}"
        );
        assert_eq!(
            canonical_order("\u{1780}\u{17C1}\u{17B6}"),
            "\u{1780}\u{17C4}"
        );
        assert_eq!(
            canonical_order("\u{1780}\u{17BE}\u{17B6}"),
            "\u{1780}\u{17C4}\u{17B8}"
        );
    }

    #[test]
    fn canonical_and_non_khmer_text_is_borrowed() {
        assert!(matches!(canonical_order(CANONICAL), Cow::Borrowed(_)));
        assert!(matches!(canonical_order("plain words"), Cow::Borrowed(_)));
    }

    #[test]
    fn the_scanner_joins_the_consonant_after_coeng() {
        let mut scanner = SyllableScanner::default();
        assert!(!scanner.joins_previous("\u{179F}\u{17D2}"));
        assert!(scanner.joins_previous("\u{179A}"));
        assert!(!scanner.joins_previous(" "));
        assert!(!scanner.joins_previous("\u{1780}"));
    }
}
