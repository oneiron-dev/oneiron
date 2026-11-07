//! The person's backchannel while the agent holds the floor (FIX 4899,
//! ARCH-0061 #backchannel): "mm-hmm", "yeah", "うん", "なるほど". A
//! backchannel keeps the agent talking; it does not take the floor or start
//! a reply. Only the listening side is here: the agent's own aizuchi is not
//! ruled.
//!
//! Entry: [`is_backchannel`]; [`may_become_backchannel`] for a partial.

/// The words a person says to keep the agent talking, not to take the floor
/// (CALLS, FIX 4899): an engine call. Matched whole, after the text is
/// normalised as [`is_backchannel`] says; a text that is several of them in
/// a row ("oh, I see", "うんうん、なるほど") is a backchannel too.
pub const BACKCHANNEL_LEXICON: &[&str] = &[
    // English.
    "mm",
    "mhm",
    "mm-hmm",
    "uh-huh",
    "uh",
    "yeah",
    "yep",
    "yes",
    "right",
    "okay",
    "ok",
    "sure",
    "exactly",
    "i see",
    "got it",
    "oh",
    "ah",
    "hmm",
    "wow",
    // Japanese aizuchi.
    "うん",
    "うんうん",
    "はい",
    "はいはい",
    "はーい",
    "ええ",
    "そう",
    "そうそう",
    "そっか",
    "そうか",
    "そうですね",
    "そうなんだ",
    "なるほど",
    "なるほどね",
    "たしかに",
    "確かに",
    "へえ",
    "へぇ",
    "へー",
    "ふーん",
    "ほう",
    "ほー",
    "あー",
    "ああ",
];

/// Whether `text` is only a backchannel: normalised (lowercase, every mark
/// that is not a letter or a digit dropped with the whitespace, and each run
/// of one repeated character folded to one), it is one or more
/// [`BACKCHANNEL_LEXICON`] entries, normalised the same way, in a row.
/// Folding makes "mmm" and "mm" one word, and "mm-hmm" and "mhm"; a
/// repeated entry ("yeah yeah", "はいはい") is entries in a row. A text with
/// no letters or digits is no backchannel.
#[must_use]
pub fn is_backchannel(text: &str) -> bool {
    entries_in_row(text, false)
}

/// Whether `text` can still become a backchannel as the person goes on
/// (FIX 4899): normalised as [`is_backchannel`] says, it is entries in a
/// row, then nothing or the start of one more entry. The start is matched
/// by character, so an entry's first words ("i" of "i see") and an entry
/// not yet finished ("yea" of "yeah", "なる" of "なるほど") both count. A
/// partial like this is undecided: it does not take the floor.
pub(crate) fn may_become_backchannel(text: &str) -> bool {
    entries_in_row(text, true)
}

/// Whether `text`, normalised, is [`BACKCHANNEL_LEXICON`] entries in a
/// row, and, when `open_end`, then the start of one more entry.
fn entries_in_row(text: &str, open_end: bool) -> bool {
    let words = normalised(text);
    if words.is_empty() {
        return false;
    }
    let entries: Vec<Vec<char>> = BACKCHANNEL_LEXICON
        .iter()
        .map(|entry| normalised(entry))
        .filter(|entry| !entry.is_empty())
        .collect();
    // Each place `at` the text's first `at` characters are entries in a row,
    // reached once.
    let mut reached = vec![false; words.len() + 1];
    let mut places = vec![0];
    while let Some(at) = places.pop() {
        let rest = &words[at..];
        if rest.is_empty() || (open_end && entries.iter().any(|entry| entry.starts_with(rest))) {
            return true;
        }
        for entry in &entries {
            let next = at + entry.len();
            if rest.starts_with(entry) && !reached[next] {
                reached[next] = true;
                places.push(next);
            }
        }
    }
    false
}

/// Whether `text` holds any letter or digit: words, not only marks.
pub(crate) fn has_words(text: &str) -> bool {
    text.chars().any(char::is_alphanumeric)
}

/// `text` lowercased, with only its letters and digits, each run of one
/// repeated character folded to one.
fn normalised(text: &str) -> Vec<char> {
    let mut folded: Vec<char> = Vec::with_capacity(text.len());
    for character in text.chars().flat_map(char::to_lowercase) {
        if character.is_alphanumeric() && folded.last() != Some(&character) {
            folded.push(character);
        }
    }
    folded
}
