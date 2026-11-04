//! A fast reject for [`super::mnemonic`] that never skips a phrase: text with
//! fewer list words in a row than the shortest phrase holds no phrase.

use super::{MAX_LIST_WORD_LEN, PHRASE_WORDS, word_lookup};

/// Whether `text` holds as many list words in a row as the shortest phrase:
/// whole runs of ASCII letters that [`super::list_word_index`] finds on the
/// list, with no other run of letters between them. Every phrase
/// [`super::mnemonic`] accepts is such a run, since its words come from one
/// segment, or from segments in a row, that hold no word off the list, and
/// only letters make a word. Text without one holds no phrase.
pub(super) fn holds_list_word_run(text: &str) -> bool {
    let Some(shortest) = PHRASE_WORDS.iter().copied().min() else {
        return false;
    };
    // bench-only (L15-LEAD, never merge): L15_TRY=no_word_lookup runs the old binary search.
    if crate::stage_timing::try_on("no_word_lookup") {
        return holds_list_word_run_search(text, shortest);
    }
    let lookup = word_lookup::lookup();
    let mut run = 0_usize;
    let mut letters = 0_usize;
    // The word's lower-case letters so far, packed as its lookup key.
    let mut key = 0_u64;
    // Only ASCII bytes are letters, so a byte walk reads the words the
    // stream's char walk reads; a blank past the end ends the last word.
    for byte in text.bytes().chain([b' ']) {
        if byte.is_ascii_alphabetic() {
            if letters < MAX_LIST_WORD_LEN {
                key |= u64::from(byte.to_ascii_lowercase()) << (8 * letters);
            }
            letters += 1;
            continue;
        }
        if letters == 0 {
            continue;
        }
        // A word longer than the longest list word is off the list.
        let listed = letters <= MAX_LIST_WORD_LEN && lookup.index(key).is_some();
        letters = 0;
        key = 0;
        run = if listed { run + 1 } else { 0 };
        if run >= shortest {
            return true;
        }
    }
    false
}

/// bench-only (never merge): the binary-search prefilter this row replaced.
fn holds_list_word_run_search(text: &str, shortest: usize) -> bool {
    let mut run = 0_usize;
    let mut letters = 0_usize;
    let mut lower = [0_u8; MAX_LIST_WORD_LEN];
    for byte in text.bytes().chain([b' ']) {
        if byte.is_ascii_alphabetic() {
            if let Some(slot) = lower.get_mut(letters) {
                *slot = byte.to_ascii_lowercase();
            }
            letters += 1;
            continue;
        }
        if letters == 0 {
            continue;
        }
        let listed = lower.get(..letters).is_some_and(|word| {
            super::WORDS
                .binary_search_by(|entry| entry.as_bytes().cmp(word))
                .is_ok()
        });
        letters = 0;
        run = if listed { run + 1 } else { 0 };
        if run >= shortest {
            return true;
        }
    }
    false
}
