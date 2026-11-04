//! A constant-time lookup into the BIP39 list for the shape checks. A word of
//! at most [`MAX_LIST_WORD_LEN`] ASCII letters is packed into one `u64` key
//! (its lower-case bytes, little-endian, zero-padded), so a token is matched
//! by one hash probe instead of a binary search over strings.

use std::sync::LazyLock;

use super::{MAX_LIST_WORD_LEN, WORDS};

/// Open-addressed slots: twice the list, so probes stay short.
const SLOTS: usize = 4096;

/// The list's keys and a slot table over them.
pub(super) struct WordLookup {
    /// Each list word's key, at its position on the list.
    keys: Vec<u64>,
    /// 0 is an empty slot; otherwise the word's position plus one.
    slots: Vec<u16>,
}

static LOOKUP: LazyLock<WordLookup> = LazyLock::new(|| {
    let mut keys = Vec::with_capacity(WORDS.len());
    let mut slots = vec![0_u16; SLOTS];
    for (position, word) in WORDS.iter().enumerate() {
        let key = word_key(word.as_bytes()).unwrap_or(0);
        keys.push(key);
        let mut slot = slot_of(key);
        while slots[slot] != 0 {
            slot = (slot + 1) & (SLOTS - 1);
        }
        // The list holds 2,048 words, so every position fits.
        slots[slot] = u16::try_from(position + 1).unwrap_or(u16::MAX);
    }
    WordLookup { keys, slots }
});

/// The lookup, built on first use.
pub(super) fn lookup() -> &'static WordLookup {
    &LOOKUP
}

/// The key of `word`: its bytes lower-cased, or `None` where no list word can
/// match, a word longer than the longest list word or holding a byte that is
/// not an ASCII letter (every list word is lower-case ASCII letters).
pub(super) fn word_key(word: &[u8]) -> Option<u64> {
    if word.len() > MAX_LIST_WORD_LEN {
        return None;
    }
    let mut key = 0_u64;
    for (at, &byte) in word.iter().enumerate() {
        if !byte.is_ascii_alphabetic() {
            return None;
        }
        key |= u64::from(byte.to_ascii_lowercase()) << (8 * at);
    }
    Some(key)
}

fn slot_of(key: u64) -> usize {
    let mixed = (key ^ (key >> 32)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    // The top 12 bits pick one of the 4,096 slots.
    usize::try_from(mixed >> 52).unwrap_or(0)
}

impl WordLookup {
    /// The position on the list of the word whose key is `key`, if it is a
    /// list word: the index a binary search of the sorted list finds.
    pub(super) fn index(&self, key: u64) -> Option<u16> {
        let mut slot = slot_of(key);
        loop {
            let entry = *self.slots.get(slot)?;
            if entry == 0 {
                return None;
            }
            let position = entry - 1;
            if self.keys.get(usize::from(position)) == Some(&key) {
                return Some(position);
            }
            slot = (slot + 1) & (SLOTS - 1);
        }
    }
}
