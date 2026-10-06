//! Re-prefill accounting: the prefix-cache loss OF-263 does not price.
//!
//! A provider caches the prompt prefix a call has already prefilled. When the
//! next call's prompt extends that prefix (an append), only the new tail is
//! fresh input. When it edits an earlier position, everything from the first
//! changed byte to the end of the new prompt is prefilled again. That edited
//! tail is the re-prefill. A single-shot call has no earlier prompt and
//! re-prefills nothing.
//!
//! This is the quantity the ctx-arms window's `checkpoint()` counts per model
//! call (first edited cached position to the window end). ctx-arms can switch
//! to [`reprefill_tokens`] and the shared `CostComponentReport` column when
//! its branch rebases onto this one.

/// Tokens re-prefilled when `next` follows `previous` in one cached lineage.
/// An extension or a shrink re-prefills 0; an edit re-prefills the tokens of
/// `next` from the first differing byte (backed off to a char boundary).
pub(crate) fn reprefill_tokens(previous: &str, next: &str, count: impl Fn(&str) -> u64) -> u64 {
    let mut common = previous
        .bytes()
        .zip(next.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    if common == previous.len() || common == next.len() {
        return 0;
    }
    while !next.is_char_boundary(common) {
        common -= 1;
    }
    count(&next[common..])
}

/// The real offline tokenizer the BEAM reports already count with.
pub(crate) fn context_pack_tokens(text: &str) -> u64 {
    oneiron::count_context_pack_tokens(text) as u64
}

/// One prompt lineage: the calls that share a system prompt and a cache.
#[derive(Debug, Default)]
pub(crate) struct PrefixCache {
    last: Option<String>,
}

impl PrefixCache {
    /// Records one call's full prompt and returns what it re-prefilled.
    pub(crate) fn call(&mut self, prompt: String) -> u64 {
        let reprefill = self.last.as_deref().map_or(0, |previous| {
            reprefill_tokens(previous, &prompt, context_pack_tokens)
        });
        self.last = Some(prompt);
        reprefill
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes4(text: &str) -> u64 {
        (text.len() as u64).div_ceil(4)
    }

    #[test]
    fn appends_and_shrinks_reprefill_nothing() {
        assert_eq!(reprefill_tokens("abcd", "abcdefgh", bytes4), 0);
        assert_eq!(reprefill_tokens("abcdefgh", "abcd", bytes4), 0);
        assert_eq!(reprefill_tokens("same", "same", bytes4), 0);
    }

    #[test]
    fn an_edit_reprefills_from_the_first_changed_byte_to_the_end() {
        // 4 bytes kept, 12 bytes from the edit to the end of the new prompt.
        assert_eq!(
            reprefill_tokens("keep-old-tail", "keep-new-tail-more", bytes4),
            4
        );
        assert_eq!(reprefill_tokens("abcdefgh", "Xbcdefgh", bytes4), 2);
    }

    #[test]
    fn edits_inside_a_multibyte_char_back_off_to_its_boundary() {
        // "é" and "è" share their first UTF-8 byte; the tail starts at the char.
        assert_eq!(reprefill_tokens("café", "cafè", |t| t.len() as u64), 2);
    }

    #[test]
    fn a_lineage_charges_only_edits_after_the_first_call() {
        let mut cache = PrefixCache::default();
        assert_eq!(cache.call("system\n{\"evidence\":\"\"}".into()), 0);
        assert_eq!(cache.call("system\n{\"evidence\":\"\"} more".into()), 0);
        assert!(cache.call("system\n{\"evidence\":\"new pack\"}".into()) > 0);
    }
}
