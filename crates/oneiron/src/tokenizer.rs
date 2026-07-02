pub const DEFAULT_CONTEXT_PACK_TOKENIZER_ID: &str = "o200k_base";
pub const DEFAULT_CONTEXT_PACK_TOKENIZER: PackTokenizer = PackTokenizer::O200kBase;

pub trait ContextPackTokenizer {
    fn id(&self) -> &'static str;
    fn count(&self, text: &str) -> usize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackTokenizer {
    O200kBase,
}

impl PackTokenizer {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::O200kBase => DEFAULT_CONTEXT_PACK_TOKENIZER_ID,
        }
    }

    #[must_use]
    pub fn count(self, text: &str) -> usize {
        match self {
            // tiktoken-rs vendors this vocabulary with include_str!, so pack
            // accounting is offline at runtime and at benchmark time.
            Self::O200kBase => tiktoken_rs::o200k_base_singleton().count_ordinary(text),
        }
    }
}

impl ContextPackTokenizer for PackTokenizer {
    fn id(&self) -> &'static str {
        (*self).id()
    }

    fn count(&self, text: &str) -> usize {
        (*self).count(text)
    }
}

#[must_use]
pub fn count_context_pack_tokens(text: &str) -> usize {
    DEFAULT_CONTEXT_PACK_TOKENIZER.count(text)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_CONTEXT_PACK_TOKENIZER, DEFAULT_CONTEXT_PACK_TOKENIZER_ID,
        count_context_pack_tokens,
    };

    #[test]
    fn tokenizer_id_and_counts_are_deterministic() {
        let text = "Oneiron context pack tokenizer determinism テスト";

        assert_eq!(DEFAULT_CONTEXT_PACK_TOKENIZER.id(), "o200k_base");
        assert_eq!(DEFAULT_CONTEXT_PACK_TOKENIZER_ID, "o200k_base");
        assert_eq!(
            count_context_pack_tokens(text),
            DEFAULT_CONTEXT_PACK_TOKENIZER.count(text)
        );
        assert_eq!(
            DEFAULT_CONTEXT_PACK_TOKENIZER.count(text),
            DEFAULT_CONTEXT_PACK_TOKENIZER.count(text)
        );
        assert!(count_context_pack_tokens(text) > 0);
    }
}
