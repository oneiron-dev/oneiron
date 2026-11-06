pub const DEFAULT_CONTEXT_PACK_TOKENIZER_ID: &str = "o200k_base";
pub const DEFAULT_CONTEXT_PACK_TOKENIZER: PackTokenizer = PackTokenizer::O200kBase;

pub trait ContextPackTokenizer {
    fn id(&self) -> &'static str;
    fn count(&self, text: &str) -> usize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackTokenizer {
    O200kBase,
    O200kHarmony,
    Cl100kBase,
    P50kBase,
    P50kEdit,
    R50kBase,
}

impl PackTokenizer {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::O200kBase => DEFAULT_CONTEXT_PACK_TOKENIZER_ID,
            Self::O200kHarmony => "o200k_harmony",
            Self::Cl100kBase => "cl100k_base",
            Self::P50kBase => "p50k_base",
            Self::P50kEdit => "p50k_edit",
            Self::R50kBase => "r50k_base",
        }
    }

    #[must_use]
    pub fn count(self, text: &str) -> usize {
        match self {
            // tiktoken-rs vendors these vocabularies with include_str!, so pack
            // accounting is offline at runtime and at benchmark time.
            Self::O200kBase => tiktoken_rs::o200k_base_singleton().count_ordinary(text),
            Self::O200kHarmony => tiktoken_rs::o200k_harmony_singleton().count_ordinary(text),
            Self::Cl100kBase => tiktoken_rs::cl100k_base_singleton().count_ordinary(text),
            Self::P50kBase => tiktoken_rs::p50k_base_singleton().count_ordinary(text),
            Self::P50kEdit => tiktoken_rs::p50k_edit_singleton().count_ordinary(text),
            Self::R50kBase => tiktoken_rs::r50k_base_singleton().count_ordinary(text),
        }
    }

    /// The vendored encoding for a provider wire model name, if tiktoken maps it.
    ///
    /// Pure lookup over `tiktoken_rs::tokenizer::get_tokenizer`: `None` means the
    /// wire name is not a recognized OpenAI encoding (Claude/Gemini/llama alias
    /// and friends stay admitted on the engine-normalized path). `Gpt2` is the
    /// library's actual `r50k` alias, not a seventh encoding.
    #[must_use]
    pub fn for_provider_model(wire: &str) -> Option<Self> {
        match tiktoken_rs::tokenizer::get_tokenizer(wire)? {
            tiktoken_rs::tokenizer::Tokenizer::O200kBase => Some(Self::O200kBase),
            tiktoken_rs::tokenizer::Tokenizer::O200kHarmony => Some(Self::O200kHarmony),
            tiktoken_rs::tokenizer::Tokenizer::Cl100kBase => Some(Self::Cl100kBase),
            tiktoken_rs::tokenizer::Tokenizer::P50kBase => Some(Self::P50kBase),
            tiktoken_rs::tokenizer::Tokenizer::P50kEdit => Some(Self::P50kEdit),
            tiktoken_rs::tokenizer::Tokenizer::R50kBase
            | tiktoken_rs::tokenizer::Tokenizer::Gpt2 => Some(Self::R50kBase),
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
