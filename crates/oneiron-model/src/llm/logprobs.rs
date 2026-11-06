//! Borrowed views over a reply token's reported scores.
//!
//! The raw JSON carrier stays the protocol; these views only borrow the
//! first token's top alternatives without copying or extra validation.

use serde_json::Value;

/// One top-logprob alternative, borrowed from its JSON row.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TokenScore<'a> {
    /// The alternative token text, as reported.
    pub token: &'a str,
    /// The alternative's log-probability, as reported.
    pub logprob: f64,
}

impl<'a> TokenScore<'a> {
    /// Borrow one alternative row; `None` skips that row only.
    pub fn from_json(value: &'a Value) -> Option<Self> {
        Some(Self {
            token: value.get("token")?.as_str()?,
            logprob: value.get("logprob")?.as_f64()?,
        })
    }
}

/// The first reply token's top alternatives, borrowed.
///
/// `None` only when the outer `content`/`top_logprobs` path is missing or
/// mistyped; malformed rows are skipped individually.
pub fn first_token_alternatives(scores: &Value) -> Option<impl Iterator<Item = TokenScore<'_>>> {
    let alternatives = scores
        .get("content")?
        .as_array()?
        .first()?
        .get("top_logprobs")?
        .as_array()?;
    Some(alternatives.iter().filter_map(TokenScore::from_json))
}
