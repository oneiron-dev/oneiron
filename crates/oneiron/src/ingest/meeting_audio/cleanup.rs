//! Conservative fix-don't-invent cleanup with no lexical or speaker edits.

use super::{AudioError, AudioResult, TranscriptTurn};

/// Lexical corrections cannot be proved from text alone. They need a separate
/// acoustic evidence path; this door therefore rejects lexical additions,
/// deletions (including negation loss), reorderings, and substitutions.
/// It also preserves word boundaries, symbols, signs, and decimal separators.
/// The strict policy applies independently per speaker turn.
pub fn validate_cleanup(original: &str, cleaned: &str) -> AudioResult<()> {
    let original = lexical_tokens(original);
    let cleaned = lexical_tokens(cleaned);
    if original.is_empty() || original != cleaned {
        return Err(AudioError::CleanupInventedContent);
    }
    Ok(())
}

fn lexical_tokens(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut token = String::new();
    for (index, ch) in chars.iter().copied().enumerate() {
        // Punctuation between digits can change a number/date/time. Preserve
        // it rather than treating 1.5, 1,5, and 1:5 as the same assertion.
        let numeric_separator = index > 0
            && chars[index - 1].is_numeric()
            && chars.get(index + 1).is_some_and(|c| c.is_numeric());
        let cosmetic = matches!(
            ch,
            '.' | ','
                | '!'
                | '?'
                | ';'
                | ':'
                | '。'
                | '、'
                | '！'
                | '？'
                | '「'
                | '」'
                | '“'
                | '”'
                | '"'
                | '('
                | ')'
        ) && !numeric_separator;
        if ch.is_whitespace() || cosmetic {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.extend(ch.to_lowercase());
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

pub(super) fn apply_cleanup(turns: &mut [TranscriptTurn], texts: Vec<String>) -> AudioResult<()> {
    if turns.len() != texts.len() {
        return Err(AudioError::CleanupChangedTurns);
    }
    for (turn, text) in turns.iter().zip(&texts) {
        validate_cleanup(&turn.text, text)?;
    }
    for (turn, text) in turns.iter_mut().zip(texts) {
        turn.text = text.trim().to_owned();
    }
    Ok(())
}
