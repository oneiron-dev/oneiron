//! Conservative fix-don't-invent cleanup with no lexical or speaker edits.

use std::collections::HashMap;

use serde::Serialize;

use super::{
    AudioError, AudioResult, CleanupPolicy, LanguageCorrectionRules, TranscriptTurn, TranscriptWord,
};

pub(super) struct AcousticCandidate {
    pub words: Vec<String>,
    pub pack_sha256: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(super) struct AcceptedCorrection {
    word_id: String,
    pack_id: String,
    pack_sha256: String,
    from: String,
    to: String,
}

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

fn correction_allowed(rules: &LanguageCorrectionRules, from: &str, to: &str) -> bool {
    let protected = |token: &str| {
        rules
            .protected_tokens
            .iter()
            .any(|value| token == value.to_lowercase())
            || rules
                .protected_suffixes
                .iter()
                .any(|value| !value.is_empty() && token.ends_with(&value.to_lowercase()))
    };
    !protected(from)
        && !protected(to)
        && rules
            .allowed_pairs
            .iter()
            .any(|pair| lexical_tokens(&pair.from) == [from] && lexical_tokens(&pair.to) == [to])
}

/// A cleanup model alone is never evidence for lexical replacement. Only a
/// 1:1 acoustic alternative from the same hash-bound ASR pack can correct a
/// single word. Raw words, clocks, speakers and source IDs never change.
pub(super) fn apply_cleanup(
    turns: &mut [TranscriptTurn],
    texts: Vec<String>,
    words: &[TranscriptWord],
    candidates: &HashMap<String, AcousticCandidate>,
    language_hint: Option<&str>,
    policy: Option<&CleanupPolicy>,
) -> AudioResult<Vec<AcceptedCorrection>> {
    if turns.len() != texts.len() {
        return Err(AudioError::CleanupChangedTurns);
    }
    let by_id: HashMap<_, _> = words
        .iter()
        .map(|word| (word.word_id.as_str(), word))
        .collect();
    let mut accepted = Vec::new();
    for (turn, text) in turns.iter().zip(&texts) {
        if validate_cleanup(&turn.text, text).is_ok() {
            continue;
        }
        let rules = language_hint
            .and_then(|lang| policy.and_then(|p| p.language_rules.get(lang)))
            .ok_or(AudioError::CleanupInventedContent)?;
        let original = lexical_tokens(&turn.text);
        let cleaned = lexical_tokens(text);
        if original.is_empty()
            || original.len() != cleaned.len()
            || original.len() != turn.source_word_ids.len()
        {
            return Err(AudioError::CleanupInventedContent);
        }
        for (index, word_id) in turn.source_word_ids.iter().enumerate() {
            let word = by_id
                .get(word_id.as_str())
                .ok_or(AudioError::CleanupInventedContent)?;
            if lexical_tokens(&word.text) != [original[index].clone()]
                || word.speaker_cluster != turn.speaker_cluster
            {
                return Err(AudioError::CleanupInventedContent);
            }
            if original[index] == cleaned[index] {
                continue;
            }
            // Acoustic provenance is necessary but insufficient. The host's
            // language-specific policy must permit this exact lexical pair
            // and exclude polarity-bearing tokens/suffixes on both sides.
            if !correction_allowed(rules, &original[index], &cleaned[index]) {
                return Err(AudioError::CleanupInventedContent);
            }
            let candidate = candidates
                .get(word_id)
                .ok_or(AudioError::CleanupInventedContent)?;
            let replacement = lexical_tokens(&cleaned[index]);
            if replacement.len() != 1
                || !candidate
                    .words
                    .iter()
                    .any(|value| lexical_tokens(value) == replacement)
            {
                return Err(AudioError::CleanupInventedContent);
            }
            accepted.push(AcceptedCorrection {
                word_id: word_id.clone(),
                pack_id: word.pack_id.clone(),
                pack_sha256: candidate.pack_sha256.clone(),
                from: word.text.clone(),
                to: cleaned[index].clone(),
            });
        }
    }
    for (turn, text) in turns.iter_mut().zip(texts) {
        turn.text = text.trim().to_owned();
    }
    Ok(accepted)
}
