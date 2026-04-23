//! Script-safe CJK n-gram generator.
//!
//! Used as the Portable fallback path for JP / ZH / KO when a morphological
//! dictionary is not discoverable on disk (plan §7). Emits unigrams on the
//! `Surface` channel and bigrams on the `CjkNgram` overlay channel, with the
//! hard invariant (plan §1.2): **no generated bigram crosses a script-class
//! boundary**. Each ngram call operates on a single `ScriptRun` slice, so
//! the invariant is enforced by construction — the caller never hands us
//! text that spans multiple runs.
//!
//! Offsets are always expressed as `offset_base + local_char_byte_offset`
//! into the caller's original UTF-8. Positions are assigned one per unigram;
//! each bigram overlay sits at the *first* character's position with
//! `position_increment = 0`.

use super::token::{AnalyzerChannel, Token, TokenKind};

/// Analyze a single-script CJK run and append tokens to `out`.
///
/// * `text` — the run's UTF-8 slice (caller guarantees script-uniform).
/// * `offset_base` — absolute byte offset of `text` in the caller's original
///   input. Emitted tokens use `offset_base + local_offset`.
/// * `position_base` — position index of the first emitted surface unigram.
///
/// Returns the next position after the last surface unigram emitted.
pub fn analyze(text: &str, offset_base: u32, position_base: u32, out: &mut Vec<Token>) -> u32 {
    if text.is_empty() {
        return position_base;
    }

    // Collect (char_byte_start, char_str) once so we can build both unigrams
    // and bigrams in a single pass without re-walking the string.
    let chars: Vec<(u32, &str)> = text
        .char_indices()
        .map(|(i, c)| {
            let start = i as u32;
            let end = start + c.len_utf8() as u32;
            (start, &text[start as usize..end as usize])
        })
        .collect();

    let mut position = position_base;

    for (i, &(local_start, ch)) in chars.iter().enumerate() {
        let start = offset_base + local_start;
        let end = start + ch.len() as u32;

        out.push(Token::new(
            ch,
            start,
            end,
            position,
            AnalyzerChannel::Surface,
            TokenKind::Cjk,
        ));

        if let Some(&(next_local_start, next_ch)) = chars.get(i + 1) {
            let bi_end = offset_base + next_local_start + next_ch.len() as u32;
            let mut term = String::with_capacity(ch.len() + next_ch.len());
            term.push_str(ch);
            term.push_str(next_ch);
            out.push(
                Token::new(
                    term,
                    start,
                    bi_end,
                    position,
                    AnalyzerChannel::CjkNgram,
                    TokenKind::Cjk,
                )
                .overlay(),
            );
        }

        position += 1;
    }

    position
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface_terms(tokens: &[Token]) -> Vec<&str> {
        tokens
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .map(|t| t.term.as_ref())
            .collect()
    }

    fn ngram_terms(tokens: &[Token]) -> Vec<&str> {
        tokens
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
            .map(|t| t.term.as_ref())
            .collect()
    }

    #[test]
    fn han_unigrams_and_bigrams() {
        let mut out = Vec::new();
        analyze("東京大学", 0, 0, &mut out);
        assert_eq!(surface_terms(&out), vec!["東", "京", "大", "学"]);
        assert_eq!(ngram_terms(&out), vec!["東京", "京大", "大学"]);
    }

    #[test]
    fn empty_input_returns_position_base() {
        let mut out = Vec::new();
        let next = analyze("", 0, 42, &mut out);
        assert_eq!(next, 42);
        assert!(out.is_empty());
    }

    #[test]
    fn single_char_has_no_bigram() {
        let mut out = Vec::new();
        analyze("東", 0, 0, &mut out);
        assert_eq!(surface_terms(&out), vec!["東"]);
        assert!(ngram_terms(&out).is_empty());
    }

    #[test]
    fn offsets_refer_to_original_slice() {
        let text = "東京大学";
        let mut out = Vec::new();
        analyze(text, 0, 0, &mut out);
        for tok in &out {
            let slice = &text[tok.byte_start as usize..tok.byte_end as usize];
            assert_eq!(slice, tok.term.as_ref());
        }
    }

    #[test]
    fn offset_base_shifts_absolute_offsets() {
        let mut out = Vec::new();
        analyze("東京", 100, 0, &mut out);
        let surface_offsets: Vec<(u32, u32)> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .map(|t| (t.byte_start, t.byte_end))
            .collect();
        // '東' is 3 UTF-8 bytes; run starts at 100.
        assert_eq!(surface_offsets, vec![(100, 103), (103, 106)]);
    }

    #[test]
    fn bigram_overlay_has_zero_position_but_counts_length() {
        let mut out = Vec::new();
        analyze("東京", 0, 0, &mut out);
        let bigram = out.iter().find(|t| t.channel == AnalyzerChannel::CjkNgram).unwrap();
        assert_eq!(bigram.position_increment, 0);
        // Bigrams live on their own BM25 field (CjkNgram) and must
        // contribute to that field's length so `b` normalization can fire.
        assert_eq!(bigram.length_increment, 1);
    }

    #[test]
    fn bigram_shares_position_with_first_char() {
        let mut out = Vec::new();
        analyze("東京大", 0, 0, &mut out);
        let positions: Vec<(u32, AnalyzerChannel, &str)> = out
            .iter()
            .map(|t| (t.position, t.channel, t.term.as_ref()))
            .collect();
        // Interleaved: (0, Surface, 東), (0, CjkNgram, 東京), (1, Surface, 京),
        // (1, CjkNgram, 京大), (2, Surface, 大).
        assert_eq!(
            positions,
            vec![
                (0, AnalyzerChannel::Surface, "東"),
                (0, AnalyzerChannel::CjkNgram, "東京"),
                (1, AnalyzerChannel::Surface, "京"),
                (1, AnalyzerChannel::CjkNgram, "京大"),
                (2, AnalyzerChannel::Surface, "大"),
            ]
        );
    }

    #[test]
    fn position_base_is_honored() {
        let mut out = Vec::new();
        let next = analyze("東京", 0, 10, &mut out);
        let surface_positions: Vec<u32> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .map(|t| t.position)
            .collect();
        assert_eq!(surface_positions, vec![10, 11]);
        assert_eq!(next, 12);
    }

    #[test]
    fn hangul_syllable_bigrams() {
        let mut out = Vec::new();
        analyze("안녕하세요", 0, 0, &mut out);
        assert_eq!(surface_terms(&out), vec!["안", "녕", "하", "세", "요"]);
        assert_eq!(ngram_terms(&out), vec!["안녕", "녕하", "하세", "세요"]);
    }

    #[test]
    fn hiragana_unigrams_and_bigrams() {
        let mut out = Vec::new();
        analyze("とうきょう", 0, 0, &mut out);
        assert_eq!(surface_terms(&out), vec!["と", "う", "き", "ょ", "う"]);
        assert_eq!(ngram_terms(&out), vec!["とう", "うき", "きょ", "ょう"]);
    }
}
