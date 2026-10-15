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

        if let Some([_, (next_local_start, next_ch)]) = chars[i..].array_windows::<2>().next() {
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

/// Emit char-adjacent bigrams on `CjkNgram` without surface unigrams.
/// Called by the ZH / JP / KO morph paths after their tokenizers run; the
/// bigrams provide recall across morpheme boundaries.
pub(super) fn emit_bigram_overlay(
    text: &str,
    offset_base: u32,
    position_base: u32,
    out: &mut Vec<Token>,
) {
    let chars: Vec<(u32, &str)> = text
        .char_indices()
        .map(|(i, c)| {
            let start = i as u32;
            let end = start + c.len_utf8() as u32;
            (start, &text[start as usize..end as usize])
        })
        .collect();

    for (i, [(local_start, ch), (next_local_start, next_ch)]) in
        chars.as_slice().array_windows::<2>().enumerate()
    {
        let start = offset_base + *local_start;
        let end = offset_base + *next_local_start + next_ch.len() as u32;
        let mut term = String::with_capacity(ch.len() + next_ch.len());
        term.push_str(ch);
        term.push_str(next_ch);
        out.push(
            Token::new(
                term,
                start,
                end,
                position_base + i as u32,
                AnalyzerChannel::CjkNgram,
                TokenKind::Cjk,
            )
            .overlay(),
        );
    }
}
