//! Text past one call's bound is spoken as several calls, in order, never
//! refused (Rule 5). The bound is the provider's or the policy's text limit
//! per call. A piece ends after a sentence where one falls inside the bound,
//! else after a space, else at a character boundary, so the pieces' audio
//! plays back as the whole text.

/// The byte length of `text`'s first piece within `max_bytes`: all of it
/// when it fits. A single character wider than the bound goes alone.
pub(super) fn first_piece(text: &str, max_bytes: usize) -> usize {
    if text.len() <= max_bytes {
        return text.len();
    }
    let mut limit = max_bytes;
    while !text.is_char_boundary(limit) {
        limit -= 1;
    }
    if limit == 0 {
        return text.chars().next().map_or(text.len(), char::len_utf8);
    }
    let mut sentence = None;
    let mut space = None;
    let mut previous = None;
    for (at, ch) in text[..limit].char_indices() {
        let after = at + ch.len_utf8();
        if ch.is_whitespace() {
            space = Some(after);
            if ch == '\n' || matches!(previous, Some('.' | '!' | '?')) {
                sentence = Some(after);
            }
        } else if matches!(ch, '。' | '！' | '？') {
            sentence = Some(after);
        }
        previous = Some(ch);
    }
    sentence.or(space).unwrap_or(limit)
}

/// `text` as its pieces within `max_bytes`, in order. A piece that is only
/// whitespace says nothing and is dropped.
pub(super) fn pieces(text: &str, max_bytes: usize) -> Vec<&str> {
    let mut pieces = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let (piece, tail) = rest.split_at(first_piece(rest, max_bytes));
        if !piece.trim().is_empty() {
            pieces.push(piece);
        }
        rest = tail;
    }
    pieces
}
