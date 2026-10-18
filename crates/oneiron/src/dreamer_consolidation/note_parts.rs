//! A Dreamer-written text past the NOTE body bound, as the ordered parts it
//! lands in: the split an imported note's file takes.

/// `text` in parts of at most `bound` bytes, in order. Each is cut on a
/// character boundary, at the last line break in its second half when it
/// has one, so a line stays whole where it can. Text within the bound is one
/// part; no byte of `text` is left out.
pub(super) fn parts(text: &str, bound: usize) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    while text.len() - start > bound {
        let mut end = text.floor_char_boundary(start + bound);
        if let Some(line) = text.as_bytes()[start..end]
            .iter()
            .rposition(|&byte| byte == b'\n')
            .filter(|&line| line >= bound / 2)
        {
            end = start + line + 1;
        }
        parts.push(&text[start..end]);
        start = end;
    }
    parts.push(&text[start..]);
    parts
}
