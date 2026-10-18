//! Comment text past one stored comment's codec bound lands whole, as linked
//! parts on its thread: part 1 is the comment, and each later part is a reply
//! headed "(part n)". Together the parts hold every byte of the text.

use super::model::ANNOTATION_COMMENT_TEXT_MAX_BYTES;

/// The stored bodies of `text`, in order. A text within the bound is its own
/// one body.
pub(super) fn comment_parts(text: &str) -> Vec<String> {
    split(text, ANNOTATION_COMMENT_TEXT_MAX_BYTES)
}

fn split(text: &str, bound: usize) -> Vec<String> {
    if text.len() <= bound {
        return vec![text.to_owned()];
    }
    let mut parts = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let label = match parts.len() + 1 {
            1 => String::new(),
            n => format!("(part {n})\n"),
        };
        let room = bound - label.len();
        let cut = if rest.len() <= room {
            rest.len()
        } else {
            cut_at(rest, room)
        };
        parts.push(format!("{label}{}", &rest[..cut]));
        rest = &rest[cut..];
    }
    parts
}

/// Where the next part ends: after the last newline in the second half of
/// the `room` bytes, else at the last character boundary within them.
fn cut_at(text: &str, room: usize) -> usize {
    let mut end = room;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    match text[..end].rfind('\n') {
        Some(at) if at >= end / 2 => at + 1,
        _ => end,
    }
}
