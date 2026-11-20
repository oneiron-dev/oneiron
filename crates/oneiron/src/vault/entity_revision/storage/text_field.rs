//! A revision document's text field set to a row's new text, its diff held
//! to a budget.

use crate::error::{Error, Result};
use loro::{LoroText, UpdateOptions};

/// How long one field's diff may run. Myers' diff takes time in proportion to
/// the text's length times the size of the change, so a large body replaced
/// by an unrelated one diffed for hours while the write held the vault's
/// writer. The note folder import holds its whole-text diff to the same
/// budget (`WHOLE_TEXT_TIMEOUT_MS`).
const FIELD_DIFF_TIMEOUT_MS: f64 = 2_000.0;

/// Sets `field` to `text` by the smallest edits the diff finds within
/// [`FIELD_DIFF_TIMEOUT_MS`], so every unchanged character keeps its identity
/// and the cursors on it. Past the budget, the edits the diff already made
/// stay (it makes them in text order, each one part of the change) and the
/// one span that still differs is replaced whole: the field always ends equal
/// to `text`, and the characters before and after that span keep theirs.
pub(super) fn set_text(field: &LoroText, text: &str) -> Result<()> {
    let options = UpdateOptions {
        timeout_ms: Some(FIELD_DIFF_TIMEOUT_MS),
        use_refined_diff: true,
    };
    if field.update(text, options).is_ok() {
        return Ok(());
    }
    let held: Vec<char> = field.to_string().chars().collect();
    let wanted: Vec<char> = text.chars().collect();
    let prefix = held
        .iter()
        .zip(&wanted)
        .take_while(|(old, new)| old == new)
        .count();
    let suffix = held[prefix..]
        .iter()
        .rev()
        .zip(wanted[prefix..].iter().rev())
        .take_while(|(old, new)| old == new)
        .count();
    let removed = held.len() - prefix - suffix;
    if removed > 0 {
        field
            .delete(prefix, removed)
            .map_err(|_| Error::InvariantViolation("entity text update"))?;
    }
    let inserted: String = wanted[prefix..wanted.len() - suffix].iter().collect();
    if !inserted.is_empty() {
        field
            .insert(prefix, &inserted)
            .map_err(|_| Error::InvariantViolation("entity text update"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::set_text;
    use loro::LoroDoc;
    use loro::cursor::Side;
    use std::time::{Duration, Instant};

    /// An unrelated replacement of a large field runs past the budget, ends
    /// exactly at the new text, and a cursor on the unchanged tail keeps its
    /// character. Before the budget this diff ran for hours.
    #[test]
    fn an_unrelated_replacement_past_the_budget_ends_at_the_new_text() {
        let doc = LoroDoc::new();
        let field = doc.get_text("field:txt");
        let old = format!("{} tail \u{2713}", "x".repeat(1 << 20));
        field.insert(0, &old).unwrap();
        doc.commit();
        let tail = field
            .get_cursor(old.chars().count() - 1, Side::Middle)
            .unwrap();
        let new = "\u{e9}dited tail \u{2713}";
        let started = Instant::now();
        set_text(&field, new).unwrap();
        doc.commit();
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the replacement took {:?}",
            started.elapsed()
        );
        assert_eq!(field.to_string(), new);
        assert_eq!(
            doc.get_cursor_pos(&tail).unwrap().current.pos,
            new.chars().count() - 1,
            "the unchanged tail keeps its identity"
        );
    }

    /// A small edit inside the budget is the diff's own: the characters on
    /// both sides of it keep their identity.
    #[test]
    fn an_edit_inside_the_budget_keeps_every_unchanged_character() {
        let doc = LoroDoc::new();
        let field = doc.get_text("field:txt");
        field.insert(0, "the first draft of a turn").unwrap();
        doc.commit();
        let head = field.get_cursor(1, Side::Middle).unwrap();
        let tail = field.get_cursor(21, Side::Middle).unwrap();
        set_text(&field, "the second draft of a turn").unwrap();
        doc.commit();
        assert_eq!(field.to_string(), "the second draft of a turn");
        assert_eq!(doc.get_cursor_pos(&head).unwrap().current.pos, 1);
        assert_eq!(doc.get_cursor_pos(&tail).unwrap().current.pos, 22);
    }
}
