//! A Loro text set to a new text, its diff held to a budget. Every place
//! that sets a stored text to a whole new value goes through this module.
//! Entity document forks and recovery replays, office body paragraphs and
//! cells, and secret projection copies go through [`set_text`], which leaves
//! the text as it was when the diff would run past the budget: each of those
//! texts is later merged with a peer's concurrent edits, or keeps marks its
//! caller does not reapply, so a coarse replacement would lose them. Entity
//! revision fields go through [`set_text_or_replace_span`], which past the
//! budget replaces the one span that still differs.

use loro::{LoroError, LoroResult, LoroText, UpdateOptions, UpdateTimeoutError};

/// How long one text's diff may run. Myers' diff takes time in proportion to
/// the text's length times the size of the change, so a large body replaced
/// by an unrelated one diffed for hours while the write held the vault's
/// writer. The note folder import holds its whole-text diff to the same
/// budget (`WHOLE_TEXT_TIMEOUT_MS`). The vendored diff times the budget on a
/// monotonic clock, so a wall clock stepped back cannot hold it off
/// (`crates/loro/PROVENANCE.md`).
const TEXT_DIFF_TIMEOUT_MS: f64 = 2_000.0;

/// Why [`set_text`] left a text as it was.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SetTextError {
    /// The diff ran past [`TEXT_DIFF_TIMEOUT_MS`].
    #[error("the text diff ran past its budget")]
    DiffOverBudget(#[from] UpdateTimeoutError),
    /// Loro refused to write the detached copy the diff first runs on.
    #[error("the text diff's detached copy: {0}")]
    DetachedCopy(#[from] LoroError),
}

/// Sets `field` to `text` by the smallest edits the diff finds, so every
/// unchanged character keeps its identity, its marks and the cursors on it.
/// When that diff would run past [`TEXT_DIFF_TIMEOUT_MS`], `field` stays
/// exactly as it was and the call returns [`SetTextError::DiffOverBudget`].
///
/// The diff first runs, timed, on a detached copy of the held text. The
/// vendored diff makes the same edits for the same two texts every time, and
/// its timeout only stops it (`loro-internal-1.16.2/src/diff/diff_impl.rs`),
/// so the untimed diff on `field` that follows makes exactly the edits the
/// copy's diff finished, in about the same time. No edit reaches `field`
/// before the copy's diff has finished.
pub(crate) fn set_text(field: &LoroText, text: &str) -> Result<(), SetTextError> {
    let held = field.to_string();
    if held == text {
        return Ok(());
    }
    let copy = LoroText::new();
    if !held.is_empty() {
        copy.insert(0, &held)?;
    }
    copy.update(
        text,
        UpdateOptions {
            timeout_ms: Some(TEXT_DIFF_TIMEOUT_MS),
            use_refined_diff: true,
        },
    )?;
    field.update(
        text,
        UpdateOptions {
            timeout_ms: None,
            use_refined_diff: true,
        },
    )?;
    Ok(())
}

/// Sets `field` to `text` by the smallest edits the diff finds within
/// [`TEXT_DIFF_TIMEOUT_MS`], so every unchanged character keeps its identity
/// and the cursors on it. Past the budget, the edits the diff already made
/// stay (it makes them in text order, each one part of the change) and the
/// one span that still differs is replaced whole: the field always ends equal
/// to `text`, and the characters before and after that span keep theirs.
pub(crate) fn set_text_or_replace_span(field: &LoroText, text: &str) -> LoroResult<()> {
    let options = UpdateOptions {
        timeout_ms: Some(TEXT_DIFF_TIMEOUT_MS),
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
        field.delete(prefix, removed)?;
    }
    let inserted: String = wanted[prefix..wanted.len() - suffix].iter().collect();
    if !inserted.is_empty() {
        field.insert(prefix, &inserted)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SetTextError, set_text, set_text_or_replace_span};
    use loro::cursor::Side;
    use loro::{LoroDoc, StyleConfigMap, UpdateOptions};
    use std::time::{Duration, Instant};

    /// The reviewer's input: a large unrelated replacement with one bold span
    /// of unchanged text in its middle. The diff runs past the budget, so the
    /// field keeps every character and mark it held and gains no edit.
    #[test]
    fn a_replacement_past_the_budget_leaves_the_text_and_its_marks_as_they_were() {
        let doc = LoroDoc::new();
        doc.config_text_style(StyleConfigMap::default_rich_text_config());
        let field = doc.get_text("field:txt");
        let side = 500_000;
        let middle = 4096;
        let old = format!(
            "{}{}{}",
            "a".repeat(side),
            "X".repeat(middle),
            "a".repeat(side)
        );
        field.insert(0, &old).unwrap();
        field.mark(side..side + middle, "bold", true).unwrap();
        doc.commit();
        let held_delta = field.to_delta();
        let held_version = doc.oplog_vv();
        let new = format!(
            "{}{}{}",
            "b".repeat(side),
            "X".repeat(middle),
            "b".repeat(side)
        );
        let started = Instant::now();
        let result = set_text(&field, &new);
        let elapsed = started.elapsed();
        doc.commit();
        assert!(
            elapsed < Duration::from_secs(60),
            "the refusal took {elapsed:?}"
        );
        assert!(
            matches!(result, Err(SetTextError::DiffOverBudget(_))),
            "{result:?}"
        );
        assert_eq!(field.to_string(), old);
        assert_eq!(field.to_delta(), held_delta, "the bold span keeps its mark");
        assert_eq!(doc.oplog_vv(), held_version, "the field gains no edit");
    }

    /// A small edit inside the budget is the diff's own: it makes as many
    /// edits as Loro's own update on a twin, and the characters on both sides
    /// of it keep their identity. The text ends in a character outside the
    /// basic plane, after both cursors.
    #[test]
    fn an_edit_inside_the_budget_is_the_diffs_own() {
        let old = "the first draft of a turn \u{1f600}";
        let new = "the second draft of a turn \u{1f600}";
        let doc = LoroDoc::new();
        doc.set_peer_id(7).unwrap();
        let field = doc.get_text("field:txt");
        field.insert(0, old).unwrap();
        doc.commit();
        let twin = LoroDoc::new();
        twin.set_peer_id(7).unwrap();
        let twin_field = twin.get_text("field:txt");
        twin_field.insert(0, old).unwrap();
        twin.commit();
        let head = field.get_cursor(1, Side::Middle).unwrap();
        let tail = field.get_cursor(21, Side::Middle).unwrap();
        set_text(&field, new).unwrap();
        doc.commit();
        twin_field.update(new, UpdateOptions::default()).unwrap();
        twin.commit();
        assert_eq!(field.to_string(), new);
        assert_eq!(doc.oplog_vv(), twin.oplog_vv(), "the same edits as update");
        assert_eq!(doc.get_cursor_pos(&head).unwrap().current.pos, 1);
        assert_eq!(doc.get_cursor_pos(&tail).unwrap().current.pos, 22);
    }

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
        set_text_or_replace_span(&field, new).unwrap();
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
        set_text_or_replace_span(&field, "the second draft of a turn").unwrap();
        doc.commit();
        assert_eq!(field.to_string(), "the second draft of a turn");
        assert_eq!(doc.get_cursor_pos(&head).unwrap().current.pos, 1);
        assert_eq!(doc.get_cursor_pos(&tail).unwrap().current.pos, 22);
    }
}
