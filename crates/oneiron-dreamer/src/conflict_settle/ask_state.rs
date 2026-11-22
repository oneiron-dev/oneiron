//! The ask state the job mirrors: the bytes an ask reads, the engine's
//! page split, and an ask's canonical options.

use serde_json::{Map, Value, json};

use super::{
    AskPart, CallLabels, DISMISS, ESCALATE, HOLD_BOTH, KEEP_PREFIX, MAX_SETTLEMENT_KEEP_OPTIONS,
    MAX_SETTLEMENT_STATE_BYTES, SettleRow,
};

/// `value`'s serialized length.
pub(super) fn json_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// The state an ask over `rows` at `part` reads, as the engine builds it:
/// the contested predicates and every row whole, with the page and the
/// round before's answers when the ask has them.
fn state_of(
    predicates: &[String],
    rows: &[&SettleRow],
    part: &AskPart<'_>,
    labels: &mut CallLabels,
) -> Value {
    let mut members: Vec<Value> = Vec::new();
    for row in rows {
        let label = labels.assign(&row.id);
        members.push(row.shown(&label));
    }
    let mut state = Map::new();
    state.insert("predicates".to_owned(), json!(predicates));
    state.insert("members".to_owned(), Value::Array(members));
    if let Some((_, page, pages)) = part.at.filter(|(_, _, pages)| *pages > 1) {
        state.insert("page".to_owned(), json!(page + 1));
        state.insert("pages".to_owned(), json!(pages));
    }
    if !part.before.is_empty() {
        let answers: Vec<String> = part
            .before
            .iter()
            .map(|answer| answer.shown(labels))
            .collect();
        state.insert("page_answers".to_owned(), json!(answers));
    }
    Value::Object(state)
}

/// The bytes an ask over `rows` at `part` would read.
pub(super) fn state_bytes(predicates: &[String], rows: &[&SettleRow], part: &AskPart<'_>) -> usize {
    json_len(&state_of(predicates, rows, part, &mut CallLabels::empty()))
}

/// Splits `entries` into pages in their order, as the engine's splitter
/// does: each page starts at `frame` bytes, and an entry that would take a
/// page past the state bound, or that `admits` refuses, opens the next. A
/// single entry wider than the bound goes whole on a page of its own.
pub(super) fn split_pages<T: Copy>(
    frame: usize,
    entries: &[T],
    adds: impl Fn(&[T], T) -> usize,
    admits: impl Fn(&[T], T) -> bool,
) -> Vec<Vec<T>> {
    let mut pages: Vec<Vec<T>> = Vec::new();
    let mut page: Vec<T> = Vec::new();
    let mut bytes = frame;
    for &entry in entries {
        let mut added = adds(&page, entry);
        if !page.is_empty()
            && (bytes.saturating_add(added) > MAX_SETTLEMENT_STATE_BYTES || !admits(&page, entry))
        {
            pages.push(std::mem::take(&mut page));
            bytes = frame;
            added = adds(&page, entry);
        }
        page.push(entry);
        bytes = bytes.saturating_add(added);
    }
    if !page.is_empty() || pages.is_empty() {
        pages.push(page);
    }
    pages
}

/// How many of `rows` a Keep may name.
pub(super) fn keeps(rows: &[&SettleRow]) -> usize {
    rows.iter().filter(|row| row.keep).count()
}

/// Whether a page holding `page` takes `row` beside it: past
/// [`MAX_SETTLEMENT_KEEP_OPTIONS`] keep options a keepable row opens the
/// next page.
pub(super) fn admits(page: &[&SettleRow], row: &SettleRow) -> bool {
    !row.keep || keeps(page) < MAX_SETTLEMENT_KEEP_OPTIONS
}

/// The canonical options of an ask over `rows`: hold both, dismiss,
/// escalate, then a Keep of each keepable row by its full id.
pub(super) fn canonical_options(rows: &[&SettleRow]) -> Vec<String> {
    let mut options = vec![
        HOLD_BOTH.to_owned(),
        DISMISS.to_owned(),
        ESCALATE.to_owned(),
    ];
    for row in rows.iter().filter(|row| row.keep) {
        options.push(format!("{KEEP_PREFIX}{}", row.id));
    }
    options
}
