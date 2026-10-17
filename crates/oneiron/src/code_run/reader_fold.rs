//! The model call behind `summarize` (code-mode-summary-sdk-v1): the one
//! prompt a summary job sends, by its recipe. The fold around it is code
//! first, in the bundled `readAll` helper; this is only the bounded call one
//! group of members takes.

use super::reader::{SummarizeEffort, SummarizeRecipe};

/// The system prompt a summary job's one model call takes, by `recipe`. The
/// members follow it as the user message, each fenced and named by its ref.
#[must_use]
pub fn summarize_prompt(recipe: &SummarizeRecipe) -> String {
    let length = match recipe.effort {
        SummarizeEffort::Low => "in at most five sentences",
        SummarizeEffort::Medium => "in at most three short paragraphs",
        SummarizeEffort::High => "thoroughly, keeping every distinct finding",
    };
    format!(
        "You summarize results of a code run (summary recipe v{version}, effort {effort}).\n\
         Each part below is fenced and named by its ref; a part may be a reader's JSON finding \
         with `answer`, `cites` and `coverage`, or plain text.\n\
         Write one plain-text summary {length}. Keep every cited byte range as it is \
         written, as `[start, end]`, next to what it supports. Say what the parts disagree on. \
         State nothing the parts do not say, and add no preface.",
        version = recipe.version,
        effort = recipe.effort.as_str(),
    )
}

/// The user message of one summary: each member's text fenced and named by
/// its ref, in order.
#[must_use]
pub fn summarize_input<'m>(members: impl IntoIterator<Item = (&'m str, &'m str)>) -> String {
    let mut text = String::new();
    for (reference, body) in members {
        text.push_str("<part ref=\"");
        text.push_str(reference);
        text.push_str("\">\n");
        text.push_str(&body.replace("</part>", "<\\/part>"));
        text.push_str("\n</part>\n");
    }
    text
}
