//! The model call behind `summarize` (code-mode-summary-sdk-v1): the one
//! prompt a summary job sends, by its recipe. The fold around it is code
//! first, in the bundled `readAll` helper; this is only the bounded call one
//! group of members takes.

use super::reader::{SummarizeEffort, SummarizeRecipe};

pub(super) const SUMMARIZE_PROMPT_RELATIVE_PATH: &str = "blocks/code-reader-summary.md";
const DEFAULT_SUMMARIZE_TEMPLATE: &str =
    include_str!("../../prompts/blocks/code-reader-summary.md");

pub(super) fn render_summarize_prompt(
    version: u32,
    effort: SummarizeEffort,
    template: &str,
) -> String {
    let length = match effort {
        SummarizeEffort::Low => include_str!("../../prompts/blocks/code-reader-summary-low.md"),
        SummarizeEffort::Medium => {
            include_str!("../../prompts/blocks/code-reader-summary-medium.md")
        }
        SummarizeEffort::High => include_str!("../../prompts/blocks/code-reader-summary-high.md"),
    };
    template
        .replace("{{version}}", &version.to_string())
        .replace("{{effort}}", effort.as_str())
        .replace("{{length}}", length)
}

pub(super) fn default_summarize_prompt(version: u32, effort: SummarizeEffort) -> String {
    render_summarize_prompt(version, effort, DEFAULT_SUMMARIZE_TEMPLATE)
}

/// The system prompt frozen when this summary was queued. The memo and the
/// worker use these same bytes even if its package changes while it waits.
#[must_use]
pub fn summarize_prompt(recipe: &SummarizeRecipe) -> String {
    recipe.prompt.clone()
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
