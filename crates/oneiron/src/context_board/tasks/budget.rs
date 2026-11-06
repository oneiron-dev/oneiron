//! Explicit token allotments for the admitted TASKS-row projection.

use super::super::frame::xml_text_token;
use super::projection::{TaskRow, TasksOverflow, TasksSection, TasksSectionRows};
use super::render::fits_row;
use crate::tokenizer::count_context_pack_tokens;

impl TasksSection {
    /// Escaped projection lines in actual render order: task lines, then the
    /// overflow footer, then `fits:` discovery rows, each through the frame's
    /// exact text leaf. Newline-joined by the caller like
    /// `assemble_tasks_section` plus `ShedSection::of`, without lead rows.
    fn projection_lines(rows: &[TaskRow], overflow: Option<TasksOverflow>) -> Vec<String> {
        let mut lines = Vec::with_capacity(rows.len().saturating_mul(2).saturating_add(1));
        lines.extend(rows.iter().map(|row| xml_text_token(&row.line)));
        if let Some(line) = overflow.and_then(|overflow| overflow.line()) {
            lines.push(xml_text_token(&line));
        }
        lines.extend(
            rows.iter()
                .filter_map(fits_row)
                .map(|line| xml_text_token(&line)),
        );
        lines
    }

    /// Token cost of this full section's first `shown` rows with a truthful
    /// footer, in actual render order (task lines, overflow footer, `fits:`
    /// rows), each escaped and newline-joined like the frame.
    ///
    /// `self` must hold all already-admitted rows (as `render_with_cap` with
    /// the actual input length produces); `shown` is a stable-order prefix.
    /// Typed rows and the stored honesty bit only, never substring parsing.
    fn tokens_for_prefix(&self, shown: usize) -> usize {
        let shown = shown.min(self.rows.len());
        let source_exhausted = self
            .overflow
            .map(|overflow| overflow.source_exhausted)
            .unwrap_or(true);
        let known_omitted_rows = self.rows.len().saturating_sub(shown);
        let overflow = (known_omitted_rows > 0 || !source_exhausted).then_some(TasksOverflow {
            known_omitted_rows,
            source_exhausted,
        });
        let lines = Self::projection_lines(&self.rows[..shown], overflow);
        count_context_pack_tokens(&lines.join("\n"))
    }

    /// Pre-frame projection cost of these concrete rows: task lines, overflow
    /// footer and `fits:` rows, escaped and newline-joined like the frame.
    ///
    /// Post hook/tag when the server calls it after `pin_hook_tasks` and
    /// `tag_hook_pins`, but before the whole-frame shed and row-byte fence,
    /// so it is NOT the final delivered board cost. Project/fanout lead rows
    /// ride outside this allotment. Typed, never substring-parsed.
    #[must_use]
    pub fn projected_tokens(&self) -> usize {
        let lines = Self::projection_lines(&self.rows, self.overflow);
        count_context_pack_tokens(&lines.join("\n"))
    }
}

impl TasksSectionRows {
    /// Renders a fitting stable-order prefix of concrete TASK rows under a
    /// token allotment for this explicit request: task lines, overflow footer
    /// and `fits:` rows, escaped and newline-joined like the frame.
    ///
    /// `budget_tok` covers concrete rows only, including their `fits:` rows
    /// and the overflow footer; project/fanout lead rows ride outside it.
    /// `Some(0)` is a literal zero for optional rows: the footer (and any
    /// hook pins the caller adds after) may exceed it and are reported, never
    /// withheld. `None` callers keep `render`'s 100-row behavior.
    ///
    /// Builds all already-admitted native rows via `render_with_cap` with the
    /// actual input length (never 100/`usize::MAX`), keeping
    /// `source_exhausted` unchanged and counts truthful. A fitting prefix,
    /// not a maximal-prefix promise; the final candidate fits unless the
    /// 0-row footer floor itself exceeds. No new row/byte/count cap, store,
    /// default or timeout.
    #[must_use]
    pub fn render_with_token_budget(&self, budget_tok: usize) -> TasksSection {
        let total_input = self.intents.len().saturating_add(self.bare_jobs.len());
        let mut full = TasksSection::render_with_cap(
            &self.intents,
            &self.bare_jobs,
            self.source_exhausted,
            total_input,
        );
        let total = full.rows.len();
        if full.projected_tokens() <= budget_tok {
            return full;
        }
        if full.tokens_for_prefix(0) > budget_tok {
            let known_omitted_rows = total;
            let overflow =
                (known_omitted_rows > 0 || !self.source_exhausted).then_some(TasksOverflow {
                    known_omitted_rows,
                    source_exhausted: self.source_exhausted,
                });
            return TasksSection {
                rows: Vec::new(),
                overflow,
            };
        }
        let mut low = 0;
        let mut high = total;
        while low < high {
            let mid = low + (high - low + 1) / 2;
            if full.tokens_for_prefix(mid) <= budget_tok {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        while low > 0 && full.tokens_for_prefix(low) > budget_tok {
            low -= 1;
        }
        let known_omitted_rows = total.saturating_sub(low);
        full.rows.truncate(low);
        full.overflow =
            (known_omitted_rows > 0 || !self.source_exhausted).then_some(TasksOverflow {
                known_omitted_rows,
                source_exhausted: self.source_exhausted,
            });
        full
    }
}
