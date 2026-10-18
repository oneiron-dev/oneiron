//! The retained evidence of a self-written summary's span, as its Dreamer
//! check reads it (FIX 4465 B): the run's own committed steps, each its
//! program and its console, rendered exactly as an unfold renders them. An
//! output kept from model context (a secret, a taint) stays withheld here
//! too. It reads replay, never a summary and never the home the call wore.

use super::super::store::{load_context_output, observation_output_path, script_output_path};
use crate::code_run::{CodeRunHistoryTurn, CodeRunReplayRecord, ExecutorStorage};
use crate::{Error, Result};

impl ExecutorStorage<'_> {
    /// Steps `first..=last` of `record`'s run as one text, or an error when
    /// any of them is not a step the run committed or does not read.
    pub(crate) fn compaction_span_text(
        &self,
        record: &CodeRunReplayRecord,
        first: u64,
        last: u64,
    ) -> Result<String> {
        let committed = u64::try_from(record.step_checkpoints.len())
            .map_err(|_| Error::ArithmeticOverflow("executor step count"))?;
        if first > last || last >= committed {
            return Err(Error::InvalidConfig(
                "a checked span is not steps its run committed".into(),
            ));
        }
        let mut text = String::new();
        for step in first..=last {
            let turn = CodeRunHistoryTurn {
                code: load_context_output(self, record, &script_output_path(step))?,
                console: load_context_output(self, record, &observation_output_path(step))?,
            };
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(&turn.assistant_exec());
            text.push('\n');
            text.push_str(&turn.user_console(step));
        }
        Ok(text)
    }
}
