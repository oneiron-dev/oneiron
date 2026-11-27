//! Reads the return value and console of a served run through its held outputs.

use super::record::has_caller_source;
use super::store::{clean_for_context, console_output_path, observation_output_path};
use crate::code_run::{
    CODE_RUN_OUTPUT_PREVIEW_WITHHELD, CodeRunRawOutput, CodeRunReplayRecord, ExecutorStorage,
    unmarked_secret,
};
use crate::{Error, Result, Vault};
use serde_json::{Value, json};

const INLINE_RESULT_CHARS: usize = 20_000;

/// The result a host may release with the run's served-row checks.
#[derive(Default)]
pub struct CallerRunOutput {
    pub result: Option<Value>,
    pub console: Vec<String>,
    /// A stored result name when the inline value contains only its prefix.
    pub truncated_ref: Option<String>,
}

/// Reads only served observations and console, never the caller source or a
/// model reply. Use the same taint and erase checks as named result reads.
pub fn read_caller_run_output(
    vault: &Vault,
    record: &CodeRunReplayRecord,
    complete: bool,
) -> Result<CallerRunOutput> {
    let storage = ExecutorStorage::Canonical(vault);
    if storage.code_run_response_erased(record.run_id)? {
        return Ok(CallerRunOutput::default());
    }
    let mut view = CallerRunOutput::default();
    let find = |path: String| record.outputs.iter().find(|output| output.path == path);
    let last = record
        .step_checkpoints
        .last()
        .map(|checkpoint| checkpoint.seq);
    let source = has_caller_source(record);
    let mut console_chars = 0usize;
    for checkpoint in &record.step_checkpoints {
        let seq = checkpoint.seq;
        // Source replay runs the whole body, including its logs, again. The
        // latest slice already includes the console from the replayed prefix.
        if source && Some(seq) != last {
            continue;
        }
        let Some(output) = find(console_output_path(seq)).or_else(|| {
            if complete && Some(seq) == last {
                None
            } else {
                find(observation_output_path(seq))
            }
        }) else {
            continue;
        };
        let remaining = INLINE_RESULT_CHARS.saturating_sub(console_chars);
        if remaining == 0 {
            break;
        }
        let (text, _) = read_body(&storage, record, output, remaining * 4 + 1)?;
        let (text, _) = char_prefix(&text, remaining);
        console_chars += text.chars().count();
        view.console.extend(text.lines().map(str::to_owned));
    }
    if unmarked_secret(&json!(view.console)).is_some() {
        view.console = vec![CODE_RUN_OUTPUT_PREVIEW_WITHHELD.to_owned()];
    }
    if complete && let Some(output) = last.and_then(|seq| find(observation_output_path(seq))) {
        // JSON may use six bytes for one character (a control character).
        let (text, partial) = read_body(&storage, record, output, INLINE_RESULT_CHARS * 6 + 2)?;
        if !text.is_empty() {
            let value = if source && !partial {
                serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text.clone()))
            } else if source && text.starts_with('"') {
                decode_string_prefix(&text)
                    .map_or_else(|| Value::String(text.clone()), Value::String)
            } else {
                Value::String(text.clone())
            };
            let rendered = match &value {
                Value::String(text) => std::borrow::Cow::Borrowed(text.as_str()),
                value => std::borrow::Cow::Owned(value.to_string()),
            };
            let (prefix, clipped) = char_prefix(&rendered, INLINE_RESULT_CHARS);
            view.result = Some(if unmarked_secret(&value).is_some() {
                Value::String(CODE_RUN_OUTPUT_PREVIEW_WITHHELD.to_owned())
            } else if clipped || partial {
                view.truncated_ref = record
                    .bindings
                    .iter()
                    .find(|binding| binding.path == output.path && binding.handle == output.handle)
                    .map(|binding| binding.name.clone())
                    .or_else(|| Some(output.handle.clone()));
                Value::String(prefix.to_owned())
            } else {
                value
            });
        }
    }
    Ok(view)
}

fn char_prefix(text: &str, limit: usize) -> (&str, bool) {
    let end = text.char_indices().nth(limit).map(|(at, _)| at);
    (&text[..end.unwrap_or(text.len())], end.is_some())
}

// Close a truncated JSON string at the last complete character/escape.
fn decode_string_prefix(text: &str) -> Option<String> {
    text.char_indices().rev().take(7).find_map(|(end, _)| {
        let mut closed = text[..end].to_owned();
        closed.push('"');
        serde_json::from_str::<String>(&closed).ok()
    })
}

fn read_body(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    output: &CodeRunRawOutput,
    cap: usize,
) -> Result<(String, bool)> {
    if !clean_for_context(storage, Some(record.run_id), output)? {
        return Ok((CODE_RUN_OUTPUT_PREVIEW_WITHHELD.to_owned(), false));
    }
    let Some(raw) = storage.read_code_run_raw_output_range(output, 0, cap)? else {
        return Err(Error::CorruptedIndex("executor replay output bytes"));
    };
    let partial = (raw.len() as u64) < output.raw_len;
    let tail = match std::str::from_utf8(&raw) {
        Err(error) if partial && error.error_len().is_none() => error.valid_up_to(),
        _ => raw.len(),
    };
    Ok((String::from_utf8_lossy(&raw[..tail]).into_owned(), partial))
}
