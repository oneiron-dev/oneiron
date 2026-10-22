//! The provider usage a bound work's ended attempt reports (FIX 7452), read
//! from that attempt's own capture and nothing else: no vendor log,
//! credential file or network lookup, and never another seat's attempt.
//!
//! An endpoint run's transcript is its normalized response, and an MCP
//! host may leave the same normalized `usage` in its transcript. A runner
//! CLI prints its own usage on stdout, each in its own shape:
//!
//! - Claude Code (`--output-format json` or `stream-json`): the final
//!   `result` event's `usage`, the run's cumulative summary.
//! - Codex (`exec --json`): the last `turn.completed` event's `usage`, the
//!   thread's running total, so for one fresh `exec` this run's.
//! - OpenCode (`run --format json`): each `step_finish` event's
//!   `part.tokens`, one step's own, summed over the steps.
//!
//! One cumulative summary is read, or steps that do not overlap are summed:
//! never a running total plus its steps. A shape not read here, or one
//! missing its totals, reads as no usage: never a measured zero, and never
//! a failed read of the outcome. Parts a vendor does not report stay zero
//! in the normalized split, and its own object rides `raw_provider`. A read
//! books nothing.

use std::ffi::OsStr;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::Vault;
use crate::attempt_queue::AttemptResultRef;
use crate::llm::{LlmInputUsage, LlmOutputUsage, LlmUsage};

use super::connector::ByoaConnectorSpec;
use super::exhaust::{ByoaExhaust, decode_byoa_exhaust, parse_byoa_result_ref};
use super::provider::{CLAUDE_CODE_PROGRAM, CODEX_PROGRAM, OPENCODE_PROGRAM};
use super::stream::ByoaStream;

/// The part of a normalized transcript that names its usage.
#[derive(Deserialize)]
struct TranscriptUsage {
    usage: LlmUsage,
}

/// The usage the capture `exhaust` reports for an attempt of `connector`.
/// `None` when the capture does not resolve or names no usage read here.
pub(super) fn captured_usage(
    vault: &Vault,
    connector: &ByoaConnectorSpec,
    exhaust: &AttemptResultRef,
) -> Option<LlmUsage> {
    let (artifact_id, version) = parse_byoa_result_ref(exhaust).ok()?;
    let (_, _, captured) = decode_byoa_exhaust(vault, &artifact_id, version).ok()?;
    terminal_usage(connector, &captured)
}

/// The usage an ended attempt of `connector` reports in its own `exhaust`:
/// an endpoint's or MCP host's normalized transcript, or a known runner
/// CLI's stdout. `None` for any other shape.
pub(super) fn terminal_usage(
    connector: &ByoaConnectorSpec,
    exhaust: &ByoaExhaust,
) -> Option<LlmUsage> {
    match connector {
        ByoaConnectorSpec::Endpoint(_) | ByoaConnectorSpec::ProtocolAttach(_) => {
            let transcript = exhaust.transcript.as_ref()?;
            serde_json::from_reader::<_, TranscriptUsage>(transcript.reader())
                .ok()
                .map(|read| read.usage)
        }
        ByoaConnectorSpec::CliSandbox(spec) => {
            let program = Path::new(&spec.program)
                .file_name()
                .and_then(OsStr::to_str)?;
            match program {
                CLAUDE_CODE_PROGRAM => claude_usage(&exhaust.stdout),
                CODEX_PROGRAM => codex_usage(&exhaust.stdout),
                OPENCODE_PROGRAM => opencode_usage(&exhaust.stdout),
                _ => None,
            }
        }
    }
}

/// Claude Code's final `result` event's `usage`. Its input total counts
/// the cached input it reports apart, as the Anthropic API's does.
fn claude_usage(stdout: &ByoaStream) -> Option<LlmUsage> {
    let result = last_event(stdout, "result")?;
    let usage = result.get("usage")?;
    let input = count(usage, "input_tokens")?;
    let output = count(usage, "output_tokens")?;
    let cache_read = count(usage, "cache_read_input_tokens").unwrap_or_default();
    let cache_write = count(usage, "cache_creation_input_tokens").unwrap_or_default();
    Some(LlmUsage {
        input: LlmInputUsage {
            total: input.saturating_add(cache_read).saturating_add(cache_write),
            cache_read,
            cache_write,
        },
        output: LlmOutputUsage {
            total: output,
            text: output,
            reasoning: 0,
        },
        raw_provider: usage.clone(),
    })
}

/// Codex's last `turn.completed` event's `usage`. Its cached input is part
/// of its input, and its reasoning part of its output.
fn codex_usage(stdout: &ByoaStream) -> Option<LlmUsage> {
    let turn = last_event(stdout, "turn.completed")?;
    let usage = turn.get("usage")?;
    let input = count(usage, "input_tokens")?;
    let output = count(usage, "output_tokens")?;
    let reasoning = count(usage, "reasoning_output_tokens").unwrap_or_default();
    Some(LlmUsage {
        input: LlmInputUsage {
            total: input,
            cache_read: count(usage, "cached_input_tokens").unwrap_or_default(),
            cache_write: count(usage, "cache_write_input_tokens").unwrap_or_default(),
        },
        output: LlmOutputUsage {
            total: output,
            text: output.saturating_sub(reasoning),
            reasoning,
        },
        raw_provider: usage.clone(),
    })
}

/// OpenCode's `step_finish` events' `part.tokens`, summed: each is its own
/// step's. Its input leaves out the cached input it reports apart, and its
/// output the reasoning. A step without its totals reads as no usage.
fn opencode_usage(stdout: &ByoaStream) -> Option<LlmUsage> {
    let mut steps = Vec::new();
    let mut whole = true;
    each_event(stdout, |event| {
        if event_type(&event) == Some("step_finish") {
            match event.get("part").and_then(|part| part.get("tokens")) {
                Some(tokens) => steps.push(tokens.clone()),
                None => whole = false,
            }
        }
    })?;
    if !whole || steps.is_empty() {
        return None;
    }
    let mut input = LlmInputUsage::default();
    let mut output = LlmOutputUsage::default();
    for tokens in &steps {
        let fresh = count(tokens, "input")?;
        let text = count(tokens, "output")?;
        let reasoning = count(tokens, "reasoning").unwrap_or_default();
        let cache = tokens.get("cache");
        let read = cache
            .and_then(|cache| count(cache, "read"))
            .unwrap_or_default();
        let write = cache
            .and_then(|cache| count(cache, "write"))
            .unwrap_or_default();
        input.total = input
            .total
            .saturating_add(fresh)
            .saturating_add(read)
            .saturating_add(write);
        input.cache_read = input.cache_read.saturating_add(read);
        input.cache_write = input.cache_write.saturating_add(write);
        output.total = output.total.saturating_add(text).saturating_add(reasoning);
        output.text = output.text.saturating_add(text);
        output.reasoning = output.reasoning.saturating_add(reasoning);
    }
    Some(LlmUsage {
        input,
        output,
        raw_provider: json!({ "step_finish": steps }),
    })
}

/// A whole count `value` names under `key`.
fn count(value: &JsonValue, key: &str) -> Option<u64> {
    value.get(key)?.as_u64()
}

fn event_type(event: &JsonValue) -> Option<&str> {
    event.get("type").and_then(JsonValue::as_str)
}

/// The last event of type `kind` in `stream`.
fn last_event(stream: &ByoaStream, kind: &str) -> Option<JsonValue> {
    let mut last = None;
    each_event(stream, |event| {
        if event_type(&event) == Some(kind) {
            last = Some(event);
        }
    })?;
    last
}

/// Hands `visit` each JSON object `stream` holds one to a line, read whole
/// from its start in order. A line that does not open with `{` past its
/// leading blanks is passed over without being held, and one that does not
/// parse is passed over. `None` when the stream cannot be read.
fn each_event(stream: &ByoaStream, mut visit: impl FnMut(JsonValue)) -> Option<()> {
    let mut reader = BufReader::new(stream.reader());
    let mut line = Vec::new();
    loop {
        let buffered = reader.fill_buf().ok()?;
        let Some(&first) = buffered.first() else {
            return Some(());
        };
        if first.is_ascii_whitespace() {
            let blanks = buffered
                .iter()
                .take_while(|byte| byte.is_ascii_whitespace())
                .count();
            reader.consume(blanks);
        } else if first == b'{' {
            line.clear();
            reader.read_until(b'\n', &mut line).ok()?;
            if let Ok(event) = serde_json::from_slice(&line) {
                visit(event);
            }
        } else {
            skip_line(&mut reader)?;
        }
    }
}

/// Passes over the rest of one line without holding it.
fn skip_line(reader: &mut impl BufRead) -> Option<()> {
    loop {
        let buffered = reader.fill_buf().ok()?;
        if buffered.is_empty() {
            return Some(());
        }
        let (take, ends) = buffered
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or((buffered.len(), false), |at| (at + 1, true));
        reader.consume(take);
        if ends {
            return Some(());
        }
    }
}
