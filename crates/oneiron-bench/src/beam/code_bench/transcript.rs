//! Reads one writer's transcript in Claude Code's `--output-format
//! stream-json`: one JSON object per line, `assistant` messages carrying
//! `tool_use` blocks and `usage`, `user` messages carrying `tool_result`
//! blocks, and a closing `result`. Claude Code takes an MCP config and a
//! tool allow-list per run, which the arms need, and one harness holds for
//! every arm. A second harness adds a second reader beside this one.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use serde::Serialize;
use serde_json::Value;

use super::super::BeamResult;
use super::manifest::rfc3339_millis;
use super::profile::{Arm, names_verb, starts_with_verb};

/// Tools no arm restricts.
const NEUTRAL_TOOLS: [&str; 1] = ["TodoWrite"];
/// graph_fs reads that open one file. The serving engine's generated verb
/// tools take the file as `arguments.spec.path` (`McpVerbToolPayload`); a
/// bare `path` input is read too.
const GRAPH_FILE_READS: [&str; 3] = ["graph_fs.read_file", "graph_fs.cat", "graph_fs.head"];
/// Programs that run the command after their own options and assignments.
const COMMAND_WRAPPERS: [&str; 14] = [
    "builtin", "command", "doas", "env", "exec", "ionice", "nice", "nohup", "setsid", "stdbuf",
    "sudo", "time", "timeout", "xargs",
];
/// Shell keywords that may stand before a command.
const SHELL_KEYWORDS: [&str; 10] = [
    "!", "{", "do", "elif", "else", "if", "then", "until", "while", "}",
];
/// Shells whose `-c` argument is a command line of its own.
const SHELLS: [&str; 6] = ["ash", "bash", "dash", "ksh", "sh", "zsh"];
/// How deep nested command lines (`sh -c`, `eval`, `find -exec`) are read.
const MAX_NESTING: usize = 4;
/// Verb roots that are source control, for the Scion side.
const SOURCE_CONTROL_VERB_ROOTS: [&str; 2] = ["self.code.", "vault.code."];

/// What a transcript shows of one attempt. Times are `None` when the
/// transcript carries no timing for them.
#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct TranscriptMetrics {
    pub(super) turns: u64,
    /// Every prompt token: fresh, cache writes and cache reads.
    pub(super) input_tokens: u64,
    pub(super) output_tokens: u64,
    /// Distinct files read through the Read tool or a graph_fs file read.
    pub(super) files_opened: u64,
    pub(super) elapsed_secs: Option<f64>,
    /// Git commands and `self.code.*` / `vault.code.*` calls, call to result.
    pub(super) source_control_secs: Option<f64>,
    /// Start to the first successful `cargo check` or `cargo test`.
    pub(super) usable_tree_secs: Option<f64>,
    /// Tool calls outside the cell's profile, in order. Kept and shown; an
    /// attempt with one never grades as a pass.
    pub(super) breaches: Vec<String>,
    /// Lines that were not JSON (a killed run can cut its last line).
    pub(super) unreadable_lines: u64,
}

struct ToolCall {
    name: String,
    input: Value,
    called_ms: Option<i64>,
}

struct ToolResult {
    at_ms: Option<i64>,
    is_error: bool,
}

/// Reads the transcript at `path` against `arm`'s profile.
pub(super) fn read(path: &Path, arm: Arm) -> BeamResult<TranscriptMetrics> {
    let text = std::fs::read_to_string(path)?;
    let mut metrics = TranscriptMetrics::default();
    let mut usage: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut calls: Vec<(String, ToolCall)> = Vec::new();
    let mut results: BTreeMap<String, ToolResult> = BTreeMap::new();
    let (mut first_ms, mut last_ms) = (None::<i64>, None::<i64>);
    let mut duration_ms = None;
    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            metrics.unreadable_lines += 1;
            continue;
        };
        let at_ms = event["timestamp"].as_str().and_then(rfc3339_millis);
        if let Some(at) = at_ms {
            first_ms = Some(first_ms.map_or(at, |first: i64| first.min(at)));
            last_ms = Some(last_ms.map_or(at, |last: i64| last.max(at)));
        }
        let message = &event["message"];
        match event["type"].as_str() {
            Some("assistant") => {
                // One message can arrive as several lines with one id; its
                // usage repeats on each, so the last one counts once.
                let id = message["id"]
                    .as_str()
                    .map_or_else(|| format!("line-{number}"), str::to_owned);
                usage.insert(id, message_usage(&message["usage"]));
                for block in content(message) {
                    if block["type"] == "tool_use" {
                        let call = ToolCall {
                            name: block["name"].as_str().unwrap_or_default().to_owned(),
                            input: block["input"].clone(),
                            called_ms: at_ms,
                        };
                        let id = block["id"].as_str().unwrap_or_default().to_owned();
                        calls.push((id, call));
                    }
                }
            }
            Some("user") => {
                for block in content(message) {
                    if block["type"] == "tool_result" {
                        let id = block["tool_use_id"].as_str().unwrap_or_default().to_owned();
                        let is_error = block["is_error"].as_bool().unwrap_or(false);
                        results.insert(id, ToolResult { at_ms, is_error });
                    }
                }
            }
            Some("result") => duration_ms = event["duration_ms"].as_f64(),
            _ => {}
        }
    }
    metrics.turns = usage.len() as u64;
    for (input, output) in usage.values() {
        metrics.input_tokens += input;
        metrics.output_tokens += output;
    }
    let timed = first_ms.is_some();
    metrics.elapsed_secs = duration_ms.map(|millis| millis / 1_000.0).or_else(|| {
        first_ms
            .zip(last_ms)
            .map(|(first, last)| seconds_between(first, last))
    });
    let mut files = BTreeSet::new();
    let mut source_control_secs = 0.0;
    let mut usable_tree_secs = None;
    for (id, call) in &calls {
        if let Some(file) = opened_file(call) {
            files.insert(file);
        }
        if breaches(arm, &call.name, &call.input) {
            metrics.breaches.push(call.name.clone());
        }
        let result = results.get(id);
        let span = call
            .called_ms
            .zip(result.and_then(|result| result.at_ms))
            .map(|(called, answered)| seconds_between(called, answered));
        if is_source_control(call) {
            source_control_secs += span.unwrap_or_default();
        }
        let built = result.is_some_and(|result| !result.is_error) && is_cargo_build(call);
        if usable_tree_secs.is_none() && built {
            usable_tree_secs = first_ms
                .zip(result.and_then(|result| result.at_ms))
                .map(|(first, answered)| seconds_between(first, answered));
        }
    }
    metrics.files_opened = files.len() as u64;
    metrics.source_control_secs = timed.then_some(source_control_secs);
    metrics.usable_tree_secs = usable_tree_secs;
    Ok(metrics)
}

fn content(message: &Value) -> &[Value] {
    message["content"].as_array().map_or(&[], Vec::as_slice)
}

/// (prompt tokens, output tokens) of one message's `usage`.
fn message_usage(usage: &Value) -> (u64, u64) {
    let count = |field: &str| usage[field].as_u64().unwrap_or(0);
    (
        count("input_tokens")
            + count("cache_creation_input_tokens")
            + count("cache_read_input_tokens"),
        count("output_tokens"),
    )
}

/// A transcript spans minutes, so its milliseconds fit an f64 exactly.
fn seconds_between(from_ms: i64, to_ms: i64) -> f64 {
    (to_ms - from_ms) as f64 / 1_000.0
}

/// The MCP tool name past `mcp__<server>__`, if the call is an MCP call.
fn mcp_tool(name: &str) -> Option<(&str, &str)> {
    name.strip_prefix("mcp__")?.split_once("__")
}

fn opened_file(call: &ToolCall) -> Option<String> {
    if call.name == "Read" {
        return call.input["file_path"].as_str().map(str::to_owned);
    }
    let (_, tool) = mcp_tool(&call.name)?;
    if GRAPH_FILE_READS.iter().any(|verb| names_verb(tool, verb)) {
        call.input["arguments"]["spec"]["path"]
            .as_str()
            .or_else(|| call.input["path"].as_str())
            .map(str::to_owned)
    } else {
        None
    }
}

fn shell_command(call: &ToolCall) -> Option<&str> {
    if call.name == "Bash" {
        call.input["command"].as_str()
    } else {
        None
    }
}

/// The commands a shell line runs, each as its words from the program on,
/// quotes removed. Each command drops its variable assignments, shell
/// keywords, wrappers (`env`, `timeout`, `xargs`, `nohup`, `sudo`, ...) and
/// their options, and the program's path (`/usr/bin/rg` reads as `rg`). The
/// line of a nested `sh -c`, `eval` or `find -exec` is read the same way.
fn shell_commands(line: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    collect_commands(line, 0, &mut commands);
    commands
}

fn collect_commands(line: &str, depth: usize, commands: &mut Vec<Vec<String>>) {
    if depth > MAX_NESTING {
        return;
    }
    for words in split_line(line) {
        let Some(start) = program_start(&words) else {
            continue;
        };
        let program = program_name(&words[start]).to_owned();
        let rest = &words[start + 1..];
        let nested = match program.as_str() {
            shell if SHELLS.contains(&shell) => rest
                .iter()
                .position(|word| {
                    word.starts_with('-') && !word.starts_with("--") && word.contains('c')
                })
                .and_then(|at| rest.get(at + 1))
                .cloned(),
            "eval" => Some(rest.join(" ")),
            "find" => rest
                .iter()
                .position(|word| matches!(word.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
                .map(|at| rest[at + 1..].join(" ")),
            _ => None,
        };
        if let Some(nested) = nested {
            collect_commands(&nested, depth + 1, commands);
        }
        let mut command = vec![program];
        command.extend(rest.iter().cloned());
        commands.push(command);
    }
}

/// A shell line's simple commands as word lists, quotes and escapes
/// removed. Outside quotes the line splits at `;`, `&`, `|`, newlines,
/// parentheses and backticks; inside double quotes it splits only where
/// the shell still runs a command, at `$(` and backticks. Nothing inside
/// single quotes splits.
fn split_line(line: &str) -> Vec<Vec<String>> {
    let mut words = WordSplitter::default();
    // Each open `(`, `$(` or backtick, and whether double quotes resume
    // when it closes.
    let mut open: Vec<(char, bool)> = Vec::new();
    let (mut single, mut double) = (false, false);
    let mut chars = line.chars().peekable();
    while let Some(character) = chars.next() {
        if single {
            if character == '\'' {
                single = false;
            } else {
                words.push(character);
            }
            continue;
        }
        if double {
            match character {
                '"' => double = false,
                '\\' => {
                    if let Some(next) = chars.next() {
                        words.push(next);
                    }
                }
                '$' if chars.peek() == Some(&'(') => {
                    chars.next();
                    words.end_command();
                    open.push(('(', true));
                    double = false;
                }
                '`' => {
                    words.end_command();
                    open.push(('`', true));
                    double = false;
                }
                other => words.push(other),
            }
            continue;
        }
        match character {
            '\'' => {
                single = true;
                words.mark_quoted();
            }
            '"' => {
                double = true;
                words.mark_quoted();
            }
            '\\' => {
                if let Some(next) = chars.next().filter(|next| *next != '\n') {
                    words.push(next);
                }
            }
            '$' if chars.peek() == Some(&'(') => {
                chars.next();
                words.end_command();
                open.push(('(', false));
            }
            '(' => {
                words.end_command();
                open.push(('(', false));
            }
            ')' | '`' => {
                words.end_command();
                if open.last().is_some_and(|(kind, _)| *kind == character) {
                    double = open.pop().is_some_and(|(_, resume)| resume);
                } else if character == '`' {
                    open.push(('`', false));
                }
            }
            ';' | '&' | '|' | '\n' => words.end_command(),
            other if other.is_whitespace() => words.end_word(),
            other => words.push(other),
        }
    }
    words.finish()
}

#[derive(Default)]
struct WordSplitter {
    commands: Vec<Vec<String>>,
    words: Vec<String>,
    word: String,
    /// The word has a quoted part, so `''` is a word of its own.
    quoted: bool,
}

impl WordSplitter {
    fn push(&mut self, character: char) {
        self.word.push(character);
    }

    fn mark_quoted(&mut self) {
        self.quoted = true;
    }

    fn end_word(&mut self) {
        if !self.word.is_empty() || self.quoted {
            self.words.push(std::mem::take(&mut self.word));
        }
        self.quoted = false;
    }

    fn end_command(&mut self) {
        self.end_word();
        if !self.words.is_empty() {
            self.commands.push(std::mem::take(&mut self.words));
        }
    }

    fn finish(mut self) -> Vec<Vec<String>> {
        self.end_command();
        self.commands
    }
}

/// The index of the program word: past assignments, keywords, wrappers
/// and the wrappers' options (and `timeout`'s duration).
fn program_start(words: &[String]) -> Option<usize> {
    let mut at = 0;
    loop {
        let word = words.get(at)?.as_str();
        if is_assignment(word) || SHELL_KEYWORDS.contains(&word) {
            at += 1;
            continue;
        }
        let name = program_name(word);
        if !COMMAND_WRAPPERS.contains(&name) {
            return Some(at);
        }
        at += 1;
        while let Some(option) = words.get(at) {
            if option == "--" {
                at += 1;
                break;
            }
            if !option.starts_with('-') || option == "-" {
                break;
            }
            at += if wrapper_option_takes_value(name, option) {
                2
            } else {
                1
            };
        }
        if name == "timeout" {
            at += 1;
        }
    }
}

/// Wrapper options whose value is the next word.
fn wrapper_option_takes_value(wrapper: &str, option: &str) -> bool {
    let valued: &[&str] = match wrapper {
        "env" => &["-u", "-C", "--unset", "--chdir"],
        "nice" => &["-n", "--adjustment"],
        "timeout" => &["-s", "-k", "--signal", "--kill-after"],
        "xargs" => &["-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"],
        "sudo" | "doas" => &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"],
        "stdbuf" => &["-i", "-o", "-e"],
        "ionice" => &["-c", "-n", "-p"],
        "time" => &["-f", "-o", "--format", "--output"],
        _ => &[],
    };
    valued.contains(&option)
}

/// `NAME=value`, as a shell assigns before a command.
fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.starts_with(|first: char| first.is_ascii_alphabetic() || first == '_')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

/// The program a word names, its path dropped.
fn program_name(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// The command's words with git's global options dropped, so `git -C dir
/// grep` reads as `git grep`.
fn git_subcommand_words(command: &[String]) -> Vec<&str> {
    let mut words: Vec<&str> = command.iter().map(String::as_str).collect();
    if words.first() == Some(&"git") {
        let mut at = 1;
        while let Some(word) = words.get(at) {
            if !word.starts_with('-') {
                break;
            }
            let valued = matches!(
                *word,
                "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env"
            );
            at += if valued { 2 } else { 1 };
        }
        words.drain(1..at.min(words.len()));
    }
    words
}

fn is_source_control(call: &ToolCall) -> bool {
    if let Some(line) = shell_command(call) {
        return shell_commands(line)
            .iter()
            .any(|command| command[0] == "git");
    }
    mcp_tool(&call.name).is_some_and(|(_, tool)| {
        SOURCE_CONTROL_VERB_ROOTS
            .iter()
            .any(|root| starts_with_verb(tool, root))
    })
}

fn is_cargo_build(call: &ToolCall) -> bool {
    shell_command(call).is_some_and(|line| {
        shell_commands(line).iter().any(|command| {
            command[0] == "cargo"
                && command
                    .get(1)
                    .is_some_and(|step| step == "check" || step == "test")
        })
    })
}

/// A call outside the arm's profile: a tool it does not allow, a shell
/// command it denies however it is started, or an MCP tool of another
/// server or outside its verbs.
fn breaches(arm: Arm, name: &str, input: &Value) -> bool {
    if let Some((server, tool)) = mcp_tool(name) {
        return arm.server() != Some(server) || !arm.admits_tool(tool);
    }
    if NEUTRAL_TOOLS.contains(&name) {
        return false;
    }
    let denied = arm.denied_tools();
    if denied.iter().any(|rule| rule == name) {
        return true;
    }
    if name == "Bash" {
        let line = input["command"].as_str().unwrap_or_default();
        let prefixes: Vec<Vec<&str>> = denied
            .iter()
            .filter_map(|rule| rule.strip_prefix("Bash(")?.strip_suffix(":*)"))
            .map(|prefix| prefix.split_whitespace().collect())
            .collect();
        return shell_commands(line).iter().any(|command| {
            let words = git_subcommand_words(command);
            prefixes.iter().any(|prefix| words.starts_with(prefix))
        });
    }
    !arm.allowed_tools(&[]).iter().any(|tool| tool == name)
}
