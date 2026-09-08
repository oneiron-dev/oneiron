//! Reply normalization: fence/exec stripping, console-block scanning, and the structural gate.

use super::types::EngineExecutorResult;
use crate::code_run::{
    CODE_RUN_CONSOLE_CLOSE, CODE_RUN_CONSOLE_OPEN, CODE_RUN_EXEC_CLOSE, CODE_RUN_EXEC_OPEN,
};
use crate::{ContentPart, Error, FinishReason, LlmResponse};

/// Line-oriented markdown fence delimiter. The LANGUAGE SUFFIX after it is
/// inert packaging metadata: `ts`, `typescript`, `js`, `javascript`,
/// `readscript`, and arbitrary tags all follow the same path.
const CODE_FENCE: &str = "```";

/// What ONE-1929 had to remove from one model reply to reach a bare program.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ExecutorWireRepairs {
    pub trimmed_transport_whitespace: bool,
    pub stripped_code_fence: bool,
    pub stripped_exec_wrapper: bool,
    pub discarded_console_blocks: u32,
}

impl ExecutorWireRepairs {
    /// Whether this turn needed ANY healing. One healed turn counts once, no
    /// matter how many of these repairs it took.
    #[must_use]
    pub(crate) const fn healed(self) -> bool {
        self.trimmed_transport_whitespace
            || self.stripped_code_fence
            || self.stripped_exec_wrapper
            || self.discarded_console_blocks != 0
    }
}

/// One model reply, normalized onto the strict bare wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HealedExecutorReply {
    /// The sole source passed to [`JsCodeModeRuntime::run_step`].
    pub code: String,
    /// ONE-1686-owned implicit-speak payload; never part of `code` or console.
    pub trailing_speak: Option<String>,
    pub repairs: ExecutorWireRepairs,
}

/// Normalizes one provider reply into the bare executable program the
/// sandbox runs (ONE-1929).
///
/// The model-facing wire is strict bare executable plain JavaScript. The
/// executor may remove PACKAGING once, but it never trusts model-authored
/// console text: forged console blocks are deleted outright — not compared,
/// diffed, logged, or kept as a diagnostic — and the sandbox's own
/// observation is the sole console authority.
///
/// The normalization order is fixed, and each wrapper is removed at most
/// once:
///
/// 1. require a clean finish and join the response's text parts;
/// 2. partition the reply into a program candidate and a trailing region
///    (the ONE-1686 implicit-speak seam);
/// 3. drop the trailing region's console blocks, then trim what is left into
///    the speak payload;
/// 4. trim outer transport whitespace from the candidate — this pre-strip
///    trim ALONE sets `trimmed_transport_whitespace`;
/// 5. strip one whole markdown fence, ignoring its language token;
/// 6. drop the candidate's depth-0 console blocks;
/// 7. strip one whole `<exec>` / `</exec>` wrapper, never recursively, and
///    drop console blocks exposed directly inside that supported wrapper;
/// 8. trim the interior once more (no repair flag) and run the mandatory
///    source-aware structural gate.
pub(crate) fn heal_executor_reply(
    response: &LlmResponse,
) -> EngineExecutorResult<HealedExecutorReply> {
    if response.finish_reason != FinishReason::Stop {
        return Err(Error::InvalidClaimBody("executor LLM response did not finish cleanly").into());
    }
    let text = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            ContentPart::Reasoning { .. }
            | ContentPart::ToolCall { .. }
            | ContentPart::ToolResult { .. }
            | ContentPart::Image { .. } => None,
        })
        .collect::<Vec<_>>()
        .join("\n");

    let (candidate, trailing) = partition_reply(&text);
    let (cleaned_trailing, trailing_discards) =
        partition_top_level_console_blocks(trailing, ConsoleRegion::Trailing)?;
    let trailing_speak = cleaned_trailing.trim();

    let trimmed = candidate.trim();
    let mut repairs = ExecutorWireRepairs {
        trimmed_transport_whitespace: trimmed.len() != candidate.len(),
        discarded_console_blocks: trailing_discards,
        ..ExecutorWireRepairs::default()
    };

    let unfenced = match strip_one_whole_fence(trimmed)? {
        Some(interior) => {
            repairs.stripped_code_fence = true;
            interior
        }
        None => trimmed,
    };
    let (deconsoled, candidate_discards) =
        partition_top_level_console_blocks(unfenced, ConsoleRegion::Candidate)?;
    repairs.discarded_console_blocks = repairs
        .discarded_console_blocks
        .checked_add(candidate_discards)
        .ok_or(Error::ArithmeticOverflow(
            "executor discarded console blocks",
        ))?;
    let unwrapped = match strip_one_whole_exec_wrapper(&deconsoled) {
        Some(interior) => {
            repairs.stripped_exec_wrapper = true;
            // The supported outer wrapper is packaging. Once it is removed,
            // console blocks directly inside it are top-level model packaging
            // too. Scan that interior once; a nested second exec wrapper still
            // protects its own body and survives into the mandatory gate.
            let (cleaned, wrapper_discards) =
                partition_top_level_console_blocks(interior, ConsoleRegion::Candidate)?;
            repairs.discarded_console_blocks = repairs
                .discarded_console_blocks
                .checked_add(wrapper_discards)
                .ok_or(Error::ArithmeticOverflow(
                    "executor discarded console blocks",
                ))?;
            cleaned
        }
        None => deconsoled,
    };

    let code = unwrapped.trim();
    mandatory_structural_gate(code, trailing_speak)?;
    Ok(HealedExecutorReply {
        code: code.to_owned(),
        trailing_speak: (!trailing_speak.is_empty()).then(|| trailing_speak.to_owned()),
        repairs,
    })
}

/// The ONE-1686 reply partition: where the program candidate ends and the
/// trailing region begins.
///
/// A reply that OPENS with a whole markdown fence hands everything after that
/// fence's closer line to ONE-1686 as trailing prose; anything else is one
/// undivided candidate, so prose the partition cannot classify stays in front
/// of the code and fails the mandatory structural gate instead of being
/// silently split off. Two sibling fenced programs partition the same way and
/// the second fence reaches that gate as residual structure — they are never
/// joined into one source.
fn partition_reply(text: &str) -> (&str, &str) {
    let lines = reply_lines(text);
    let Some(opener) = lines.iter().position(|line| !line.text.trim().is_empty()) else {
        return (text, "");
    };
    if !lines[opener].text.trim_start().starts_with(CODE_FENCE) {
        return (text, "");
    }
    let Some(offset) = lines[opener + 1..]
        .iter()
        .position(|line| line.text.trim() == CODE_FENCE)
    else {
        return (text, "");
    };
    let split = lines[opener + 1 + offset].end;
    (&text[..split], &text[split..])
}

/// Removes ONE whole line-oriented markdown fence.
///
/// The opener must be the entire first non-empty line and the matching closer
/// the entire final non-empty line; both delimiter lines are removed in full,
/// including their terminators. The opener's language token is IGNORED — the
/// old `js`/`javascript` whitelist and `ts`/`typescript`/`readscript`
/// rejection are gone, because a language tag is not a parseability proof.
/// Anything else is left alone for the mandatory structural gate.
///
/// # Errors
///
/// A lone fence delimiter is its own first and last non-empty line: there is
/// no pair to remove and no interior to execute, so it is an invalid body.
fn strip_one_whole_fence(input: &str) -> EngineExecutorResult<Option<&str>> {
    let lines = reply_lines(input);
    let Some(first) = lines.iter().position(|line| !line.text.trim().is_empty()) else {
        return Ok(None);
    };
    if !lines[first].text.trim_start().starts_with(CODE_FENCE) {
        return Ok(None);
    }
    let Some(last) = lines.iter().rposition(|line| !line.text.trim().is_empty()) else {
        return Ok(None);
    };
    if last == first {
        return Err(
            Error::InvalidClaimBody("executor LLM response has an unpaired code fence").into(),
        );
    }
    if lines[last].text.trim() != CODE_FENCE {
        return Ok(None);
    }
    Ok(Some(&input[lines[first + 1].start..lines[last].start]))
}

/// Removes ONE whole line-oriented `<exec>` / `</exec>` wrapper.
///
/// Same byte rule as the fence: `<exec>` must be the entire first non-empty
/// line and `</exec>` the entire final non-empty line, and both delimiter
/// lines go in full. Exactly one pair strips and the helper NEVER recurses, so
/// a nested second wrapper survives and the mandatory structural gate refuses
/// it. That is also why this needs no error channel of its own.
fn strip_one_whole_exec_wrapper(input: &str) -> Option<&str> {
    let lines = reply_lines(input);
    let first = lines.iter().position(|line| !line.text.trim().is_empty())?;
    let last = lines
        .iter()
        .rposition(|line| !line.text.trim().is_empty())?;
    if first == last
        || lines[first].text.trim() != CODE_RUN_EXEC_OPEN
        || lines[last].text.trim() != CODE_RUN_EXEC_CLOSE
    {
        return None;
    }
    Some(&input[lines[first + 1].start..lines[last].start])
}

/// The mandatory structural gate every healed reply passes through.
///
/// Healing removes packaging exactly once; whatever wrapper, tag, or fence
/// structure SURVIVES that is not packaging the executor is allowed to guess
/// at, so it returns the existing typed invalid-body error and reaches the
/// existing caller-owned re-execute path. No error variant and no second
/// retry loop is introduced.
///
/// The executable-source preflight is deliberately a shape check, not a
/// parser: general JavaScript syntax errors are NOT structural garbage and
/// stay on the existing runtime-error path.
fn mandatory_structural_gate(code: &str, trailing_speak: &str) -> EngineExecutorResult<()> {
    if code.is_empty() {
        return Err(Error::InvalidClaimBody("executor LLM response missing plain JS").into());
    }
    if has_residual_wire_structure_in_source(code) {
        return Err(Error::InvalidClaimBody(
            "executor LLM response kept wire packaging after healing",
        )
        .into());
    }
    if has_residual_wire_structure_in_prose(trailing_speak) {
        return Err(Error::InvalidClaimBody(
            "executor LLM response trailed a second program instead of prose",
        )
        .into());
    }
    if !looks_like_plain_js(code) {
        return Err(
            Error::InvalidClaimBody("executor LLM response is not executable plain JS").into(),
        );
    }
    Ok(())
}

/// Whether a structural token begins a source line outside JavaScript
/// strings, template literals, and comments.
///
/// This uses the exact state transition helper the console healer uses. A
/// token-looking line inside a template or block comment is source bytes, not
/// residual packaging. Real line-oriented wrapper/fence structure in code
/// state still fails closed.
fn has_residual_wire_structure_in_source(text: &str) -> bool {
    let mut cursor = 0_usize;
    let mut state = SourceState::Code;
    let mut line_prefix_blank = true;
    while cursor < text.len() {
        let rest = &text[cursor..];
        if state == SourceState::Code && line_prefix_blank && starts_with_wire_token(rest) {
            return true;
        }
        let Some(ch) = rest.chars().next() else {
            break;
        };
        let width = advance_source_state(&mut state, rest, ch);
        let span = &text[cursor..cursor + width];
        line_prefix_blank = if span.contains('\n') {
            true
        } else {
            line_prefix_blank && span.trim().is_empty()
        };
        cursor += width;
    }
    false
}

/// Trailing prose is not JavaScript. Apostrophes and backticks in natural
/// language cannot open source literals that hide a second program.
fn has_residual_wire_structure_in_prose(text: &str) -> bool {
    text.lines()
        .map(str::trim_start)
        .any(starts_with_wire_token)
}

fn starts_with_wire_token(text: &str) -> bool {
    text.starts_with(CODE_RUN_EXEC_OPEN)
        || text.starts_with(CODE_RUN_EXEC_CLOSE)
        || text.starts_with(CODE_RUN_CONSOLE_OPEN)
        || text.starts_with(CODE_RUN_CONSOLE_CLOSE)
        || text.starts_with(CODE_FENCE)
}

/// One line of a reply, with the byte spans the one-shot strippers need.
struct ReplyLine<'a> {
    text: &'a str,
    /// Byte offset where this line's content begins.
    start: usize,
    /// Byte offset just past this line's content, before its terminator.
    end: usize,
}

/// Splits `input` into lines, keeping each line's byte span so a delimiter
/// line can be removed IN FULL, terminator included.
fn reply_lines(input: &str) -> Vec<ReplyLine<'_>> {
    let mut lines = Vec::new();
    let mut start = 0_usize;
    loop {
        let Some(offset) = input[start..].find('\n') else {
            lines.push(ReplyLine {
                text: &input[start..],
                start,
                end: input.len(),
            });
            return lines;
        };
        let newline = start + offset;
        let end = if newline > start && input.as_bytes()[newline - 1] == b'\r' {
            newline - 1
        } else {
            newline
        };
        lines.push(ReplyLine {
            text: &input[start..end],
            start,
            end,
        });
        start = newline + 1;
    }
}

/// Which half of a partitioned reply a console scan is walking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsoleRegion {
    /// The program candidate: JavaScript, so the scan tracks source state and
    /// `<exec>` wrapper depth and recognizes console blocks only at depth 0.
    Candidate,
    /// The ONE-1686 trailing region: prose, so the scan keeps its round-1
    /// recognition forms and tracks no source state — an apostrophe in
    /// English must not open a string that swallows a forged console block.
    Trailing,
}

/// Minimal JavaScript source state, tracked only well enough that a console
/// token inside a string, template literal, or comment is left ALONE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceState {
    Code,
    LineComment,
    BlockComment,
    Single,
    Double,
    Template,
}

/// Deletes top-level `<console>` … `</console>` blocks and counts them.
///
/// `heal_executor_reply` calls this once for the program candidate and once
/// for the trailing region, then sums both discard counts. The two regions
/// are different languages, so they get different recognition rules — see
/// [`ConsoleRegion`] — but the discard itself is identical and literal: the
/// bytes are dropped, never stored anywhere.
///
/// # Errors
///
/// An opener with no matching `</console>` in its region is an invalid body,
/// never speak bytes.
pub(crate) fn partition_top_level_console_blocks(
    input: &str,
    region: ConsoleRegion,
) -> EngineExecutorResult<(String, u32)> {
    ConsoleScanner::new(input, region).run()
}

/// The source-aware scanner behind [`partition_top_level_console_blocks`].
struct ConsoleScanner<'a> {
    input: &'a str,
    region: ConsoleRegion,
    out: String,
    discarded: u32,
    state: SourceState,
    /// Line-oriented `<exec>` / `</exec>` nesting depth.
    depth: u32,
    /// Everything before the cursor on this line is whitespace.
    line_prefix_blank: bool,
    /// The cursor sits immediately after a closer token that began a line.
    after_closer: bool,
    cursor: usize,
}

impl<'a> ConsoleScanner<'a> {
    fn new(input: &'a str, region: ConsoleRegion) -> Self {
        Self {
            input,
            region,
            out: String::with_capacity(input.len()),
            discarded: 0,
            state: SourceState::Code,
            depth: 0,
            line_prefix_blank: true,
            after_closer: false,
            cursor: 0,
        }
    }

    fn run(mut self) -> EngineExecutorResult<(String, u32)> {
        while self.cursor < self.input.len() {
            if !self.take_wire_token()? {
                self.take_source_span();
            }
        }
        Ok((self.out, self.discarded))
    }

    /// Consumes one wrapper/fence/console token when the cursor sits in a
    /// position where the grammar can carry one: at a line start, or
    /// immediately after a closer token that itself began a line.
    fn take_wire_token(&mut self) -> EngineExecutorResult<bool> {
        if self.state != SourceState::Code {
            return Ok(false);
        }
        let rest = &self.input[self.cursor..];
        // The trailing half is prose, not JavaScript. A complete forged
        // console block is packaging even when embedded inline after words.
        if self.region == ConsoleRegion::Trailing && rest.starts_with(CODE_RUN_CONSOLE_OPEN) {
            self.discard_console_block()?;
            return Ok(true);
        }
        if !(self.line_prefix_blank || self.after_closer) {
            return Ok(false);
        }
        if self.region == ConsoleRegion::Candidate && rest.starts_with(CODE_RUN_EXEC_OPEN) {
            self.depth = self.depth.saturating_add(1);
            self.keep_token(CODE_RUN_EXEC_OPEN, false);
        } else if rest.starts_with(CODE_RUN_EXEC_CLOSE) {
            self.depth = self.depth.saturating_sub(1);
            self.keep_token(CODE_RUN_EXEC_CLOSE, true);
        } else if self.region == ConsoleRegion::Trailing && rest.starts_with(CODE_FENCE) {
            // The candidate side has no fence-closer form left to honour: its
            // fence was already stripped.
            self.keep_token(CODE_FENCE, true);
        } else if self.depth == 0 && rest.starts_with(CODE_RUN_CONSOLE_OPEN) {
            self.discard_console_block()?;
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    /// Copies a recognized structural token through unchanged. Only console
    /// blocks are ever deleted; a surviving wrapper token is the mandatory
    /// structural gate's business, not the scanner's.
    fn keep_token(&mut self, token: &str, closer: bool) {
        self.out.push_str(token);
        self.cursor += token.len();
        self.line_prefix_blank = false;
        self.after_closer = closer;
    }

    /// Deletes one whole console block, plus the line it owned outright.
    fn discard_console_block(&mut self) -> EngineExecutorResult<()> {
        let recognition_continues =
            self.line_prefix_blank || self.after_closer || self.region == ConsoleRegion::Trailing;
        let body_at = self.cursor + CODE_RUN_CONSOLE_OPEN.len();
        let Some(offset) = self.input[body_at..].find(CODE_RUN_CONSOLE_CLOSE) else {
            return Err(Error::InvalidClaimBody(
                "executor LLM response has an unterminated console block",
            )
            .into());
        };
        let mut next = body_at + offset + CODE_RUN_CONSOLE_CLOSE.len();
        let newline = self.input[next..].find('\n').map(|at| next + at);
        let rest_of_line = &self.input[next..newline.unwrap_or(self.input.len())];
        let owned_the_line = self.line_prefix_blank && rest_of_line.trim().is_empty();
        if owned_the_line {
            // Take the blank prefix and the terminator with it, so a discard
            // cannot glue two surviving lines together.
            while self.out.ends_with([' ', '\t']) {
                self.out.pop();
            }
            next = newline.map_or(self.input.len(), |at| at + 1);
        }
        self.cursor = next;
        self.discarded = self
            .discarded
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow(
                "executor discarded console blocks",
            ))?;
        // A discard is itself a recognized closer. Preserve the grammar
        // position so glued sibling blocks are consumed one after another;
        // do not make the deleted bytes turn a nonblank prefix blank.
        self.line_prefix_blank = owned_the_line || self.line_prefix_blank;
        self.after_closer = recognition_continues;
        Ok(())
    }

    /// Copies the next source span through, advancing the source state.
    fn take_source_span(&mut self) {
        let rest = &self.input[self.cursor..];
        let Some(ch) = rest.chars().next() else {
            self.cursor = self.input.len();
            return;
        };
        let width = if self.region == ConsoleRegion::Trailing {
            ch.len_utf8()
        } else {
            advance_source_state(&mut self.state, rest, ch)
        };
        let end = self.cursor + width;
        let span = &self.input[self.cursor..end];
        self.out.push_str(span);
        self.cursor = end;
        self.line_prefix_blank = if span.contains('\n') {
            true
        } else {
            self.line_prefix_blank && span.trim().is_empty()
        };
        self.after_closer = false;
    }

    // Source-state transitions live in the shared helper below so healing and
    // residual-structure detection cannot disagree about literals/comments.
}

/// Applies one JavaScript source-state transition and returns the consumed
/// UTF-8 byte width. This intentionally recognizes only the lexical forms the
/// wire grammar needs to protect: strings, template literals, and comments.
fn advance_source_state(state: &mut SourceState, rest: &str, ch: char) -> usize {
    match *state {
        SourceState::Code => advance_code_state(state, rest, ch),
        SourceState::LineComment => {
            if ch == '\n' {
                *state = SourceState::Code;
            }
            ch.len_utf8()
        }
        SourceState::BlockComment => {
            if rest.starts_with("*/") {
                *state = SourceState::Code;
                return 2;
            }
            ch.len_utf8()
        }
        SourceState::Single | SourceState::Double | SourceState::Template => {
            advance_quoted_state(state, rest, ch)
        }
    }
}

fn advance_code_state(state: &mut SourceState, rest: &str, ch: char) -> usize {
    if rest.starts_with("//") {
        *state = SourceState::LineComment;
        return 2;
    }
    if rest.starts_with("/*") {
        *state = SourceState::BlockComment;
        return 2;
    }
    *state = match ch {
        '\'' => SourceState::Single,
        '"' => SourceState::Double,
        '`' => SourceState::Template,
        _ => SourceState::Code,
    };
    ch.len_utf8()
}

fn advance_quoted_state(state: &mut SourceState, rest: &str, ch: char) -> usize {
    if ch == '\\' {
        // The escaped character cannot close the literal.
        return 1 + rest[1..].chars().next().map_or(0, char::len_utf8);
    }
    let closes = match *state {
        SourceState::Single => ch == '\'',
        SourceState::Double => ch == '"',
        _ => ch == '`',
    };
    // Only a template literal spans lines; recovering the other two at the
    // newline keeps one stray quote from swallowing the rest of the reply.
    if closes || (ch == '\n' && *state != SourceState::Template) {
        *state = SourceState::Code;
    }
    ch.len_utf8()
}

/// The executable-source preflight: a SHAPE check on the healed program.
///
/// It refuses prose, not imperfect JavaScript. A structurally clean source
/// with a genuine syntax error still reaches the sandbox and fails on the
/// existing runtime-error path, which is the boundary this ticket keeps.
fn looks_like_plain_js(text: &str) -> bool {
    let trimmed = text.trim_start();
    let first_line = trimmed.lines().next().unwrap_or_default().trim_start();
    [
        "await ",
        "const ",
        "let ",
        "var ",
        "if ",
        "for ",
        "while ",
        "switch ",
        "try ",
        "return ",
        "throw ",
        "function ",
        "async ",
        "class ",
        "import ",
        "export ",
        "self.",
    ]
    .iter()
    .any(|prefix| first_line.starts_with(prefix))
}
