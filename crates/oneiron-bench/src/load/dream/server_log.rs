//! The server log as `load dream` reads it: the lines written since the
//! last read, the Dreamer's `dreamer partition stages`, `dreamer wake pass`,
//! `dreamer sitting open` and `dreamer sitting close` lines (target
//! `oneiron::dreamer::stages`, L07 DREAM-OBSERVE) as `key=value` fields, and
//! the WARN and ERROR lines by message. The lines are tracing's default fmt
//! text; a field may be missing or quoted.

use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::PathBuf;
use std::time::Instant;

/// The message of one consolidation partition attempt's line.
pub(super) const STAGES: &str = "dreamer partition stages";
/// The message of one wake pass's line.
pub(super) const PASS: &str = "dreamer wake pass";
/// The message of a sitting's open line: TURNs witnessed after it join it.
pub(super) const OPEN: &str = "dreamer sitting open";
/// The message of a sitting's close line: the Meso round it queued.
pub(super) const CLOSE: &str = "dreamer sitting close";
/// The message of one physical model request send (target
/// `oneiron::model::send`, debug): the body's digest and length.
pub(super) const SENT: &str = "model request sent";
/// The span a durable step's model call runs in, as tracing's default fmt
/// opens it before a line's target: `model_step{attempt=.. step=..}:`.
const STEP_SPAN: &str = "model_step{";

/// A line's `key=value` fields, values unquoted.
pub(super) type Fields = BTreeMap<String, String>;

/// Reads a growing file from where the last read stopped; a line still
/// being written waits for its newline.
pub(in crate::load) struct Tail {
    path: PathBuf,
    offset: u64,
    partial: Vec<u8>,
}

impl Tail {
    pub(in crate::load) fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            partial: Vec::new(),
        }
    }

    /// The complete lines written since the last call.
    fn lines(&mut self) -> Vec<String> {
        let Ok(mut file) = std::fs::File::open(&self.path) else {
            return Vec::new();
        };
        let mut bytes = Vec::new();
        if file.seek(SeekFrom::Start(self.offset)).is_err() || file.read_to_end(&mut bytes).is_err()
        {
            return Vec::new();
        }
        self.offset += bytes.len() as u64;
        self.partial.extend_from_slice(&bytes);
        let Some(end) = self.partial.iter().rposition(|&b| b == b'\n') else {
            return Vec::new();
        };
        let rest = self.partial.split_off(end + 1);
        let done = std::mem::replace(&mut self.partial, rest);
        String::from_utf8_lossy(&done)
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// One Dreamer line and when the bench read it, in ms since the run began.
pub(super) struct Seen {
    pub(super) at_ms: f64,
    pub(super) fields: Fields,
}

/// One WARN or ERROR line: when it was read, its level and its message.
pub(super) struct Alarm {
    pub(super) at_ms: f64,
    pub(super) level: &'static str,
    pub(super) message: String,
}

/// Everything the log showed so far.
#[derive(Default)]
pub(in crate::load) struct Scan {
    pub(super) stages: Vec<Seen>,
    pub(super) passes: Vec<Seen>,
    pub(super) opens: Vec<Seen>,
    pub(super) closes: Vec<Seen>,
    /// The model request sends, each with its step span's `attempt` and
    /// `step` when a durable step sent it.
    pub(super) sends: Vec<Seen>,
    pub(super) alarms: Vec<Alarm>,
}

impl Scan {
    /// Reads what `tail` has new, stamped with the time since `origin`.
    pub(in crate::load) fn read(&mut self, tail: &mut Tail, origin: Instant) {
        let lines = tail.lines();
        let at_ms = origin.elapsed().as_secs_f64() * 1000.0;
        for raw in lines {
            let line = plain(&raw);
            if let Some(level) = alarm(&line) {
                self.alarms.push(Alarm {
                    at_ms,
                    level,
                    message: message(&line),
                });
            }
            if let Some(fields) = fields(&line, STAGES) {
                self.stages.push(Seen { at_ms, fields });
            } else if let Some(fields) = fields(&line, PASS) {
                self.passes.push(Seen { at_ms, fields });
            } else if let Some(fields) = fields(&line, OPEN) {
                self.opens.push(Seen { at_ms, fields });
            } else if let Some(fields) = fields(&line, CLOSE) {
                self.closes.push(Seen { at_ms, fields });
            } else if let Some(fields) = sent_fields(&line) {
                self.sends.push(Seen { at_ms, fields });
            }
        }
    }

    /// How many sitting open lines the log showed so far.
    pub(in crate::load) fn opened(&self) -> usize {
        self.opens.len()
    }

    /// Whether this server logs the Dreamer's lines at all.
    pub(super) fn observed(&self) -> bool {
        !self.stages.is_empty() || !self.passes.is_empty()
    }
}

/// `line` without terminal colour escapes.
fn plain(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI: `ESC [`, parameters, then one final byte in `@`..=`~`.
            for c in chars.by_ref() {
                if c != '[' && ('@'..='~').contains(&c) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The `key=value` fields after `message` on a default fmt line; a quoted
/// value is unquoted, a bare word is skipped. `None` when the line does not
/// carry `message`.
pub(super) fn fields(line: &str, message: &str) -> Option<Fields> {
    let rest = &line[line.find(message)? + message.len()..];
    let mut fields = Fields::new();
    let mut chars = rest.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let key: String =
            std::iter::from_fn(|| chars.next_if(|c| *c != '=' && !c.is_whitespace())).collect();
        if key.is_empty() {
            break;
        }
        if chars.next_if_eq(&'=').is_none() {
            continue;
        }
        let value = if chars.next_if_eq(&'"').is_some() {
            let mut value = String::new();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => value.extend(chars.next()),
                    '"' => break,
                    c => value.push(c),
                }
            }
            value
        } else {
            std::iter::from_fn(|| chars.next_if(|c| !c.is_whitespace())).collect()
        };
        fields.insert(key, value);
    }
    Some(fields)
}

/// A send line's fields: its own (`body`, `bytes`) and its step span's
/// (`attempt`, `step`); a line field wins over a span field of one name.
/// `None` when the line is no send line.
fn sent_fields(line: &str) -> Option<Fields> {
    let mut fields = fields(line, SENT)?;
    if let Some(start) = line.find(STEP_SPAN) {
        let span = &line[start + STEP_SPAN.len()..];
        let span = &span[..span.find('}').unwrap_or(span.len())];
        for (key, value) in span
            .split_whitespace()
            .filter_map(|word| word.split_once('='))
        {
            fields
                .entry(key.to_owned())
                .or_insert_with(|| value.to_owned());
        }
    }
    Some(fields)
}

/// A field as a number, when it is one.
pub(super) fn number(fields: &Fields, key: &str) -> Option<f64> {
    fields.get(key)?.parse().ok()
}

/// The level of a default fmt line (its second word), when it is WARN or
/// ERROR.
fn alarm(line: &str) -> Option<&'static str> {
    match line.split_whitespace().nth(1)? {
        "WARN" => Some("warn"),
        "ERROR" => Some("error"),
        _ => None,
    }
}

/// Whether `word` is a `key=value` field.
fn is_field(word: &str) -> bool {
    word.split_once('=').is_some_and(|(key, _)| {
        !key.is_empty()
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    })
}

/// A WARN or ERROR line's target and message, its fields left out: the
/// words after the level up to the first `key=value`, at most 160 chars.
fn message(line: &str) -> String {
    let words = line
        .split_whitespace()
        .skip(2)
        .take_while(|word| !is_field(word))
        .collect::<Vec<_>>()
        .join(" ");
    words.chars().take(160).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_send_line_carries_its_step_spans_attempt_and_step() {
        let raw = "\u{1b}[2m2026-11-17T08:30:00.123456Z\u{1b}[0m \u{1b}[34mDEBUG\u{1b}[0m \
            \u{1b}[1mmodel_step\u{1b}[0m\u{1b}[1m{\u{1b}[0m\u{1b}[3mattempt\u{1b}[0m\u{1b}[2m=\u{1b}[0m0a1b \
            \u{1b}[3mstep\u{1b}[0m\u{1b}[2m=\u{1b}[0m9f8e\u{1b}[1m}\u{1b}[0m\u{1b}[2m:\u{1b}[0m \
            \u{1b}[2moneiron::model::send\u{1b}[0m\u{1b}[2m:\u{1b}[0m model request sent \
            \u{1b}[3mbody\u{1b}[0m\u{1b}[2m=\u{1b}[0m00112233aabbccdd \u{1b}[3mbytes\u{1b}[0m\u{1b}[2m=\u{1b}[0m4242";
        let fields = sent_fields(&plain(raw)).expect("a send line");
        let want = [
            ("attempt", "0a1b"),
            ("body", "00112233aabbccdd"),
            ("bytes", "4242"),
            ("step", "9f8e"),
        ];
        assert_eq!(
            fields,
            want.iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<Fields>()
        );
    }

    #[test]
    fn a_send_outside_a_step_names_no_attempt_and_other_lines_are_no_sends() {
        let line = "2026-11-17T08:30:00Z DEBUG oneiron::model::send: model request sent body=00112233aabbccdd bytes=7";
        let fields = sent_fields(line).expect("a send line");
        assert_eq!(
            fields.get("body").map(String::as_str),
            Some("00112233aabbccdd")
        );
        assert!(!fields.contains_key("attempt") && !fields.contains_key("step"));
        let stages = "2026-11-17T08:30:00Z  INFO oneiron::dreamer::stages: dreamer partition stages attempt=0a1b";
        assert_eq!(sent_fields(stages), None);
    }
}
