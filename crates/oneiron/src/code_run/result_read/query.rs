//! `query`: the values a JSON path picks out of a result, or the rows of a
//! line table (JSON lines, CSV, TSV) picked by column and condition.
//!
//! A JSON document is read as a stream: the path steers the parser, every
//! value off the path is skipped unread, and each value it picks is held
//! only until it is answered, so memory is the largest picked value, never
//! the document. It cannot resume midway, so it reads past the scan bound
//! and asks that row's question instead. A table is read a row at a time
//! from a byte cursor under the scan bound.
//!
//! A selection past one reply streams into the spill sink when the caller
//! gave one (a code run binds it as a result); without one it pages. One
//! picked document value past one reply, with no sink, is answered as a
//! range ref over its own bytes in the body, with its first page.

use super::{
    READ_PIECE_BYTES, ReadBounds, Reply, ResultBody, SHAPE_HEAD_BYTES, Scan, decode, invalid_input,
    refusal, scan_limit, shape,
};
use crate::code_run::CodeRunOutputKind;
use crate::limit_ask::EngineLimit;
use crate::store::BodySink;
use crate::{Error, Result};
use serde::de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};
use std::cell::Cell;

/// Bytes of a reply kept for its fields around the picked values.
const REPLY_FIELD_BYTES: usize = 4 * 1024;

/// The custom error a picked selection stops the document parser with.
const STOPPED: &str = "query selection stopped";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryInput {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    columns: Option<Vec<String>>,
    #[serde(default, rename = "where")]
    filter: Option<Value>,
    #[serde(default)]
    limit: Option<u64>,
    #[serde(default)]
    cursor: Option<QueryCursor>,
}

/// Where a query goes on: a table's next row by its byte offset and number,
/// or the picked values of a document to pass over.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryCursor {
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    row: Option<u64>,
    #[serde(default)]
    skip: Option<u64>,
}

/// One step of a JSON path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Key(String),
    Index(u64),
    All,
}

/// Reads a path of `.key`, `["key"]`, `[i]` and `[*]` steps after an
/// optional `$`; a path may also start with a bare key (`items[*].id`).
fn parse_path(path: &str) -> std::result::Result<Vec<Step>, String> {
    let bad = |why: &str| format!("path {path:?}: {why}");
    let mut rest = path.trim();
    let rooted = rest.starts_with('$');
    rest = rest.strip_prefix('$').unwrap_or(rest);
    let mut steps = Vec::new();
    while !rest.is_empty() {
        let dotted = rest.strip_prefix('.');
        if dotted.is_some() || (steps.is_empty() && !rooted && !rest.starts_with('[')) {
            let after = dotted.unwrap_or(rest);
            if let Some(after) = after.strip_prefix('*') {
                steps.push(Step::All);
                rest = after;
                continue;
            }
            let end = after.find(['.', '[']).unwrap_or(after.len());
            if end == 0 {
                return Err(bad("a key is empty"));
            }
            steps.push(Step::Key(after[..end].to_owned()));
            rest = &after[end..];
        } else if let Some(after) = rest.strip_prefix('[') {
            if let Some(after) = after.strip_prefix("*]") {
                steps.push(Step::All);
                rest = after;
            } else if after.starts_with('"') {
                let mut keys = serde_json::Deserializer::from_str(after).into_iter::<String>();
                let key = keys
                    .next()
                    .and_then(std::result::Result::ok)
                    .ok_or_else(|| bad("a quoted key does not close"))?;
                let used = keys.byte_offset();
                rest = after[used..]
                    .strip_prefix(']')
                    .ok_or_else(|| bad("a quoted key is not followed by ]"))?;
                steps.push(Step::Key(key));
            } else {
                let end = after.find(']').ok_or_else(|| bad("a [ does not close"))?;
                let index = after[..end]
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| bad("an index is not a whole number"))?;
                steps.push(Step::Index(index));
                rest = &after[end + 1..];
            }
        } else {
            return Err(bad("expected .key, [\"key\"], [i] or [*]"));
        }
    }
    Ok(steps)
}

/// The fields of one line of a delimited table (RFC 4180): a quoted field
/// keeps its delimiters, and `""` in it is one quote. A quoted field that
/// runs past its line is not joined to the next.
pub(super) fn split_fields(line: &str, delimiter: u8) -> Vec<String> {
    let delimiter = char::from(delimiter);
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut fresh = true;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c != '"' {
                field.push(c);
            } else if chars.peek() == Some(&'"') {
                field.push('"');
                chars.next();
            } else {
                quoted = false;
            }
        } else if c == '"' && fresh {
            quoted = true;
            fresh = false;
        } else if c == delimiter {
            fields.push(std::mem::take(&mut field));
            fresh = true;
        } else {
            field.push(c);
            fresh = false;
        }
    }
    fields.push(field);
    fields
}

/// A `where` comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
}

impl Op {
    fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "=" | "==" => Self::Eq,
            "!=" => Self::Ne,
            "<" => Self::Lt,
            "<=" => Self::Le,
            ">" => Self::Gt,
            ">=" => Self::Ge,
            "contains" => Self::Contains,
            _ => return None,
        })
    }
}

/// Which picked values a query keeps as rows, and the columns it keeps of
/// each.
struct Filter {
    columns: Option<Vec<String>>,
    conditions: Vec<(String, Op, Value)>,
}

impl Filter {
    /// `where` as `{col: value}` (each equal) or `[[col, op, value], ...]`.
    fn parse(
        columns: Option<Vec<String>>,
        filter: Option<Value>,
    ) -> std::result::Result<Self, String> {
        let conditions = match filter {
            None => Vec::new(),
            Some(Value::Object(fields)) => fields
                .into_iter()
                .map(|(column, value)| (column, Op::Eq, value))
                .collect(),
            Some(Value::Array(rules)) => rules
                .into_iter()
                .map(|rule| match rule {
                    Value::Array(parts) => match <[Value; 3]>::try_from(parts) {
                        Ok([Value::String(column), Value::String(op), value]) => Op::parse(&op)
                            .map(|op| (column, op, value))
                            .ok_or_else(|| format!("where: unknown operator {op:?}")),
                        _ => Err("where: a rule is [column, op, value]".to_owned()),
                    },
                    _ => Err("where: a rule is [column, op, value]".to_owned()),
                })
                .collect::<std::result::Result<_, _>>()?,
            Some(_) => return Err("where is {column: value} or [[column, op, value]]".to_owned()),
        };
        Ok(Self {
            columns,
            conditions,
        })
    }

    fn keeps(&self, row: &Value) -> bool {
        self.conditions
            .iter()
            .all(|(column, op, want)| compare(row.get(column).unwrap_or(&Value::Null), *op, want))
    }

    fn project(&self, row: Value) -> Value {
        let Some(columns) = &self.columns else {
            return row;
        };
        let mut fields = match row {
            Value::Object(fields) => fields,
            _ => Map::new(),
        };
        let mut projected = Map::new();
        for column in columns {
            let value = fields.remove(column).unwrap_or(Value::Null);
            projected.insert(column.clone(), value);
        }
        Value::Object(projected)
    }
}

/// A value as a number: a JSON number, or a string that reads as one (a
/// CSV field).
fn number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// Equality as `where` reads it: numbers by value, anything else as JSON.
fn same(have: &Value, want: &Value) -> bool {
    match want {
        Value::Number(_) => number(have).zip(number(want)).is_some_and(|(a, b)| a == b),
        _ => have == want,
    }
}

fn compare(have: &Value, op: Op, want: &Value) -> bool {
    match op {
        Op::Eq => same(have, want),
        Op::Ne => !same(have, want),
        Op::Contains => match (have, want) {
            (Value::String(have), Value::String(want)) => have.contains(want.as_str()),
            (Value::Array(items), _) => items.iter().any(|item| same(item, want)),
            _ => false,
        },
        Op::Lt | Op::Le | Op::Gt | Op::Ge => {
            let order = match (have, want) {
                (Value::String(have), Value::String(want)) => {
                    Some(have.as_str().cmp(want.as_str()))
                }
                _ => number(have)
                    .zip(number(want))
                    .and_then(|(have, want)| have.partial_cmp(&want)),
            };
            order.is_some_and(|order| match op {
                Op::Lt => order.is_lt(),
                Op::Le => order.is_le(),
                Op::Gt => order.is_gt(),
                _ => order.is_ge(),
            })
        }
    }
}

/// Why a selection stopped before its source ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// It reached its `limit`.
    Limit,
    /// The next value would not fit the reply, and there is no sink.
    Budget,
    /// Its path picks one value, and it has it.
    One,
}

/// What a query picked, as it picks it: held up to one reply, then, when
/// it has a sink, streamed into it whole.
struct Picked<'s> {
    filter: Option<Filter>,
    limit: Option<u64>,
    /// Values (or rows) rather than one value.
    many: bool,
    budget: usize,
    held: Vec<Box<RawValue>>,
    held_bytes: usize,
    spill: Option<&'s mut BodySink>,
    spilling: bool,
    count: u64,
    /// Picked document values to pass over, and how many it has met.
    skip: u64,
    seen: u64,
    stop: Option<Stop>,
    failed: Option<Error>,
    /// The one document value that did not fit an empty reply, with no
    /// sink to stream it into.
    oversized: Option<Box<RawValue>>,
    /// The bytes the parser had taken from the body when the last picked
    /// value ended.
    value_end: u64,
}

impl Picked<'_> {
    fn rows(&self) -> bool {
        self.filter.is_some()
    }

    /// Offers a picked document value: kept whole, or read as a row.
    fn offer_raw(&mut self, raw: Box<RawValue>) -> Result<bool> {
        if self.filter.is_none() {
            return self.emit(raw);
        }
        let value = serde_json::from_str(raw.get())
            .map_err(|error| Error::InvalidConfig(format!("query value: {error}")))?;
        self.offer(value)
    }

    /// Offers one picked value: a row the filter keeps is projected first.
    /// Whether the selection goes on.
    fn offer(&mut self, value: Value) -> Result<bool> {
        let value = match &self.filter {
            Some(filter) if !filter.keeps(&value) => return Ok(true),
            Some(filter) => filter.project(value),
            None => value,
        };
        let raw = serde_json::value::to_raw_value(&value)
            .map_err(|error| Error::InvalidConfig(format!("query value encoding: {error}")))?;
        self.emit(raw)
    }

    fn emit(&mut self, item: Box<RawValue>) -> Result<bool> {
        if !self.spilling && self.held_bytes + item.get().len() + 1 > self.budget {
            let (rows, many) = (self.rows(), self.many);
            let Some(sink) = self.spill.as_deref_mut() else {
                if self.held.is_empty() && self.filter.is_none() {
                    self.oversized = Some(item);
                }
                self.stop = Some(Stop::Budget);
                return Ok(false);
            };
            if many && !rows {
                sink.write(b"[")?;
            }
            for (at, held) in self.held.iter().enumerate() {
                write_item(sink, rows, many, at == 0, held)?;
            }
            self.held = Vec::new();
            self.spilling = true;
        }
        if self.spilling {
            let (rows, many, first) = (self.rows(), self.many, self.count == 0);
            if let Some(sink) = self.spill.as_deref_mut() {
                write_item(sink, rows, many, first, &item)?;
            }
        } else {
            self.held_bytes += item.get().len() + 1;
            self.held.push(item);
        }
        self.count += 1;
        if self.limit.is_some_and(|limit| self.count >= limit) {
            self.stop = Some(Stop::Limit);
            return Ok(false);
        }
        if !self.many {
            self.stop = Some(Stop::One);
            return Ok(false);
        }
        Ok(true)
    }

    /// The reply: the values held, or, past one reply, the count streamed
    /// into the sink, closed.
    fn finish(mut self, reference: &str, done: bool, next: Option<Value>) -> Result<Reply> {
        if self.spilling {
            let (rows, many) = (self.rows(), self.many);
            if let Some(sink) = self.spill.as_deref_mut()
                && many
                && !rows
            {
                sink.write(b"]")?;
            }
            return Ok(Reply::Spilled {
                count: self.count,
                next,
            });
        }
        if self.stop == Some(Stop::Budget) && self.held.is_empty() {
            let mut refused = refusal("selection_too_large");
            refused["error"] = json!(
                "one value this query picks is larger than one reply; pick inside it with a \
                 longer path, or slice the result"
            );
            return Ok(Reply::Denied(refused));
        }
        let held = if self.rows() || self.many {
            serde_json::to_value(&self.held)
        } else {
            serde_json::to_value(self.held.first())
        }
        .map_err(|error| Error::InvalidConfig(format!("query reply encoding: {error}")))?;
        let mut reply = json!({"ref": reference, "count": self.count, "done": done});
        let field = if self.rows() {
            "rows"
        } else if self.many {
            "values"
        } else {
            "value"
        };
        reply[field] = held;
        if let Some(next) = next {
            reply["next"] = next;
        }
        Ok(Reply::Output(reply))
    }
}

/// Writes one picked value into a spill sink: a row as a JSON line, a value
/// of many as an array element, one value as it is.
fn write_item(
    sink: &mut BodySink,
    rows: bool,
    many: bool,
    first: bool,
    item: &RawValue,
) -> Result<()> {
    if many && !rows && !first {
        sink.write(b",")?;
    }
    sink.write(item.get().as_bytes())?;
    if rows {
        sink.write(b"\n")?;
    }
    Ok(())
}

/// `query`: see the module. `handle` is the handle of the result `body`
/// is of, which a range ref over one picked value names.
pub(super) fn query(
    body: &dyn ResultBody,
    reference: &str,
    handle: &str,
    input: Value,
    bounds: &ReadBounds<'_>,
    spill: Option<&mut BodySink>,
) -> Result<Reply> {
    let input: QueryInput = match decode(input) {
        Ok(input) => input,
        Err(refused) => return Ok(Reply::Denied(refused)),
    };
    if input.limit == Some(0) {
        return Ok(Reply::Denied(invalid_input("limit must be at least 1")));
    }
    let filter = if input.columns.is_some() || input.filter.is_some() {
        match Filter::parse(input.columns, input.filter) {
            Ok(filter) => Some(filter),
            Err(error) => return Ok(Reply::Denied(invalid_input(error))),
        }
    } else {
        None
    };
    let steps = match input.path.as_deref() {
        Some(path) => match parse_path(path) {
            Ok(steps) => steps,
            Err(error) => return Ok(Reply::Denied(invalid_input(error))),
        },
        None if filter.is_some() => vec![Step::All],
        None => Vec::new(),
    };
    let head = body.read(0, SHAPE_HEAD_BYTES)?;
    let shape = shape::shape(&head, body.kind(), head.len() as u64 == body.len());
    let table = match shape["format"].as_str() {
        Some("json") => None,
        Some("jsonl") => Some(None),
        Some("csv") => Some(Some(b',')),
        Some("tsv") => Some(Some(b'\t')),
        _ => {
            let mut refused = refusal("not_queryable");
            refused["shape"] = shape;
            return Ok(Reply::Denied(refused));
        }
    };
    // A table is an array of its rows.
    let steps = if table.is_some() && steps.is_empty() {
        vec![Step::All]
    } else {
        steps
    };
    let cursor = input.cursor.unwrap_or_default();
    let picked = Picked {
        many: filter.is_some() || steps.contains(&Step::All),
        filter,
        limit: input.limit,
        budget: bounds.reply_bytes.saturating_sub(REPLY_FIELD_BYTES),
        held: Vec::new(),
        held_bytes: 0,
        spill,
        spilling: false,
        count: 0,
        skip: cursor.skip.unwrap_or(0),
        seen: 0,
        stop: None,
        failed: None,
        oversized: None,
        value_end: 0,
    };
    match table {
        None => document(body, reference, handle, &steps, picked, bounds),
        Some(delimiter) => table_rows(body, reference, &steps, delimiter, &cursor, picked, bounds),
    }
}

/// Picks values out of a JSON document as it streams past.
fn document(
    body: &dyn ResultBody,
    reference: &str,
    handle: &str,
    steps: &[Step],
    mut picked: Picked<'_>,
    bounds: &ReadBounds<'_>,
) -> Result<Reply> {
    let mut reader = BodyReader { body, at: 0 };
    let consumed = Cell::new(0);
    let parsed = {
        let buffered = std::io::BufReader::with_capacity(READ_PIECE_BYTES, &mut reader);
        let mut parser = serde_json::Deserializer::from_reader(Counted {
            inner: buffered,
            consumed: &consumed,
        });
        Pick {
            steps,
            picked: &mut picked,
            consumed: &consumed,
        }
        .deserialize(&mut parser)
    };
    // A document cannot be resumed midway, so it is read past the scan
    // bound, and the row's question is asked once.
    bounds
        .watch
        .measure(EngineLimit::CodeResultScanBytes, reader.at);
    if let Some(failed) = picked.failed.take() {
        return Err(failed);
    }
    let done = match parsed {
        Ok(()) => true,
        Err(_) if picked.stop.is_some() => picked.stop == Some(Stop::One),
        Err(error) => {
            let mut refused = refusal("invalid_json");
            refused["error"] = json!(error.to_string());
            return Ok(Reply::Denied(refused));
        }
    };
    if picked.stop == Some(Stop::Budget)
        && let Some(raw) = picked.oversized.take()
        && let Some(paged) = page_value(body, handle, &raw, picked.value_end, bounds)?
    {
        let mut reply = json!({
            "ref": reference,
            "count": 1,
            "done": !picked.many,
            "paged": paged,
        });
        if picked.many {
            reply["next"] = json!({"skip": picked.seen});
        }
        return Ok(Reply::Output(reply));
    }
    let next = match picked.stop {
        Some(Stop::Limit) => Some(json!({"skip": picked.seen})),
        Some(Stop::Budget) => Some(json!({"skip": picked.seen.saturating_sub(1)})),
        _ => None,
    };
    picked.finish(reference, done, next)
}

/// The one picked value `raw` too large for a reply, as a range ref over
/// its own bytes in the body (`<handle>#<start>-<end>`, in the whole
/// body's offsets) with its size and its first page, as `slice` reads it:
/// the reader goes on with `slice` of that ref from the page's `next`. The
/// parser had taken `end` bytes from the body when `raw` ended, one of them
/// perhaps a byte it peeked past it, so the value sits at `end - k` for a
/// `k` of 0 or 1: the one whose bytes there are `raw`'s. `None` when
/// neither is.
fn page_value(
    body: &dyn ResultBody,
    handle: &str,
    raw: &RawValue,
    end: u64,
    bounds: &ReadBounds<'_>,
) -> Result<Option<Value>> {
    let text = raw.get().as_bytes();
    let len = text.len() as u64;
    let head = &text[..text.len().min(64)];
    let mut start = None;
    for peeked in [0, 1] {
        let Some(at) = end.checked_sub(len + peeked) else {
            continue;
        };
        if body.read(at, head.len())? == head && body.read(at + len - 1, 1)?.last() == text.last()
        {
            start = Some(at);
            break;
        }
    }
    let Some(start) = start else {
        return Ok(None);
    };
    let window = ValueWindow { body, start, len };
    let from = window.base();
    let range_ref = format!("{handle}#{from}-{}", from + len);
    let page_bounds = ReadBounds {
        reply_bytes: bounds.reply_bytes.saturating_sub(REPLY_FIELD_BYTES),
        watch: bounds.watch,
    };
    match super::slice::slice(&window, &range_ref, json!({"bytes": [0]}), &page_bounds)? {
        Reply::Output(mut page) => {
            page["bytes"] = json!(len);
            Ok(Some(page))
        }
        Reply::Denied(_) | Reply::Spilled { .. } => Ok(None),
    }
}

/// The bytes of one picked value, as a window of the body it is in.
struct ValueWindow<'b> {
    body: &'b dyn ResultBody,
    start: u64,
    len: u64,
}

impl ResultBody for ValueWindow<'_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn kind(&self) -> CodeRunOutputKind {
        self.body.kind()
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let take = usize::try_from(self.len.saturating_sub(offset).min(len as u64))
            .map_err(|_| Error::ArithmeticOverflow("code-run result read"))?;
        self.body.read(self.start + offset, take)
    }

    fn line_index(&self) -> Option<Vec<u64>> {
        None
    }

    fn base(&self) -> u64 {
        self.body.base() + self.start
    }
}

/// A reader that counts the bytes taken from it.
struct Counted<'c, R> {
    inner: R,
    consumed: &'c Cell<u64>,
}

impl<R: std::io::Read> std::io::Read for Counted<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.consumed.set(self.consumed.get() + read as u64);
        Ok(read)
    }
}

/// A body as a byte reader, a piece at a time.
struct BodyReader<'b> {
    body: &'b dyn ResultBody,
    at: u64,
}

impl std::io::Read for BodyReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes = self
            .body
            .read(self.at, buf.len().min(READ_PIECE_BYTES))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        buf[..bytes.len()].copy_from_slice(&bytes);
        self.at += bytes.len() as u64;
        Ok(bytes.len())
    }
}

/// The value at one point of the document, read as the rest of the path
/// steers: past its last step, the picked value whole. `consumed` counts
/// the bytes the parser has taken from the body.
struct Pick<'a, 's> {
    steps: &'a [Step],
    picked: &'a mut Picked<'s>,
    consumed: &'a Cell<u64>,
}

impl<'de> DeserializeSeed<'de> for Pick<'_, '_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<(), D::Error> {
        let Some((step, rest)) = self.steps.split_first() else {
            self.picked.seen += 1;
            if self.picked.seen <= self.picked.skip {
                IgnoredAny::deserialize(deserializer)?;
                return Ok(());
            }
            let raw = Box::<RawValue>::deserialize(deserializer)?;
            self.picked.value_end = self.consumed.get();
            return match self.picked.offer_raw(raw) {
                Ok(true) => Ok(()),
                Ok(false) => Err(D::Error::custom(STOPPED)),
                Err(error) => {
                    self.picked.failed = Some(error);
                    Err(D::Error::custom(STOPPED))
                }
            };
        };
        deserializer.deserialize_any(Descend {
            step,
            rest,
            picked: self.picked,
            consumed: self.consumed,
        })
    }
}

/// One path step into an object or an array; any other value holds none.
struct Descend<'a, 's> {
    step: &'a Step,
    rest: &'a [Step],
    picked: &'a mut Picked<'s>,
    consumed: &'a Cell<u64>,
}

impl<'de> Visitor<'de> for Descend<'_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            let hit = match self.step {
                Step::Key(want) => *want == key,
                Step::All => true,
                Step::Index(_) => false,
            };
            if hit {
                map.next_value_seed(Pick {
                    steps: self.rest,
                    picked: &mut *self.picked,
                    consumed: self.consumed,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        let mut at = 0_u64;
        loop {
            let hit = match self.step {
                Step::Index(want) => *want == at,
                Step::All => true,
                Step::Key(_) => false,
            };
            let more = if hit {
                seq.next_element_seed(Pick {
                    steps: self.rest,
                    picked: &mut *self.picked,
                    consumed: self.consumed,
                })?
                .is_some()
            } else {
                seq.next_element::<IgnoredAny>()?.is_some()
            };
            if !more {
                return Ok(());
            }
            at += 1;
        }
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
}

/// The values `steps` pick out of one row held in memory.
fn select(value: Value, steps: &[Step], out: &mut Vec<Value>) {
    let Some((step, rest)) = steps.split_first() else {
        out.push(value);
        return;
    };
    match (step, value) {
        (Step::Key(key), Value::Object(mut fields)) => {
            if let Some(value) = fields.remove(key) {
                select(value, rest, out);
            }
        }
        (Step::Index(index), Value::Array(items)) => {
            if let Some(value) = usize::try_from(*index)
                .ok()
                .and_then(|index| items.into_iter().nth(index))
            {
                select(value, rest, out);
            }
        }
        (Step::All, Value::Array(items)) => {
            for value in items {
                select(value, rest, out);
            }
        }
        (Step::All, Value::Object(fields)) => {
            for (_, value) in fields {
                select(value, rest, out);
            }
        }
        _ => {}
    }
}

/// One line of a table as its reader meets it.
enum Line {
    /// A line's bytes, less its newline.
    Row(Vec<u8>),
    End,
    /// The scan bound ended the read before the line did.
    Limit,
}

/// A body's lines, read forward a piece at a time from a byte offset.
struct LineReader<'b> {
    body: &'b dyn ResultBody,
    held: Vec<u8>,
    held_at: u64,
    /// Where the next line starts.
    at: u64,
}

impl<'b> LineReader<'b> {
    fn new(body: &'b dyn ResultBody, at: u64) -> Self {
        Self {
            body,
            held: Vec::new(),
            held_at: at,
            at,
        }
    }

    fn next(&mut self, scan: &mut Scan) -> Result<Line> {
        loop {
            let from = usize::try_from(self.at - self.held_at)
                .map_err(|_| Error::ArithmeticOverflow("code-run result line"))?;
            if let Some(newline) = self.held[from..].iter().position(|byte| *byte == b'\n') {
                let row = self.held[from..from + newline].to_vec();
                self.at += newline as u64 + 1;
                return Ok(Line::Row(row));
            }
            let end = self.held_at + self.held.len() as u64;
            if end >= self.body.len() {
                if from == self.held.len() {
                    return Ok(Line::End);
                }
                let row = self.held[from..].to_vec();
                self.at = end;
                return Ok(Line::Row(row));
            }
            self.held.drain(..from);
            self.held_at = self.at;
            let piece = scan.read(self.body, end, READ_PIECE_BYTES)?;
            if piece.is_empty() {
                return Ok(Line::Limit);
            }
            self.held.extend_from_slice(&piece);
        }
    }
}

/// A line less a carriage return before its newline.
fn line_text(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\r").unwrap_or(bytes)
}

/// Picks rows out of a line table: JSON lines (`delimiter` `None`) or a
/// CSV/TSV table whose first line names its columns. A row of JSON lines
/// that does not parse is passed over and counted.
fn table_rows(
    body: &dyn ResultBody,
    reference: &str,
    steps: &[Step],
    delimiter: Option<u8>,
    cursor: &QueryCursor,
    mut picked: Picked<'_>,
    bounds: &ReadBounds<'_>,
) -> Result<Reply> {
    let mut scan = Scan::new(bounds.scan_bytes());
    let Some((first, rest)) = steps.split_first() else {
        return picked.finish(reference, true, None);
    };
    let only = match first {
        Step::All => None,
        Step::Index(index) => Some(*index),
        Step::Key(_) => return picked.finish(reference, true, None),
    };
    let mut header = Vec::new();
    let mut body_start = 0;
    if let Some(delimiter) = delimiter {
        let mut lines = LineReader::new(body, 0);
        match lines.next(&mut scan)? {
            Line::Row(bytes) => {
                header = split_fields(&String::from_utf8_lossy(line_text(&bytes)), delimiter);
            }
            Line::End => return picked.finish(reference, true, None),
            Line::Limit => {
                let mut reply =
                    picked.finish(reference, false, Some(json!({"offset": 0, "row": 0})))?;
                if let Reply::Output(reply) = &mut reply {
                    reply["limit"] = scan_limit();
                }
                return Ok(reply);
            }
        }
        body_start = lines.at;
    }
    let mut row = cursor.row.unwrap_or(0);
    let mut lines = LineReader::new(body, cursor.offset.unwrap_or(body_start).max(body_start));
    let mut skipped = 0_u64;
    let mut limited = false;
    let (done, next) = loop {
        let start = lines.at;
        let bytes = match lines.next(&mut scan)? {
            Line::Row(bytes) => bytes,
            Line::End => break (true, None),
            Line::Limit => {
                limited = true;
                break (false, Some(json!({"offset": start, "row": row})));
            }
        };
        let text = line_text(&bytes);
        if text.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let this = row;
        row += 1;
        match only {
            Some(index) if this < index => continue,
            Some(index) if this > index => break (true, None),
            _ => {}
        }
        let value = match delimiter {
            None => match serde_json::from_slice::<Value>(text) {
                Ok(value) => value,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            },
            Some(delimiter) => {
                let fields = split_fields(&String::from_utf8_lossy(text), delimiter);
                let mut named = Map::new();
                for (at, field) in fields.into_iter().enumerate() {
                    let column = header.get(at).cloned().unwrap_or_else(|| format!("_{at}"));
                    named.insert(column, Value::String(field));
                }
                for column in &header {
                    named.entry(column.clone()).or_insert(Value::Null);
                }
                Value::Object(named)
            }
        };
        let mut values = Vec::new();
        select(value, rest, &mut values);
        let mut going = true;
        for value in values {
            if !picked.offer(value)? {
                going = false;
                break;
            }
        }
        if !going {
            break match picked.stop {
                Some(Stop::Budget) => (false, Some(json!({"offset": start, "row": this}))),
                Some(Stop::Limit) => (false, Some(json!({"offset": lines.at, "row": row}))),
                _ => (true, None),
            };
        }
        if only.is_some() {
            break (true, None);
        }
    };
    let mut reply = picked.finish(reference, done, next)?;
    if let Reply::Output(reply) = &mut reply {
        if limited {
            reply["limit"] = scan_limit();
        }
        if skipped > 0 {
            reply["skipped"] = json!(skipped);
        }
    }
    Ok(reply)
}
