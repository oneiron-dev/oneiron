//! What a query picks, as it picks it: the values it holds for one reply,
//! and the selection it streams into a spill sink past one reply.
//!
//! A scoped child's selection stops at its live cutoff (FIX 8233). Each
//! picked value checks it before it is held or written, each spill write
//! checks it first, and a spilled selection checks it before it is closed.
//! A cut selection is never closed and never answered as whole.

use super::Filter;
use crate::code_run::result_read::{LiveCutoff, Reply, refusal};
use crate::store::BodySink;
use crate::{Error, Result};
use serde_json::value::RawValue;
use serde_json::{Value, json};

/// Why a selection stopped before its source ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stop {
    /// It reached its `limit`.
    Limit,
    /// The next value would not fit the reply, and there is no sink.
    Budget,
    /// Its path picks one value, and it has it.
    One,
}

/// What a query picked, as it picks it: held up to one reply, then, when
/// it has a sink, streamed into it whole.
pub(super) struct Picked<'s> {
    pub(super) filter: Option<Filter>,
    pub(super) limit: Option<u64>,
    /// Values (or rows) rather than one value.
    pub(super) many: bool,
    pub(super) budget: usize,
    pub(super) held: Vec<Box<RawValue>>,
    pub(super) held_bytes: usize,
    pub(super) spill: Option<&'s mut BodySink>,
    pub(super) spilling: bool,
    pub(super) count: u64,
    /// Picked document values to pass over, and how many it has met.
    pub(super) skip: u64,
    pub(super) seen: u64,
    pub(super) stop: Option<Stop>,
    pub(super) failed: Option<Error>,
    /// The one selected value that did not fit an empty reply, with no
    /// sink to stream it into, or whose byte page is being resumed.
    pub(super) oversized: Option<Box<RawValue>>,
    pub(super) within: Option<u64>,
    /// The bytes the parser had taken from the body when the last picked
    /// value ended.
    pub(super) value_end: u64,
    /// The live cutoff of the scoped child the query reads for (FIX 8233).
    pub(super) live_cutoff: LiveCutoff<'s>,
}

impl Picked<'_> {
    fn rows(&self) -> bool {
        self.filter.is_some()
    }

    /// Offers a picked document value: kept whole, or read as a row.
    pub(super) fn offer_raw(&mut self, raw: Box<RawValue>) -> Result<bool> {
        if self.filter.is_none() {
            return self.emit(raw);
        }
        let value = serde_json::from_str(raw.get())
            .map_err(|error| Error::InvalidConfig(format!("query value: {error}")))?;
        self.offer(value)
    }

    /// Offers one picked value: a row the filter keeps is projected first.
    /// Whether the selection goes on.
    pub(super) fn offer(&mut self, value: Value) -> Result<bool> {
        let value = match &self.filter {
            Some(filter) if !filter.keeps(&value) => return Ok(true),
            Some(filter) => filter.project(value),
            None => value,
        };
        let raw = serde_json::value::to_raw_value(&value)
            .map_err(|error| Error::InvalidConfig(format!("query value encoding: {error}")))?;
        self.emit(raw)
    }

    /// Holds or writes one kept value, its live cutoff checked first (FIX
    /// 8233).
    fn emit(&mut self, item: Box<RawValue>) -> Result<bool> {
        self.live_cutoff.check()?;
        if !self.spilling
            && (self.within.is_some() || self.held_bytes + item.get().len() + 1 > self.budget)
        {
            let (rows, many, cutoff) = (self.rows(), self.many, self.live_cutoff);
            let Some(sink) = self.spill.as_deref_mut() else {
                if self.held.is_empty() {
                    self.oversized = Some(item);
                }
                self.stop = Some(Stop::Budget);
                return Ok(false);
            };
            if many && !rows {
                sink.write(b"[")?;
            }
            for (at, held) in self.held.iter().enumerate() {
                write_item(sink, cutoff, rows, many, at == 0, held)?;
            }
            self.held = Vec::new();
            self.spilling = true;
        }
        if self.spilling {
            let (rows, many, first) = (self.rows(), self.many, self.count == 0);
            let cutoff = self.live_cutoff;
            if let Some(sink) = self.spill.as_deref_mut() {
                write_item(sink, cutoff, rows, many, first, &item)?;
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
    /// into the sink, closed. A spilled selection is closed only while its
    /// live cutoff is not reached (FIX 8233).
    pub(super) fn finish(
        mut self,
        reference: &str,
        done: bool,
        next: Option<Value>,
    ) -> Result<Reply> {
        if self.spilling {
            self.live_cutoff.check()?;
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
/// of many as an array element, one value as it is. Nothing is written once
/// the live cutoff is reached (FIX 8233).
fn write_item(
    sink: &mut BodySink,
    live_cutoff: LiveCutoff<'_>,
    rows: bool,
    many: bool,
    first: bool,
    item: &RawValue,
) -> Result<()> {
    live_cutoff.check()?;
    if many && !rows && !first {
        sink.write(b",")?;
    }
    sink.write(item.get().as_bytes())?;
    if rows {
        sink.write(b"\n")?;
    }
    Ok(())
}
