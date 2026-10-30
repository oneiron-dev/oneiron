//! A reply read past the pipe's framing threshold, once parsed (FIX 7988):
//! its raw bytes were charged to the host's memory floor as they were read
//! (`overrun`), and the value parsed from them is charged as it reaches
//! its call, by an explicit walk of what it holds, until that call took
//! it. The charge rides the reply to its call. A charge never refuses: a
//! floor that admits no more leaves the charge as it was and reports
//! through its own accounting, and the reply is delivered all the same.

use super::Pipe;
use crate::retention::HandleRetention;
use serde_json::Value;
use std::sync::{Arc, Mutex, PoisonError};

/// The pipe's charge for the parsed replies on their way to their calls,
/// and the bytes they hold now.
#[derive(Default)]
pub(super) struct Parsed {
    charge: Option<Box<dyn HandleRetention>>,
    held: usize,
}

/// One parsed reply's charge, given back as it drops: when its call took
/// the reply, when a reply no call waits for is taken apart, or when the
/// driver's own copies of one are dropped (FIX 11578).
pub(crate) struct Held {
    parsed: Arc<Mutex<Parsed>>,
    bytes: usize,
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut parsed = self.parsed.lock().unwrap_or_else(PoisonError::into_inner);
        let held = parsed.held.saturating_sub(self.bytes);
        if let Some(charge) = parsed.charge.as_mut() {
            charge.resize(held);
        }
        parsed.held = held;
    }
}

impl Pipe {
    /// Books this pipe's parsed past-threshold replies to `charge`, a charge
    /// on the host's memory floor holding nothing yet.
    pub(crate) fn book_parsed(&self, charge: Box<dyn HandleRetention>) {
        let mut parsed = self.parsed.lock().unwrap_or_else(PoisonError::into_inner);
        parsed.charge = Some(charge);
        parsed.held = 0;
    }

    /// Charges `value`, a reply parsed from a message read past the framing
    /// threshold, until its call took it: none where this pipe booked no
    /// charge or the floor admits no more of it.
    pub(super) fn charge_parsed(&self, value: &Value) -> Option<Held> {
        self.charge_retained(footprint(value))
    }

    /// Charges `bytes` a past-threshold reply's copies keep in the driver
    /// (FIX 11578), until the returned hold drops: none where this pipe
    /// booked no charge or the floor admits no more of them, and the
    /// copies are kept all the same.
    pub(crate) fn charge_retained(&self, bytes: usize) -> Option<Held> {
        let mut parsed = self.parsed.lock().unwrap_or_else(PoisonError::into_inner);
        let held = parsed.held.saturating_add(bytes);
        let charge = parsed.charge.as_mut()?;
        if !charge.resize(held) {
            return None;
        }
        parsed.held = held;
        Some(Held {
            parsed: Arc::clone(&self.parsed),
            bytes,
        })
    }

    /// Charges `bytes` of PNG a held screenshot keeps (FIX 11578), where
    /// they prove a past-threshold reply: base64 grows bytes by four
    /// thirds, so only a PNG whose reply the framing threshold reads past
    /// is charged. None where this pipe booked no charge, the floor
    /// admits no more, or the PNG fits an inline reply.
    pub(crate) fn charge_media(&self, bytes: usize) -> Option<Held> {
        if bytes.saturating_mul(4) / 3 < super::MAX_MESSAGE as usize {
            return None;
        }
        self.charge_retained(bytes)
    }
}

/// The bytes `items` hold, as `footprint` measures each value, with the
/// room past them the driver keeps (FIX 11578).
pub(crate) fn footprint_items(items: &[Value]) -> usize {
    let slot = std::mem::size_of::<Value>();
    let spare = items
        .capacity()
        .saturating_sub(items.len())
        .saturating_mul(slot);
    items
        .iter()
        .map(footprint)
        .fold(spare, usize::saturating_add)
}

/// The bytes `value` holds, walked with an explicit stack, as a deep one
/// is read: each value's own slot, each string's and key's room, and each
/// array's and object's room for its entries.
fn footprint(value: &Value) -> usize {
    let slot = std::mem::size_of::<Value>();
    let entry = slot + std::mem::size_of::<String>();
    let mut bytes = slot;
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::String(text) => bytes = bytes.saturating_add(text.capacity()),
            Value::Array(items) => {
                bytes = bytes.saturating_add(items.capacity().saturating_mul(slot));
                stack.extend(items);
            }
            Value::Object(map) => {
                for (key, item) in map {
                    bytes = bytes.saturating_add(entry + key.capacity());
                    stack.push(item);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    bytes
}
