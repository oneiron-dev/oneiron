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
/// the reply, or when a reply no call waits for is taken apart.
pub(super) struct Held {
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
        let bytes = footprint(value);
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
