//! A value's drop, clone, comparison and print, none of which recurses: each
//! walks the value with a stack on the heap, so a value of any depth takes
//! no more of the thread's stack than a flat one (FIX 6191).

use std::fmt;

use super::Value;

impl Drop for Value {
    fn drop(&mut self) {
        // A leaf, or an empty container, has nothing to take apart.
        let mut stack = Vec::new();
        take_children(self, &mut stack);
        while let Some(mut child) = stack.pop() {
            take_children(&mut child, &mut stack);
            // `child` drops here with no children left.
        }
    }
}

/// Moves a container's children onto `stack`, leaving it empty.
fn take_children(value: &mut Value, stack: &mut Vec<Value>) {
    match value {
        Value::Array(items) if !items.is_empty() => stack.append(items),
        Value::Map(entries) if !entries.is_empty() => {
            for (key, item) in std::mem::take(entries) {
                stack.push(key);
                stack.push(item);
            }
        }
        _ => {}
    }
}

/// A container a [`Builder`] is filling: what it holds so far and the
/// values it still owes.
#[derive(Debug)]
pub(crate) enum Open {
    Array {
        items: Vec<Value>,
        left: u64,
    },
    Map {
        entries: Vec<(Value, Value)>,
        key: Option<Value>,
        /// Keys and values still owed.
        left: u64,
    },
}

/// Builds one value bottom-up from a walk of it in order, with no
/// recursion: a leaf goes into the container being filled, and a container
/// that has all its values goes into its own parent.
#[derive(Debug, Default)]
pub(crate) struct Builder {
    stack: Vec<Open>,
    done: Option<Value>,
}

impl Builder {
    /// The next value in the walk, a leaf or an empty container.
    pub(crate) fn leaf(&mut self, value: Value) {
        self.place(value);
    }

    /// An array of `len` items opens; `room` caps what is allocated up
    /// front for them, since a length on the wire is only a claim.
    pub(crate) fn array(&mut self, len: u64, room: usize) {
        if len == 0 {
            self.place(Value::Array(Vec::new()));
        } else {
            let items = Vec::with_capacity(capacity(len, room));
            self.stack.push(Open::Array { items, left: len });
        }
    }

    /// A map of `len` entries opens, as [`Self::array`] opens an array.
    pub(crate) fn map(&mut self, len: u64, room: usize) {
        if len == 0 {
            self.place(Value::Map(Vec::new()));
        } else {
            let entries = Vec::with_capacity(capacity(len, room));
            self.stack.push(Open::Map {
                entries,
                key: None,
                left: len.saturating_mul(2),
            });
        }
    }

    /// The value, once the walk has given all of it.
    pub(crate) fn finish(self) -> Option<Value> {
        if self.stack.is_empty() {
            self.done
        } else {
            None
        }
    }

    fn place(&mut self, mut value: Value) {
        loop {
            let full = match self.stack.last_mut() {
                None => {
                    self.done = Some(value);
                    return;
                }
                Some(Open::Array { items, left }) => {
                    items.push(value);
                    *left -= 1;
                    *left == 0
                }
                Some(Open::Map { entries, key, left }) => {
                    *left -= 1;
                    match key.take() {
                        None => {
                            *key = Some(value);
                            return;
                        }
                        Some(named) => entries.push((named, value)),
                    }
                    *left == 0
                }
            };
            if !full {
                return;
            }
            value = match self.stack.pop() {
                Some(Open::Array { items, .. }) => Value::Array(items),
                Some(Open::Map { entries, .. }) => Value::Map(entries),
                None => return,
            };
        }
    }
}

fn capacity(len: u64, room: usize) -> usize {
    usize::try_from(len).map_or(room, |len| len.min(room))
}

impl Clone for Value {
    fn clone(&self) -> Self {
        let mut builder = Builder::default();
        let mut stack = vec![self];
        while let Some(value) = stack.pop() {
            match value {
                Value::Array(items) => {
                    builder.array(items.len() as u64, items.len());
                    stack.extend(items.iter().rev());
                }
                Value::Map(entries) => {
                    builder.map(entries.len() as u64, entries.len());
                    for (key, item) in entries.iter().rev() {
                        stack.push(item);
                        stack.push(key);
                    }
                }
                leaf => builder.leaf(leaf_clone(leaf)),
            }
        }
        builder.finish().unwrap_or_default()
    }
}

fn leaf_clone(value: &Value) -> Value {
    match value {
        Value::Nil | Value::Array(_) | Value::Map(_) => Value::Nil,
        Value::Boolean(value) => Value::Boolean(*value),
        Value::Integer(value) => Value::Integer(*value),
        Value::F32(value) => Value::F32(*value),
        Value::F64(value) => Value::F64(*value),
        Value::String(value) => Value::String(value.clone()),
        Value::Binary(value) => Value::Binary(value.clone()),
        Value::Ext(kind, value) => Value::Ext(*kind, value.clone()),
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        let mut stack = vec![(self, other)];
        while let Some(pair) = stack.pop() {
            match pair {
                (Value::Array(left), Value::Array(right)) => {
                    if left.len() != right.len() {
                        return false;
                    }
                    stack.extend(left.iter().zip(right));
                }
                (Value::Map(left), Value::Map(right)) => {
                    if left.len() != right.len() {
                        return false;
                    }
                    for ((left_key, left_item), (right_key, right_item)) in left.iter().zip(right) {
                        stack.push((left_key, right_key));
                        stack.push((left_item, right_item));
                    }
                }
                (left, right) => {
                    if !leaf_eq(left, right) {
                        return false;
                    }
                }
            }
        }
        true
    }
}

fn leaf_eq(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Nil, Value::Nil) => true,
        (Value::Boolean(left), Value::Boolean(right)) => left == right,
        (Value::Integer(left), Value::Integer(right)) => left == right,
        (Value::F32(left), Value::F32(right)) => left == right,
        (Value::F64(left), Value::F64(right)) => left == right,
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Binary(left), Value::Binary(right)) => left == right,
        (Value::Ext(left_kind, left), Value::Ext(right_kind, right)) => {
            left_kind == right_kind && left == right
        }
        _ => false,
    }
}

/// One step of printing a value.
enum Print<'a> {
    Value(&'a Value),
    Text(&'static str),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut stack = vec![Print::Value(self)];
        while let Some(step) = stack.pop() {
            let value = match step {
                Print::Text(text) => {
                    f.write_str(text)?;
                    continue;
                }
                Print::Value(value) => value,
            };
            match value {
                Value::Array(items) => {
                    f.write_str("[")?;
                    stack.push(Print::Text("]"));
                    for (at, item) in items.iter().enumerate().rev() {
                        stack.push(Print::Value(item));
                        if at > 0 {
                            stack.push(Print::Text(", "));
                        }
                    }
                }
                Value::Map(entries) => {
                    f.write_str("{")?;
                    stack.push(Print::Text("}"));
                    for (at, (key, item)) in entries.iter().enumerate().rev() {
                        stack.push(Print::Value(item));
                        stack.push(Print::Text(": "));
                        stack.push(Print::Value(key));
                        if at > 0 {
                            stack.push(Print::Text(", "));
                        }
                    }
                }
                leaf => leaf_fmt(leaf, f)?,
            }
        }
        Ok(())
    }
}

fn leaf_fmt(value: &Value, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match value {
        Value::Nil | Value::Array(_) | Value::Map(_) => f.write_str("nil"),
        Value::Boolean(value) => write!(f, "{value}"),
        Value::Integer(value) => write!(f, "{value}"),
        Value::F32(value) => write!(f, "{value:?}f32"),
        Value::F64(value) => write!(f, "{value:?}"),
        Value::String(value) => write!(f, "{value:?}"),
        Value::Binary(value) => write!(f, "bin({} bytes)", value.len()),
        Value::Ext(kind, value) => write!(f, "ext({kind}, {} bytes)", value.len()),
    }
}
