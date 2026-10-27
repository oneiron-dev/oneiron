//! FIX 10097: an exported MessagePack value is kept whole at any depth. The
//! export, the restore and the archive form each walk the value on a stack
//! of their own, so no depth nulls a node and none spends the call stack.
//! Each node is read for credentials as it is reached; only a nested text's
//! own decoding spends depth ([`super::TEXT_DEPTH`]).
//!
//! The archive form is the value's nodes in postorder: a leaf as its typed
//! value, a container after its items as the count of items it holds, and the
//! root last. Map pairs keep their order, duplicate keys included, and numbers
//! keep their width and bits.
use std::fmt;

use rmpv::Value as Mp;
use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ExportValue, byte_container_is_opaque_or_tainted, credential_key, exported_text, invalid,
    reference_field, safe_text,
};
use crate::batch::secret_scan::{release_joined_messagepack, release_joined_strings};
use crate::error::Result;

/// `value` as the export carries it. Every node is judged where it sits:
/// a credential field, a joined secret, an id slot and opaque bytes, at any
/// depth. `text_depth` is how deep in nested text the value was decoded.
pub(super) fn export_value_tree(value: &Mp, entity_type: u8, text_depth: usize) -> ExportValue {
    let read = Reader {
        entity_type,
        text_depth,
    };
    let mut open = match read.node(value, "", 0) {
        Node::Done(value) => return value,
        Node::Open(container) => vec![container],
    };
    loop {
        let Some(top) = open.last_mut() else {
            // The root returns as it closes; nothing else empties the stack.
            return ExportValue::Nil;
        };
        match top.next() {
            Next::Item(item, key) => match read.node(item, key, top.depth + 1) {
                Node::Done(value) => top.out.push(value),
                Node::Open(container) => open.push(container),
            },
            Next::Nil => top.out.push(ExportValue::Nil),
            Next::Closed => {
                let Some(closed) = open.pop() else {
                    return ExportValue::Nil;
                };
                let value = closed.close();
                match open.last_mut() {
                    Some(parent) => parent.out.push(value),
                    None => return value,
                }
            }
        }
    }
}

/// What every node of one exported value is read with.
struct Reader {
    entity_type: u8,
    text_depth: usize,
}

/// A node read alone, or a container opened for its items.
enum Node<'v> {
    Done(ExportValue),
    Open(Open<'v>),
}

/// A container whose items are being exported.
struct Open<'v> {
    items: Items<'v>,
    /// The container's depth from the value's root: an id slot is judged by
    /// where it sits.
    depth: usize,
    /// The items exported so far; a map's keys and values in turn.
    out: Vec<ExportValue>,
}

enum Items<'v> {
    Array(&'v [Mp]),
    Map(&'v [(Mp, Mp)]),
}

/// What an open container reads next.
enum Next<'v> {
    /// An item, under the field name it holds.
    Item(&'v Mp, &'v str),
    /// A map value whose key was nulled: it goes as nil, unread.
    Nil,
    Closed,
}

impl Reader {
    fn node<'v>(&self, value: &'v Mp, key: &str, depth: usize) -> Node<'v> {
        if credential_key(key) {
            return Node::Done(ExportValue::Nil);
        }
        Node::Done(match value {
            Mp::Nil => ExportValue::Nil,
            Mp::Boolean(value) => ExportValue::Boolean(*value),
            Mp::Integer(value) => ExportValue::Integer(value.to_string()),
            Mp::F32(value) => ExportValue::F32(value.to_bits()),
            Mp::F64(value) => ExportValue::F64(value.to_bits()),
            Mp::String(value) => match value.as_str() {
                Some(value) if safe_text(value, self.text_depth) => {
                    ExportValue::String(value.to_owned())
                }
                _ => ExportValue::Nil,
            },
            Mp::Binary(bytes) if reference_field(key, bytes, self.entity_type, depth) => {
                ExportValue::EntityReference(bytes.clone())
            }
            Mp::Binary(bytes) => {
                // A binary map is not text just because its credential's value is
                // printable. Opaque encodings are intentionally nulled as a whole.
                match std::str::from_utf8(bytes) {
                    Ok(text)
                        if safe_text(text, self.text_depth)
                            && !text.chars().any(char::is_control) =>
                    {
                        ExportValue::BinaryText(text.to_owned())
                    }
                    _ => ExportValue::Nil,
                }
            }
            Mp::Array(values) => {
                // MessagePack uint8 arrays are another common byte-container. Scan
                // them before JSON encoding, rather than scanning decimal digits.
                let bytes: Option<Vec<u8>> = values
                    .iter()
                    .map(|value| value.as_u64().and_then(|v| u8::try_from(v).ok()))
                    .collect();
                if bytes.as_deref().is_some_and(|bytes| {
                    byte_container_is_opaque_or_tainted(bytes, self.text_depth)
                }) {
                    return Node::Done(ExportValue::Nil);
                }
                // A phrase one word per item, a key one line per item, whether
                // each item is a string or binary.
                if release_joined_messagepack(values) {
                    return Node::Done(ExportValue::Nil);
                }
                return Node::Open(Open {
                    items: Items::Array(values),
                    depth,
                    out: Vec::with_capacity(values.len()),
                });
            }
            Mp::Map(entries) => {
                return Node::Open(Open {
                    items: Items::Map(entries),
                    depth,
                    out: Vec::with_capacity(entries.len().saturating_mul(2)),
                });
            }
            Mp::Ext(_, _) => ExportValue::Nil,
        })
    }
}

impl<'v> Open<'v> {
    fn next(&self) -> Next<'v> {
        let at = self.out.len();
        match self.items {
            Items::Array(values) => values
                .get(at)
                .map_or(Next::Closed, |value| Next::Item(value, "")),
            Items::Map(entries) => match entries.get(at / 2) {
                None => Next::Closed,
                Some((key, _)) if at % 2 == 0 => Next::Item(key, ""),
                Some(_) if matches!(self.out.last(), Some(ExportValue::Nil)) => Next::Nil,
                Some((key, value)) => Next::Item(value, field_name(key)),
            },
        }
    }

    fn close(self) -> ExportValue {
        match self.items {
            Items::Array(_) => {
                // Read again once items are nulled: the text left is what a second
                // pass reads joined, so the array is its own fixed point.
                let joined = {
                    let kept: Vec<_> = self.out.iter().filter_map(exported_text).collect();
                    release_joined_strings(&kept)
                };
                if joined {
                    ExportValue::Nil
                } else {
                    ExportValue::Array(self.out)
                }
            }
            Items::Map(_) => {
                let mut out = self.out.into_iter();
                let mut entries = Vec::with_capacity(out.len() / 2);
                while let (Some(key), Some(value)) = (out.next(), out.next()) {
                    entries.push((key, value));
                }
                ExportValue::Map(entries)
            }
        }
    }
}

/// The field name a map key gives its value: its text, or its binary's.
fn field_name(key: &Mp) -> &str {
    key.as_str()
        .or_else(|| match key {
            Mp::Binary(bytes) => std::str::from_utf8(bytes).ok(),
            _ => None,
        })
        .unwrap_or("")
}

/// The MessagePack value an exported value restores, at any depth.
pub(super) fn restore_value_tree(value: &ExportValue) -> Result<Mp> {
    let mut built: Vec<Mp> = Vec::new();
    for node in postorder(value) {
        let restored = match node {
            Postorder::Leaf(leaf) => leaf_msgpack(leaf)?,
            Postorder::Array(len) => Mp::Array(
                take_items(&mut built, len).ok_or_else(|| invalid("array node lost its items"))?,
            ),
            Postorder::Map(len) => Mp::Map(pairs(
                len.checked_mul(2)
                    .and_then(|items| take_items(&mut built, items))
                    .ok_or_else(|| invalid("map node lost its items"))?,
            )),
        };
        built.push(restored);
    }
    match (built.pop(), built.is_empty()) {
        (Some(value), true) => Ok(value),
        _ => Err(invalid("value nodes do not form one tree")),
    }
}

fn leaf_msgpack(value: &ExportValue) -> Result<Mp> {
    Ok(match value {
        ExportValue::Nil => Mp::Nil,
        ExportValue::Boolean(value) => Mp::Boolean(*value),
        ExportValue::Integer(value) => {
            if value.starts_with('-') {
                Mp::from(
                    value
                        .parse::<i64>()
                        .map_err(|_| invalid("invalid signed integer"))?,
                )
            } else {
                Mp::from(
                    value
                        .parse::<u64>()
                        .map_err(|_| invalid("invalid unsigned integer"))?,
                )
            }
        }
        ExportValue::F32(bits) => Mp::F32(f32::from_bits(*bits)),
        ExportValue::F64(bits) => Mp::F64(f64::from_bits(*bits)),
        ExportValue::String(value) => Mp::from(value.as_str()),
        ExportValue::EntityReference(value) => Mp::Binary(value.clone()),
        ExportValue::BinaryText(value) => Mp::Binary(value.as_bytes().to_vec()),
        ExportValue::Array(_) | ExportValue::Map(_) => {
            return Err(invalid("container node read as a leaf"));
        }
    })
}

/// The last `len` values built, in order; `None` when fewer were built.
fn take_items<T>(built: &mut Vec<T>, len: usize) -> Option<Vec<T>> {
    let at = built.len().checked_sub(len)?;
    Some(built.split_off(at))
}

/// A map's items, key and value in turn, as its ordered pairs.
fn pairs<T>(items: Vec<T>) -> Vec<(T, T)> {
    let mut items = items.into_iter();
    let mut entries = Vec::with_capacity(items.len() / 2);
    while let (Some(key), Some(value)) = (items.next(), items.next()) {
        entries.push((key, value));
    }
    entries
}

/// One node of a value in postorder.
enum Postorder<'v> {
    Leaf(&'v ExportValue),
    /// An array, after its items.
    Array(usize),
    /// A map, after its keys and values in turn.
    Map(usize),
}

fn postorder(value: &ExportValue) -> Vec<Postorder<'_>> {
    let mut nodes = Vec::new();
    // Each value still to write, and whether its items are written.
    let mut pending = vec![(value, false)];
    while let Some((value, items_written)) = pending.pop() {
        match value {
            ExportValue::Array(items) if items_written => nodes.push(Postorder::Array(items.len())),
            ExportValue::Map(entries) if items_written => {
                nodes.push(Postorder::Map(entries.len()));
            }
            ExportValue::Array(items) => {
                pending.push((value, true));
                pending.extend(items.iter().rev().map(|item| (item, false)));
            }
            ExportValue::Map(entries) => {
                pending.push((value, true));
                for (key, item) in entries.iter().rev() {
                    pending.push((item, false));
                    pending.push((key, false));
                }
            }
            leaf => nodes.push(Postorder::Leaf(leaf)),
        }
    }
    nodes
}

/// One node as the archive writes it.
#[derive(Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
enum NodeOut<'v> {
    Boolean(bool),
    Integer(&'v str),
    F32(u32),
    F64(u64),
    String(&'v str),
    EntityReference(&'v [u8]),
    BinaryText(&'v str),
    Array(usize),
    Map(usize),
    #[serde(untagged)]
    Nil,
}

impl<'v> NodeOut<'v> {
    fn of(node: &Postorder<'v>) -> Self {
        match *node {
            Postorder::Array(len) => Self::Array(len),
            Postorder::Map(len) => Self::Map(len),
            Postorder::Leaf(leaf) => match leaf {
                ExportValue::Boolean(value) => Self::Boolean(*value),
                ExportValue::Integer(value) => Self::Integer(value),
                ExportValue::F32(bits) => Self::F32(*bits),
                ExportValue::F64(bits) => Self::F64(*bits),
                ExportValue::String(value) => Self::String(value),
                ExportValue::EntityReference(bytes) => Self::EntityReference(bytes),
                ExportValue::BinaryText(value) => Self::BinaryText(value),
                // A container is never a leaf of the postorder.
                ExportValue::Nil | ExportValue::Array(_) | ExportValue::Map(_) => Self::Nil,
            },
        }
    }
}

/// One node as the archive reads it.
#[derive(Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum NodeIn {
    Boolean(bool),
    Integer(String),
    F32(u32),
    F64(u64),
    String(String),
    EntityReference(Vec<u8>),
    BinaryText(String),
    Array(usize),
    Map(usize),
    #[serde(untagged)]
    Nil,
}

impl Serialize for ExportValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let nodes = postorder(self);
        let mut seq = serializer.serialize_seq(Some(nodes.len()))?;
        for node in &nodes {
            seq.serialize_element(&NodeOut::of(node))?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ExportValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_seq(NodesVisitor)
    }
}

/// Builds a value from its nodes: each container takes the items written
/// before it. A count past the items there, a tree nested past what the
/// MessagePack decoder reads (no stored body is), or nodes left over beside
/// the root, are no value.
struct NodesVisitor;

impl<'de> Visitor<'de> for NodesVisitor {
    type Value = ExportValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an exported MessagePack value's nodes in postorder")
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<ExportValue, A::Error> {
        // Each value built so far, with how many containers nest in it.
        let mut built: Vec<(ExportValue, usize)> = Vec::new();
        while let Some(node) = seq.next_element::<NodeIn>()? {
            let value = match node {
                NodeIn::Array(len) => {
                    let items = take_items(&mut built, len).ok_or_else(|| {
                        de::Error::custom("an array node names more items than precede it")
                    })?;
                    let nesting = nesting(&items).map_err(de::Error::custom)?;
                    (
                        ExportValue::Array(items.into_iter().map(|(item, _)| item).collect()),
                        nesting,
                    )
                }
                NodeIn::Map(len) => {
                    let items = len
                        .checked_mul(2)
                        .and_then(|items| take_items(&mut built, items))
                        .ok_or_else(|| {
                            de::Error::custom("a map node names more items than precede it")
                        })?;
                    let nesting = nesting(&items).map_err(de::Error::custom)?;
                    let entries = pairs(items.into_iter().map(|(item, _)| item).collect());
                    (ExportValue::Map(entries), nesting)
                }
                NodeIn::Nil => (ExportValue::Nil, 0),
                NodeIn::Boolean(value) => (ExportValue::Boolean(value), 0),
                NodeIn::Integer(value) => (ExportValue::Integer(value), 0),
                NodeIn::F32(bits) => (ExportValue::F32(bits), 0),
                NodeIn::F64(bits) => (ExportValue::F64(bits), 0),
                NodeIn::String(value) => (ExportValue::String(value), 0),
                NodeIn::EntityReference(bytes) => (ExportValue::EntityReference(bytes), 0),
                NodeIn::BinaryText(value) => (ExportValue::BinaryText(value), 0),
            };
            built.push(value);
        }
        match (built.pop(), built.is_empty()) {
            (Some((value, _)), true) => Ok(value),
            _ => Err(de::Error::custom("export value nodes do not form one tree")),
        }
    }
}

/// How many containers nest in a container holding `items`.
fn nesting(items: &[(ExportValue, usize)]) -> std::result::Result<usize, &'static str> {
    let nesting = items.iter().map(|(_, nesting)| *nesting).max().unwrap_or(0) + 1;
    if nesting > rmpv::decode::MAX_DEPTH {
        return Err("export value nests past what MessagePack decodes");
    }
    Ok(nesting)
}
