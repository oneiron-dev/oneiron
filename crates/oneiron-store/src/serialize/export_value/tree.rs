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

use oneiron_base::error::Result;

pub enum Items<'v> {
    Array(&'v [Mp]),
    Map(&'v [(Mp, Mp)]),
}

/// What an open container reads next.
pub enum Next<'v> {
    /// An item, under the field name it holds.
    Item(&'v Mp, &'v str),
    /// A map value whose key was nulled: it goes as nil, unread.
    Nil,
    Closed,
}

/// The field name a map key gives its value: its text, or its binary's.
pub fn field_name(key: &Mp) -> &str {
    key.as_str()
        .or_else(|| match key {
            Mp::Binary(bytes) => std::str::from_utf8(bytes).ok(),
            _ => None,
        })
        .unwrap_or("")
}

/// The last `len` values built, in order; `None` when fewer were built.
pub fn take_items<T>(built: &mut Vec<T>, len: usize) -> Option<Vec<T>> {
    let at = built.len().checked_sub(len)?;
    Some(built.split_off(at))
}

/// A map's items, key and value in turn, as its ordered pairs.
pub fn pairs<T>(items: Vec<T>) -> Vec<(T, T)> {
    let mut items = items.into_iter();
    let mut entries = Vec::with_capacity(items.len() / 2);
    while let (Some(key), Some(value)) = (items.next(), items.next()) {
        entries.push((key, value));
    }
    entries
}

/// One node as the archive reads it.
#[derive(Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum NodeIn {
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
