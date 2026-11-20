//! A Redact over a view held as JSON text, never read into a value
//! (SKILL-ANSWER-DEEP-JSON-STACK-SAFE): the text is read into a flat arena
//! of nodes, each path is applied as [`super::hide`] applies it to a value,
//! and the arena is written back as text. Each step keeps its own stack, so
//! no recursion follows the view's nesting, and the arena drops as flat
//! vectors. An object keeps its members as serde_json's `preserve_order` map
//! does: a repeated key keeps its first place and its last value, and a
//! removal moves the last member into the removed one's place.

use std::collections::HashMap;
use std::ops::Range;

use crate::{Error, Result};

use super::{index, segments};

/// A node's place in the arena.
type NodeId = usize;

/// The arena's own `null`, standing for an array element a path masked.
const MASKED: NodeId = 0;

/// The JSON literals, as the text spells them.
const LITERALS: [&[u8]; 3] = [b"true", b"false", b"null"];

/// Why a text view does not read: it came in as a checked JSON value, so a
/// fault here is this reader's own.
const UNREADABLE: &str = "a redacted text view does not read as JSON";

enum Node {
    /// A string, number, `true`, `false` or `null`, as the text spells it.
    Scalar(Range<usize>),
    /// An element a path masked.
    Masked,
    Array(Vec<NodeId>),
    Object(Members),
}

/// An object's members, in their order.
#[derive(Default)]
struct Members {
    entries: Vec<(String, NodeId)>,
    places: HashMap<String, usize>,
}

impl Members {
    /// A repeated key keeps its first place and takes the later value.
    fn insert(&mut self, key: String, node: NodeId) {
        if let Some(&at) = self.places.get(&key) {
            self.entries[at].1 = node;
            return;
        }
        self.places.insert(key.clone(), self.entries.len());
        self.entries.push((key, node));
    }

    fn get(&self, key: &str) -> Option<NodeId> {
        self.places.get(key).map(|&at| self.entries[at].1)
    }

    /// Removes `key`, moving the last member into its place. Whether it was
    /// there.
    fn swap_remove(&mut self, key: &str) -> bool {
        let Some(at) = self.places.remove(key) else {
            return false;
        };
        self.entries.swap_remove(at);
        if let Some((moved, _)) = self.entries.get(at) {
            self.places.insert(moved.clone(), at);
        }
        true
    }

    /// Removes every member. Whether there was one.
    fn clear(&mut self) -> bool {
        let had = !self.entries.is_empty();
        self.entries.clear();
        self.places.clear();
        had
    }
}

/// `text` with every one of `paths` hidden, in order, as [`super::hide`]
/// hides each in a value: `None` when they hid nothing, so the view is as
/// it came.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when `text` does not read as JSON.
pub(in crate::runtime_hooks::verb) fn hide_in_text(
    text: &str,
    paths: &[String],
) -> Result<Option<String>> {
    let mut arena = Arena::read(text)?;
    let mut hid = false;
    for path in paths {
        hid |= arena.hide(path);
    }
    Ok(hid.then(|| arena.write()))
}

struct Arena<'t> {
    text: &'t str,
    nodes: Vec<Node>,
    root: NodeId,
}

/// A container still open while the text is read, with the key its next
/// member takes when it is an object.
struct Open {
    node: NodeId,
    key: Option<String>,
}

impl<'t> Arena<'t> {
    fn read(text: &'t str) -> Result<Self> {
        let fault = || Error::InvariantViolation(UNREADABLE);
        let bytes = text.as_bytes();
        let mut nodes = vec![Node::Masked];
        let mut open: Vec<Open> = Vec::new();
        let mut at = 0;
        loop {
            at = space(bytes, at);
            let first = *bytes.get(at).ok_or_else(fault)?;
            let mut done = match first {
                b'{' | b'[' => {
                    let node = nodes.len();
                    let (container, end) = if first == b'{' {
                        (Node::Object(Members::default()), b'}')
                    } else {
                        (Node::Array(Vec::new()), b']')
                    };
                    nodes.push(container);
                    at = space(bytes, at + 1);
                    if bytes.get(at) == Some(&end) {
                        at += 1;
                        Some(node)
                    } else {
                        let key = if first == b'{' {
                            let (key, next) = key_at(text, at)?;
                            at = next;
                            Some(key)
                        } else {
                            None
                        };
                        open.push(Open { node, key });
                        None
                    }
                }
                b'"' => {
                    let end = string_end(bytes, at)?;
                    nodes.push(Node::Scalar(at..end));
                    at = end;
                    Some(nodes.len() - 1)
                }
                b'-' | b'0'..=b'9' => {
                    let end = bytes[at..]
                        .iter()
                        .position(|byte| {
                            !matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                        })
                        .map_or(bytes.len(), |length| at + length);
                    nodes.push(Node::Scalar(at..end));
                    at = end;
                    Some(nodes.len() - 1)
                }
                _ => {
                    let word = LITERALS
                        .into_iter()
                        .find(|word| bytes[at..].starts_with(word))
                        .ok_or_else(fault)?;
                    nodes.push(Node::Scalar(at..at + word.len()));
                    at += word.len();
                    Some(nodes.len() - 1)
                }
            };
            // A finished value joins its container; a container its end
            // closes is finished in turn.
            while let Some(node) = done.take() {
                let Some(parent) = open.last_mut() else {
                    if space(bytes, at) != bytes.len() {
                        return Err(fault());
                    }
                    return Ok(Self {
                        text,
                        nodes,
                        root: node,
                    });
                };
                let end = match &mut nodes[parent.node] {
                    Node::Array(items) => {
                        items.push(node);
                        b']'
                    }
                    Node::Object(members) => {
                        members.insert(parent.key.take().ok_or_else(fault)?, node);
                        b'}'
                    }
                    Node::Scalar(_) | Node::Masked => return Err(fault()),
                };
                at = space(bytes, at);
                match bytes.get(at) {
                    Some(b',') => {
                        at += 1;
                        if end == b'}' {
                            let (key, next) = key_at(text, space(bytes, at))?;
                            parent.key = Some(key);
                            at = next;
                        }
                    }
                    Some(&close) if close == end => {
                        at += 1;
                        done = open.pop().map(|closed| closed.node);
                    }
                    _ => return Err(fault()),
                }
            }
        }
    }

    /// Hides `path`, as [`super::hide`] does in a value. Whether it hid
    /// anything: a member removed, a non-null element masked, or a non-null
    /// view masked whole.
    fn hide(&mut self, path: &str) -> bool {
        let Some(segments) = segments(path) else {
            let hid = !self.is_null(self.root);
            self.root = MASKED;
            return hid;
        };
        let mut hid = false;
        let mut walk = vec![(self.root, 0)];
        let mut masks = Vec::new();
        while let Some((node, depth)) = walk.pop() {
            let segment = segments[depth].as_str();
            let every = segment == "*";
            let last = depth + 1 == segments.len();
            match &mut self.nodes[node] {
                Node::Object(members) if last => {
                    hid |= if every {
                        members.clear()
                    } else {
                        members.swap_remove(segment)
                    };
                }
                Node::Object(members) if every => {
                    walk.extend(members.entries.iter().map(|&(_, child)| (child, depth + 1)))
                }
                Node::Object(members) => {
                    if let Some(child) = members.get(segment) {
                        walk.push((child, depth + 1));
                    }
                }
                Node::Array(items) => {
                    let places = if every {
                        0..items.len()
                    } else {
                        match index(segment).filter(|&at| at < items.len()) {
                            Some(at) => at..at + 1,
                            None => 0..0,
                        }
                    };
                    if last {
                        masks.extend(places.map(|at| (node, at)));
                    } else {
                        walk.extend(places.map(|at| (items[at], depth + 1)));
                    }
                }
                Node::Scalar(_) | Node::Masked => {}
            }
            for (array, at) in masks.drain(..) {
                hid |= self.mask(array, at);
            }
        }
        hid
    }

    /// Masks element `at` of array `node`. Whether it was not null.
    fn mask(&mut self, node: NodeId, at: usize) -> bool {
        let Node::Array(items) = &self.nodes[node] else {
            return false;
        };
        if self.is_null(items[at]) {
            return false;
        }
        if let Node::Array(items) = &mut self.nodes[node] {
            items[at] = MASKED;
        }
        true
    }

    fn is_null(&self, node: NodeId) -> bool {
        match &self.nodes[node] {
            Node::Masked => true,
            Node::Scalar(spelled) => &self.text[spelled.clone()] == "null",
            Node::Array(_) | Node::Object(_) => false,
        }
    }

    /// The arena as compact JSON text: scalars as the text spelled them,
    /// keys encoded again.
    fn write(&self) -> String {
        let mut out = String::with_capacity(self.text.len());
        let mut open: Vec<(NodeId, usize)> = Vec::new();
        let mut next = Some(self.root);
        loop {
            if let Some(node) = next.take() {
                match &self.nodes[node] {
                    Node::Scalar(spelled) => out.push_str(&self.text[spelled.clone()]),
                    Node::Masked => out.push_str("null"),
                    Node::Array(_) => {
                        out.push('[');
                        open.push((node, 0));
                    }
                    Node::Object(_) => {
                        out.push('{');
                        open.push((node, 0));
                    }
                }
            }
            let Some((node, written)) = open.last_mut() else {
                return out;
            };
            let member = match &self.nodes[*node] {
                Node::Array(items) => items.get(*written).map(|&child| (None, child)),
                Node::Object(members) => members
                    .entries
                    .get(*written)
                    .map(|(key, child)| (Some(key), *child)),
                Node::Scalar(_) | Node::Masked => None,
            };
            match member {
                Some((key, child)) => {
                    if *written > 0 {
                        out.push(',');
                    }
                    if let Some(key) = key {
                        push_key(&mut out, key);
                        out.push(':');
                    }
                    *written += 1;
                    next = Some(child);
                }
                None => {
                    out.push(match &self.nodes[*node] {
                        Node::Object(_) => '}',
                        _ => ']',
                    });
                    open.pop();
                }
            }
        }
    }
}

/// The first byte at or after `at` that is no JSON whitespace.
fn space(bytes: &[u8], at: usize) -> usize {
    bytes[at.min(bytes.len())..]
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        .map_or(bytes.len(), |skipped| at + skipped)
}

/// The end of the string whose opening quote is at `at`, past its closing
/// quote.
fn string_end(bytes: &[u8], at: usize) -> Result<usize> {
    let mut place = at + 1;
    loop {
        match bytes.get(place) {
            Some(b'\\') => place += 2,
            Some(b'"') => return Ok(place + 1),
            Some(_) => place += 1,
            None => return Err(Error::InvariantViolation(UNREADABLE)),
        }
    }
}

/// The key whose opening quote is at `at`, decoded, and the place past the
/// `:` after it.
fn key_at(text: &str, at: usize) -> Result<(String, usize)> {
    let fault = || Error::InvariantViolation(UNREADABLE);
    let bytes = text.as_bytes();
    if bytes.get(at) != Some(&b'"') {
        return Err(fault());
    }
    let end = string_end(bytes, at)?;
    let key = serde_json::from_str::<String>(text.get(at..end).ok_or_else(fault)?)
        .map_err(|_| fault())?;
    let colon = space(bytes, end);
    if bytes.get(colon) != Some(&b':') {
        return Err(fault());
    }
    Ok((key, colon + 1))
}

fn push_key(out: &mut String, key: &str) {
    // A `String` always encodes.
    if let Ok(encoded) = serde_json::to_string(key) {
        out.push_str(&encoded);
    }
}
