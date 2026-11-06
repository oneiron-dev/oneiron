//! Borrowed root-map facts for generic EntityDoc recovery validation.

use super::{id, invalid};
use crate::error::Result;
use rmp::Marker;
use rmp::decode::{RmpRead, read_marker};
use std::io::Cursor;
use std::ops::Range;

#[derive(Default)]
pub(super) struct EntityPointer {
    started: bool,
    complete: bool,
    valid: bool,
    at: usize,
    stack: Vec<Frame>,
    reference_key: bool,
    references: u8,
    reference: Option<String>,
    text: Option<PendingText>,
    pub(super) other_fields: bool,
    pub(super) metadata: bool,
    pub(super) body_field: bool,
}

struct Frame {
    remaining: u64,
    depth: usize,
}

struct Token {
    end: usize,
    text: Option<Range<usize>>,
    children: Option<Frame>,
    map: bool,
}

struct PendingText {
    range: Range<usize>,
    next: usize,
    value: Option<String>,
    key: bool,
    body_field: bool,
}

impl PendingText {
    fn new(range: Range<usize>, key: bool, field: Option<&str>) -> Self {
        Self {
            next: range.start,
            body_field: key && field.is_some_and(|field| field.len() == range.len()),
            range,
            value: Some(String::new()),
            key,
        }
    }

    /// Decode one Unicode scalar; invalid UTF-8 stays a non-string Value.
    fn advance(&mut self, body: &[u8], field: Option<&str>) -> bool {
        if self.next == self.range.end {
            return true;
        }
        let width = match body[self.next] {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 0,
        };
        let end = self.next + width.min(self.range.end - self.next);
        let scalar = (width != 0 && end - self.next == width)
            .then(|| std::str::from_utf8(&body[self.next..end]).ok())
            .flatten();
        let Some(scalar) = scalar else {
            self.value = None;
            self.body_field = false;
            self.next = self.range.end;
            return true;
        };
        if self.body_field {
            let offset = self.next - self.range.start;
            self.body_field = field.and_then(|field| field.as_bytes().get(offset..offset + width))
                == Some(scalar.as_bytes());
        }
        self.value
            .as_mut()
            .expect("unfinished valid text has a string")
            .push_str(scalar);
        self.next = end;
        self.next == self.range.end
    }
}

impl EntityPointer {
    /// Visit one marker, root Unicode scalar, or completed container.
    pub(super) fn advance(&mut self, body: &[u8], field: Option<&str>) -> bool {
        if self.complete {
            return true;
        }
        if let Some(text) = self.text.as_mut() {
            if text.advance(body, field) {
                let text = self.text.take().expect("the completed scalar is pending");
                if text.key {
                    let key = text.value.as_deref();
                    self.reference_key = key == Some("entity_doc_ref");
                    if !self.reference_key {
                        self.other_fields = true;
                        self.metadata |= key.is_some_and(crate::ports::is_metadata_field);
                        self.body_field |= text.body_field;
                    }
                } else {
                    self.reference = text.value;
                }
            }
            return false;
        }
        if !self.started {
            self.started = true;
            let Some(token) = token(body, 0, rmpv::decode::MAX_DEPTH) else {
                self.complete = true;
                return true;
            };
            if !token.map {
                self.complete = true;
                return true;
            }
            self.at = token.end;
            self.stack
                .push(token.children.expect("a map has a child frame"));
            self.valid = true;
            return false;
        }
        let frame = self.stack.last_mut().expect("unfinished map has a frame");
        if frame.remaining == 0 {
            self.stack.pop();
            self.complete = self.stack.is_empty();
            return self.complete;
        }
        let Some(token) = token(body, self.at, frame.depth) else {
            self.valid = false;
            self.complete = true;
            return true;
        };
        frame.remaining -= 1;
        let remaining = frame.remaining;
        if self.stack.len() == 1 {
            if remaining % 2 == 1 {
                self.reference_key = false;
                if let Some(range) = token.text {
                    self.text = Some(PendingText::new(range, true, field));
                } else {
                    self.other_fields = true;
                }
            } else if self.reference_key {
                self.references = self.references.saturating_add(1);
                self.reference = None;
                if let Some(range) = token.text {
                    self.text = Some(PendingText::new(range, false, None));
                }
            }
        }
        self.at = token.end;
        if let Some(children) = token.children {
            self.stack.push(children);
        }
        false
    }

    /// A document pointer in a raw entity row must have its value in the artifact.
    /// Do not trust the writer: decoded payloads enter this gate too.
    pub(super) fn pointer(&self, body: &[u8]) -> Result<Option<&str>> {
        // As with read_value, malformed or non-map input has no pointer, even if
        // an earlier complete field happened to name one.
        if !self.valid || self.references == 0 {
            return Ok(None);
        }
        if self.references != 1 || self.at != body.len() {
            return Err(invalid("entity document pointer encoding"));
        }
        let value = self
            .reference
            .as_deref()
            .ok_or(invalid("entity document pointer type"))?;
        id(crate::recovery::canonical::parse_id(value)?)?;
        Ok(Some(value))
    }
}

/// The pinned rmpv owned decoder spends a depth step in read_value_inner and
/// another for containers/binary, or two more for strings/extensions. Keep those
/// same limits, including empty values; invalid UTF-8 strings remain values.
fn token(body: &[u8], at: usize, depth: usize) -> Option<Token> {
    depth.checked_sub(1)?;
    let mut reader = Cursor::new(body.get(at..)?);
    let marker = read_marker(&mut reader).ok()?;
    let mut text = false;
    let mut map = false;
    let mut children = None;
    let mut depth_cost = 1;
    let bytes = match marker {
        Marker::Null
        | Marker::True
        | Marker::False
        | Marker::FixPos(_)
        | Marker::FixNeg(_)
        | Marker::Reserved => 0,
        Marker::U8 | Marker::I8 => 1,
        Marker::U16 | Marker::I16 => 2,
        Marker::U32 | Marker::I32 | Marker::F32 => 4,
        Marker::U64 | Marker::I64 | Marker::F64 => 8,
        Marker::FixStr(len) => {
            text = true;
            usize::from(len)
        }
        Marker::Str8 => {
            text = true;
            usize::from(reader.read_data_u8().ok()?)
        }
        Marker::Str16 => {
            text = true;
            usize::from(reader.read_data_u16().ok()?)
        }
        Marker::Str32 => {
            text = true;
            usize::try_from(reader.read_data_u32().ok()?).ok()?
        }
        Marker::Bin8 => {
            depth_cost = 2;
            usize::from(reader.read_data_u8().ok()?)
        }
        Marker::Bin16 => {
            depth_cost = 2;
            usize::from(reader.read_data_u16().ok()?)
        }
        Marker::Bin32 => {
            depth_cost = 2;
            usize::try_from(reader.read_data_u32().ok()?).ok()?
        }
        Marker::FixArray(len) => {
            children = Some(Frame {
                remaining: u64::from(len),
                depth: depth.checked_sub(2)?,
            });
            0
        }
        Marker::Array16 => {
            children = Some(Frame {
                remaining: u64::from(reader.read_data_u16().ok()?),
                depth: depth.checked_sub(2)?,
            });
            0
        }
        Marker::Array32 => {
            children = Some(Frame {
                remaining: u64::from(reader.read_data_u32().ok()?),
                depth: depth.checked_sub(2)?,
            });
            0
        }
        Marker::FixMap(len) => {
            map = true;
            children = Some(Frame {
                remaining: u64::from(len) * 2,
                depth: depth.checked_sub(2)?,
            });
            0
        }
        Marker::Map16 => {
            map = true;
            children = Some(Frame {
                remaining: u64::from(reader.read_data_u16().ok()?) * 2,
                depth: depth.checked_sub(2)?,
            });
            0
        }
        Marker::Map32 => {
            map = true;
            children = Some(Frame {
                remaining: u64::from(reader.read_data_u32().ok()?) * 2,
                depth: depth.checked_sub(2)?,
            });
            0
        }
        Marker::FixExt1 => {
            depth_cost = 3;
            2
        }
        Marker::FixExt2 => {
            depth_cost = 3;
            3
        }
        Marker::FixExt4 => {
            depth_cost = 3;
            5
        }
        Marker::FixExt8 => {
            depth_cost = 3;
            9
        }
        Marker::FixExt16 => {
            depth_cost = 3;
            17
        }
        Marker::Ext8 => {
            depth_cost = 3;
            usize::from(reader.read_data_u8().ok()?).checked_add(1)?
        }
        Marker::Ext16 => {
            depth_cost = 3;
            usize::from(reader.read_data_u16().ok()?).checked_add(1)?
        }
        Marker::Ext32 => {
            depth_cost = 3;
            usize::try_from(reader.read_data_u32().ok()?)
                .ok()?
                .checked_add(1)?
        }
    };
    if text {
        depth_cost = 3;
    }
    depth.checked_sub(depth_cost)?;
    let start = at.checked_add(usize::try_from(reader.position()).ok()?)?;
    let end = start.checked_add(bytes)?;
    if end > body.len() {
        return None;
    }
    Some(Token {
        end,
        text: text.then_some(start..end),
        children,
        map,
    })
}
