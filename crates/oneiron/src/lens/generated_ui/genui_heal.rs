//! Healing a generated-UI segment cut mid-stream (FIX 7970; ARCH-0048 G4
//! healing-tolerant parse): a cut string the atom kit's own schema types as
//! display text is closed where it was cut, and every other cut construct (an
//! id, a ref, a pointer path, a key, a number, a literal, or anything in an
//! app component's props, whose meaning only its app knows) is dropped back
//! to the last complete member, so the healed text never holds a half-formed
//! reference. Open containers are then closed. The result is still decoded
//! and validated as a typed segment.

use crate::lens::atom::GENERATED_LENS_ATOM_KINDS;

/// A node's whole display text, outside any atom's props.
const NODE_TEXT_KEY: &str = "fallbackText";

/// The members of built-in atoms' props that the kit types as display text
/// (`LensText`): sheet and section titles, a thread entry's body, a voice
/// line's text, a pack line's summary, an answer sheet's answer, media alt
/// text.
const KIT_TEXT_KEYS: &[&str] = &["title", "body", "text", "summary", "answer", "alt"];

/// The atom kind an app component carries; its props are opaque here.
const COMPONENT_KIND: &str = "component";

struct Frame {
    array: bool,
    key: Option<String>,
    expect_key: bool,
    /// The `kind` this object named, when it named one before its props.
    kind: Option<String>,
    /// Inside some atom's `props`.
    in_props: bool,
    /// Inside the props of a built-in atom whose kind came first.
    kit_props: bool,
}

impl Frame {
    /// A container opened as the current member of `parent`.
    fn open(array: bool, parent: Option<&Self>) -> Self {
        let (in_props, kit_props) = parent.map_or((false, false), |parent| {
            let props = !parent.array && parent.key.as_deref() == Some("props");
            let kit = props
                && parent.kind.as_deref().is_some_and(|kind| {
                    kind != COMPONENT_KIND && GENERATED_LENS_ATOM_KINDS.contains(&kind)
                });
            (
                parent.in_props || props,
                if props { kit } else { parent.kit_props },
            )
        });
        Self {
            array,
            key: None,
            expect_key: !array,
            kind: None,
            in_props,
            kit_props,
        }
    }

    /// Whether a string value of the current member is display text the
    /// kit's schema lets a reader show cut short.
    fn holds_display_text(&self) -> bool {
        !self.array
            && self.key.as_deref().is_some_and(|key| {
                (key == NODE_TEXT_KEY && !self.in_props)
                    || (self.kit_props && KIT_TEXT_KEYS.contains(&key))
            })
    }
}

/// `text`, one JSON value cut short, closed into JSON as described above;
/// the text itself when it is already complete, `None` when nothing remains.
pub(super) fn heal_cut_json(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut stack: Vec<Frame> = Vec::new();
    // The last point the text could be closed at, with the containers then open.
    let mut safe: Option<(usize, Vec<bool>)> = None;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' | b'\n' | b'\r' => index += 1,
            open_byte @ (b'{' | b'[') => {
                let frame = Frame::open(open_byte == b'[', stack.last());
                stack.push(frame);
                index += 1;
                safe = Some((index, open_kinds(&stack)));
            }
            b'}' | b']' => {
                stack.pop();
                index += 1;
                if stack.is_empty() {
                    return Some(text[..index].to_owned());
                }
                safe = Some((index, open_kinds(&stack)));
            }
            b',' => {
                if let Some(frame) = stack.last_mut()
                    && !frame.array
                {
                    frame.expect_key = true;
                    frame.key = None;
                }
                index += 1;
            }
            b':' => index += 1,
            b'"' => {
                let (end, closed) = string_end(bytes, index + 1);
                let is_key = stack
                    .last()
                    .is_some_and(|frame| !frame.array && frame.expect_key);
                if !closed {
                    let free_text = !is_key && stack.last().is_some_and(Frame::holds_display_text);
                    if !free_text {
                        break;
                    }
                    let mut healed = text[..end].to_owned();
                    healed.push('"');
                    return Some(close(healed, &open_kinds(&stack)));
                }
                if is_key {
                    if let Some(frame) = stack.last_mut() {
                        frame.key = Some(text[index + 1..end].to_owned());
                        frame.expect_key = false;
                    }
                    index = end + 1;
                } else {
                    if let Some(frame) = stack.last_mut()
                        && !frame.array
                        && frame.key.as_deref() == Some("kind")
                    {
                        frame.kind = Some(text[index + 1..end].to_owned());
                    }
                    index = end + 1;
                    if stack.is_empty() {
                        return Some(text[..index].to_owned());
                    }
                    safe = Some((index, open_kinds(&stack)));
                }
            }
            _ => {
                let end = bytes[index..]
                    .iter()
                    .position(|byte| {
                        matches!(byte, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
                    })
                    .map(|offset| index + offset);
                let Some(end) = end else {
                    // A number or literal cut short may be missing digits: drop it.
                    break;
                };
                index = end;
                if stack.is_empty() {
                    return Some(text[..index].to_owned());
                }
                safe = Some((index, open_kinds(&stack)));
            }
        }
    }
    let (cut, open) = safe?;
    Some(close(text[..cut].to_owned(), &open))
}

/// Where the string whose content starts at `start` ends: the index of its
/// closing quote and `true`, or the end of its last whole character and
/// `false` when it was cut (a cut escape is left out).
fn string_end(bytes: &[u8], start: usize) -> (usize, bool) {
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return (index, true),
            b'\\' => {
                let width = if bytes.get(index + 1) == Some(&b'u') {
                    6
                } else {
                    2
                };
                if index + width > bytes.len() {
                    return (index, false);
                }
                index += width;
            }
            _ => index += 1,
        }
    }
    (bytes.len(), false)
}

/// Which containers are open, outermost first: `true` for an array.
fn open_kinds(stack: &[Frame]) -> Vec<bool> {
    stack.iter().map(|frame| frame.array).collect()
}

fn close(mut healed: String, open: &[bool]) -> String {
    for array in open.iter().rev() {
        healed.push(if *array { ']' } else { '}' });
    }
    healed
}
