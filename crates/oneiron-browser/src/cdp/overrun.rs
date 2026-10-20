//! A message the pipe cannot take whole (FIX 6851): one past the 32 MiB
//! bound fails only its own call, or is dropped when it is an event, and
//! the transport stays up ([`oversize_message_policy`]). Both transports
//! keep its first [`PREFIX`] bytes and discard the rest as it arrives,
//! never holding it: Chromium's pipe up to the message's NUL end (`cdp`),
//! Lightpanda's WebSocket by its frames (`websocket::gate`). A reply the
//! pipe cannot parse fails its own call the same way, at once, rather than
//! leaving it to wait out its bound.

use super::{MAX_MESSAGE, Pipe};

/// The most of an oversize message that is kept: enough to find a reply's
/// id, which both engines write first.
pub(super) const PREFIX: usize = 256;

/// An inbound CDP message past the 32 MiB codec bound fails only its own
/// call, with a protocol error naming the bound, or is dropped if it is an
/// event (its first bytes, `prefix`, name no id); the transport stays up.
/// False once the routes are lost.
pub(super) fn oversize_message_policy(pipe: &Pipe, prefix: &[u8]) -> bool {
    let bound = MAX_MESSAGE >> 20;
    fail_reply(
        pipe,
        prefix,
        &format!("its reply passed the {bound} MiB message bound"),
    )
}

/// Fails the call whose reply `message` is, which the pipe could not parse
/// (`why`), by the id its first bytes name; an event is dropped. False
/// once the routes are lost.
pub(super) fn unreadable(pipe: &Pipe, message: &[u8], why: &serde_json::Error) -> bool {
    let prefix = &message[..message.len().min(PREFIX)];
    fail_reply(
        pipe,
        prefix,
        &format!("its reply could not be read ({why})"),
    )
}

/// Fails the call whose reply begins with `prefix`, with `why`; a prefix
/// that names no id is an event's, and nothing is failed.
fn fail_reply(pipe: &Pipe, prefix: &[u8], why: &str) -> bool {
    let Some(id) = reply_id(prefix) else {
        return true;
    };
    let Ok(mut routes) = pipe.pending.lock() else {
        return false;
    };
    if let Some(tx) = routes.as_mut().and_then(|routes| routes.remove(&id)) {
        let _ = tx.send(Err(why.to_owned()));
    }
    true
}

/// The reply id `prefix` names: the value of its root object's `"id"` key,
/// read in key position, when it is a whole unsigned integer that a `,` or
/// `}` ends within the prefix. None for anything else (a non-object root, a
/// value that reads "id", a fraction, an integer the prefix cuts): an event,
/// or a message whose id is not proved.
fn reply_id(prefix: &[u8]) -> Option<u64> {
    let mut at = blank(prefix, 0);
    if prefix.get(at) != Some(&b'{') {
        return None;
    }
    at += 1;
    loop {
        let (key, end) = string(prefix, blank(prefix, at))?;
        at = blank(prefix, end);
        if prefix.get(at) != Some(&b':') {
            return None;
        }
        at = blank(prefix, at + 1);
        if key == b"id" {
            return integer(prefix, at);
        }
        at = blank(prefix, past_value(prefix, at)?);
        if prefix.get(at) != Some(&b',') {
            return None;
        }
        at += 1;
    }
}

/// Past the blanks JSON allows at `at`.
fn blank(bytes: &[u8], at: usize) -> usize {
    let blanks = bytes.get(at..).map_or(0, |rest| {
        rest.iter()
            .take_while(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            .count()
    });
    at + blanks
}

/// The string whose quote is at `at`: its raw bytes, and where it ends.
fn string(bytes: &[u8], at: usize) -> Option<(&[u8], usize)> {
    if bytes.get(at) != Some(&b'"') {
        return None;
    }
    let mut escaped = false;
    for (offset, &byte) in bytes.get(at + 1..)?.iter().enumerate() {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            let close = at + 1 + offset;
            return Some((&bytes[at + 1..close], close + 1));
        }
    }
    None
}

/// Where the value at `at` ends: a string; an object or an array, through
/// its closing bracket; or a number or literal, up to the `,`, `}` or blank
/// after it. None when the prefix ends first.
fn past_value(bytes: &[u8], at: usize) -> Option<usize> {
    match bytes.get(at)? {
        b'"' => string(bytes, at).map(|(_, end)| end),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut next = at;
            while let Some(&byte) = bytes.get(next) {
                match byte {
                    b'"' => {
                        next = string(bytes, next)?.1;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(next + 1);
                        }
                    }
                    _ => {}
                }
                next += 1;
            }
            None
        }
        _ => {
            let end = bytes[at..]
                .iter()
                .position(|byte| matches!(byte, b',' | b'}' | b' ' | b'\t' | b'\r' | b'\n'))?;
            (end > 0).then_some(at + end)
        }
    }
}

/// The whole unsigned JSON integer at `at`, when blanks and a `,` or `}`
/// follow it within `bytes`.
fn integer(bytes: &[u8], at: usize) -> Option<u64> {
    let digits = bytes
        .get(at..)?
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits == 0 || (digits > 1 && bytes[at] == b'0') {
        return None;
    }
    let end = at + digits;
    if !matches!(bytes.get(blank(bytes, end)), Some(b',' | b'}')) {
        return None;
    }
    std::str::from_utf8(&bytes[at..end]).ok()?.parse().ok()
}
