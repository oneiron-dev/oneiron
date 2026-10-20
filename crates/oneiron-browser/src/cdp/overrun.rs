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

/// The number the first top-level `"id"` key in `prefix` holds: the
/// reply's id. None when the prefix ends before one, as an event's does.
fn reply_id(prefix: &[u8]) -> Option<u64> {
    let mut depth = 0usize;
    // The string being read, from its first byte, and the top-level key
    // just read while only its colon may follow.
    let mut string: Option<usize> = None;
    let mut escaped = false;
    let mut key: Option<&[u8]> = None;
    for (at, &byte) in prefix.iter().enumerate() {
        if let Some(start) = string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string = None;
                key = if depth == 1 {
                    Some(&prefix[start..at])
                } else {
                    None
                };
            }
            continue;
        }
        match byte {
            b'"' => string = Some(at + 1),
            b':' if key == Some(b"id".as_slice()) => return digits(&prefix[at + 1..]),
            b' ' | b'\t' | b'\r' | b'\n' => {}
            b'{' | b'[' => {
                depth += 1;
                key = None;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                key = None;
            }
            _ => key = None,
        }
    }
    None
}

/// The number `rest` starts with, past any blank, when it ends within it.
fn digits(rest: &[u8]) -> Option<u64> {
    let rest = rest.trim_ascii_start();
    let end = rest.iter().position(|byte| !byte.is_ascii_digit())?;
    std::str::from_utf8(&rest[..end]).ok()?.parse().ok()
}
