//! A message past the pipe's framing threshold, and one it cannot read
//! (FIX 6851, FIX 7988, FIX 6860, FIX 7410). [`MAX_MESSAGE`] is where a
//! message stops being read inline, never a bound on what a message may
//! be: past it, both transports read on, and every byte the message holds
//! is charged to the host's memory floor through the pipe's inbound charge
//! ([`Pipe::book_inbound`]) before it is held, so a reply of any size (a
//! profile's whole cookie list, a huge page's tree) reaches its call whole
//! and is routed as every message is: Chromium's pipe up to the message's
//! NUL end ([`read_on`]), Lightpanda's WebSocket by its frames
//! (`websocket::gate`). The charge is given back once the message is
//! routed.
//!
//! Where the floor admits no more of it, or the session booked no charge,
//! the message is cut ([`Cut`]): its first [`PREFIX`] and last [`TAIL`]
//! bytes are kept and the rest is discarded as it arrives, the transport
//! stays up, and the cut answers once by what those bytes prove. A reply
//! fails only its own call, naming why; a paused request ends with its
//! request id and page session, failed by the pipe rather than left paused
//! (`unread_request_policy`); one whose identity those bytes do not prove
//! is noted on the session's custody as transport custody lost and warned
//! once (FIX 10329). Any other event is dropped. A message the pipe read
//! whole but cannot parse is answered the same way.

use super::{MAX_MESSAGE, Pipe};
use crate::retention::HandleRetention;
use serde_json::json;
use std::io::{self, BufRead};
use std::time::{Duration, Instant};

/// The most of a cut message's start that is kept: enough to find a
/// reply's id, which both engines write first, and a paused request's
/// method and request id, which open its event.
pub(super) const PREFIX: usize = 256;
/// The most of a cut message's end that is kept: enough to find the page
/// session Chromium names last on a flattened session's event.
pub(super) const TAIL: usize = 256;

/// The pipe's charge on the host's memory floor for the message it reads
/// past its framing threshold: one at a time, as each transport reads one
/// message at a time.
#[derive(Default)]
pub(super) struct Inbound {
    charge: Option<Box<dyn HandleRetention>>,
    /// The bytes charged now.
    charged: usize,
}

impl Pipe {
    /// Books this pipe's reads past its framing threshold to `charge`, a
    /// charge on the host's memory floor holding nothing yet. A pipe given
    /// none cuts each message past the threshold, as before.
    pub(crate) fn book_inbound(&self, charge: Box<dyn HandleRetention>) {
        if let Ok(mut inbound) = self.inbound.lock() {
            inbound.charge = Some(charge);
            inbound.charged = 0;
        }
    }

    /// Charges `bytes` in all for the message read now, before it holds
    /// them: false where the floor admits no more, or no charge was booked.
    pub(super) fn admit_inbound(&self, bytes: usize) -> bool {
        let Ok(mut inbound) = self.inbound.lock() else {
            return false;
        };
        if bytes <= inbound.charged {
            return true;
        }
        let admitted = inbound
            .charge
            .as_mut()
            .is_some_and(|charge| charge.resize(bytes));
        if admitted {
            inbound.charged = bytes;
        }
        admitted
    }

    /// Gives back the charge of the message read last, once it was routed
    /// or cut.
    pub(super) fn release_inbound(&self) {
        if let Ok(mut inbound) = self.inbound.lock() {
            let Inbound { charge, charged } = &mut *inbound;
            if *charged > 0
                && let Some(charge) = charge.as_mut()
            {
                charge.resize(0);
            }
            *charged = 0;
        }
    }

    /// Why a message past the framing threshold was cut.
    pub(super) fn inbound_refusal(&self) -> String {
        let threshold = MAX_MESSAGE >> 20;
        let booked = self
            .inbound
            .lock()
            .is_ok_and(|inbound| inbound.charge.is_some());
        if booked {
            format!(
                "its reply passed the {threshold} MiB framing threshold and the host's memory floor admits no more of it"
            )
        } else {
            format!(
                "its reply passed the {threshold} MiB framing threshold and this session booked no host memory to read on"
            )
        }
    }
}

/// How a Chromium message read on past the framing threshold ended.
pub(super) enum ReadOn {
    /// It is held whole, through its NUL end.
    Whole,
    /// The floor admitted no more of it: cut, and read past.
    Cut(Cut),
    /// The pipe ended first.
    Ended,
}

/// Reads the rest of a Chromium message whose first `buf` bytes reached
/// the framing threshold, through its NUL end, charging the room it holds
/// before it grows; or, once the floor admits no more, cuts it and reads
/// past it.
pub(super) fn read_on(pipe: &Pipe, reader: &mut impl BufRead, buf: &mut Vec<u8>) -> ReadOn {
    loop {
        let step = match reader.fill_buf() {
            Ok([]) => return ReadOn::Ended,
            Ok(bytes) => {
                let end = bytes.iter().position(|byte| *byte == 0);
                let used = end.map_or(bytes.len(), |at| at + 1);
                let needed = buf.len() + used;
                let room = buf.capacity().saturating_mul(2).max(needed);
                if needed > buf.capacity() && !pipe.admit_inbound(room) {
                    None
                } else {
                    if needed > buf.capacity() {
                        buf.reserve_exact(room - buf.len());
                    }
                    buf.extend_from_slice(&bytes[..used]);
                    Some((used, end.is_some()))
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return ReadOn::Ended,
        };
        let Some((used, ended)) = step else {
            let mut cut = Cut::of(buf, pipe.inbound_refusal());
            *buf = Vec::new();
            pipe.release_inbound();
            return if skip_rest(reader, &mut cut.tail) {
                ReadOn::Cut(cut)
            } else {
                ReadOn::Ended
            };
        };
        reader.consume(used);
        if ended {
            return ReadOn::Whole;
        }
    }
}

/// Reads past the rest of a message, through its NUL end, keeping only its
/// last [`TAIL`] bytes in `tail`: false once the pipe ended first.
fn skip_rest(reader: &mut impl BufRead, tail: &mut Vec<u8>) -> bool {
    loop {
        let (used, ended) = match reader.fill_buf() {
            Ok([]) => return false,
            Ok(bytes) => {
                let end = bytes.iter().position(|byte| *byte == 0);
                let kept = end.unwrap_or(bytes.len());
                keep_tail(tail, &bytes[..kept]);
                (end.map_or(bytes.len(), |at| at + 1), end.is_some())
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return false,
        };
        reader.consume(used);
        if ended {
            return true;
        }
    }
}

/// Adds `bytes` to the end `tail` keeps, at most its last [`TAIL`].
pub(super) fn keep_tail(tail: &mut Vec<u8>, bytes: &[u8]) {
    tail.extend_from_slice(bytes);
    if tail.len() > TAIL {
        tail.drain(..tail.len() - TAIL);
    }
}

/// A message the pipe did not route: its first and last bytes, and why.
pub(super) struct Cut {
    pub(super) prefix: Vec<u8>,
    pub(super) tail: Vec<u8>,
    pub(super) why: String,
}

impl Cut {
    /// The cut of `bytes`, all the pipe holds of its message so far.
    pub(super) fn of(bytes: &[u8], why: String) -> Self {
        let mut tail = Vec::new();
        keep_tail(&mut tail, &bytes[bytes.len().min(PREFIX)..]);
        Self {
            prefix: bytes[..bytes.len().min(PREFIX)].to_vec(),
            tail,
            why,
        }
    }

    /// Answers the cut once, by what its bytes prove: a reply fails its own
    /// call with why; a paused request is ended (`unread_request_policy`);
    /// one whose identity those bytes do not prove is noted on the session's
    /// custody as transport custody lost and warned once (FIX 10329). Any
    /// other event is dropped. False once the routes are lost.
    pub(super) fn answer(self, pipe: &Pipe) -> bool {
        if let Some(id) = reply_id(&self.prefix) {
            let Ok(mut routes) = pipe.pending.lock() else {
                return false;
            };
            if let Some(tx) = routes.as_mut().and_then(|routes| routes.remove(&id)) {
                let _ = tx.send(Err(self.why));
            }
            return true;
        }
        if let Some((session, request)) = paused_request(&self.prefix, &self.tail) {
            end_unread(pipe.clone(), session, request);
        } else if root_string(&self.prefix, &["method"]).as_deref() == Some("Fetch.requestPaused") {
            pipe.custody.refuse(crate::DestinationRefusal {
                reason: TRANSPORT_CUSTODY_LOST.to_owned(),
                message: format!(
                    "transport custody lost for a paused request: {why}",
                    why = self.why
                ),
            });
            tracing::warn!(cause = %self.why, "browser transport custody lost for a paused request");
        }
        true
    }
}

/// Answers a message the pipe read whole but could not parse (`why`), as
/// a cut one is answered. False once the routes are lost.
pub(super) fn unreadable(pipe: &Pipe, message: &[u8], why: &str) -> bool {
    Cut::of(message, format!("its reply could not be read ({why})")).answer(pipe)
}

/// How a paused request the pipe could not read ends
/// (`unread_request_policy`, CALLS row, open): failed once, by the request
/// id and page session its event's first and last bytes name, as
/// `Failed`, never passed on unread and never left paused. A request whose
/// identity those bytes do not prove is noted on the session's custody as
/// transport custody lost and warned once (FIX 10329); it still waits out
/// its page's own load, as before, with no wait or timing changed.
const UNREAD_REQUEST_REASON: &str = "Failed";

/// The reason a paused request whose identity the pipe could not prove is
/// noted as lost on the session's custody (FIX 10329): transport custody
/// was lost for that request.
const TRANSPORT_CUSTODY_LOST: &str = "transport_custody_lost";

/// Ends paused request `request` of page `session`, from its own thread:
/// the reader never waits for its own CDP reply.
fn end_unread(pipe: Pipe, session: String, request: String) {
    std::thread::spawn(move || {
        let _ = pipe.call(
            Some(&session),
            "Fetch.failRequest",
            json!({"requestId": request, "errorReason": UNREAD_REQUEST_REASON}),
            Instant::now() + Duration::from_secs(30),
        );
    });
}

/// The page session and request id of a `Fetch.requestPaused` event, from
/// its first bytes (`prefix`: its method, and `params.requestId`, which
/// Chromium writes first) and its last (`tail`: the root's `sessionId`,
/// which a flattened session's event names last), where both are proved.
fn paused_request(prefix: &[u8], tail: &[u8]) -> Option<(String, String)> {
    if root_string(prefix, &["method"]).as_deref() != Some("Fetch.requestPaused") {
        return None;
    }
    let request = root_string(prefix, &["params", "requestId"])?;
    let session = root_string(prefix, &["sessionId"]).or_else(|| last_session(tail))?;
    Some((session, request))
}

/// The string at `path` in the object that opens `bytes`, read key by key
/// as far as the bytes go: none once they end first.
fn root_string(bytes: &[u8], path: &[&str]) -> Option<String> {
    let mut at = blank(bytes, 0);
    for (depth, step) in path.iter().enumerate() {
        if bytes.get(at) != Some(&b'{') {
            return None;
        }
        at += 1;
        loop {
            let (key, end) = string(bytes, blank(bytes, at))?;
            at = blank(bytes, end);
            if bytes.get(at) != Some(&b':') {
                return None;
            }
            at = blank(bytes, at + 1);
            if key == step.as_bytes() {
                break;
            }
            at = blank(bytes, past_value(bytes, at)?);
            if bytes.get(at) != Some(&b',') {
                return None;
            }
            at += 1;
        }
        if depth + 1 == path.len() {
            let (_, end) = string(bytes, at)?;
            return serde_json::from_slice(&bytes[at..end]).ok();
        }
    }
    None
}

/// The root `sessionId` a message's last bytes name: its last key, a string
/// only blanks and the root's closing brace follow.
fn last_session(tail: &[u8]) -> Option<String> {
    const KEY: &[u8] = b"\"sessionId\"";
    let at = tail.windows(KEY.len()).rposition(|window| window == KEY)?;
    let colon = blank(tail, at + KEY.len());
    if tail.get(colon) != Some(&b':') {
        return None;
    }
    let start = blank(tail, colon + 1);
    let (_, end) = string(tail, start)?;
    let close = blank(tail, end);
    if tail.get(close) != Some(&b'}') || blank(tail, close + 1) != tail.len() {
        return None;
    }
    serde_json::from_slice(&tail[start..end]).ok()
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
