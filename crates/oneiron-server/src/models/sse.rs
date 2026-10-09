//! An incremental server-sent-events decoder (WHATWG event-stream parsing):
//! LF, CRLF or lone CR line ends, a CR/LF pair split across reads, and one
//! leading byte-order mark. Comments and fields other than `event` and `data`
//! are dropped; an event dispatches on its blank line, or at the end of the
//! stream.
//!
//! Each byte is scanned once, however many reads its line is split across,
//! and one event may hold at most [`MAX_EVENT_BYTES`]: a provider stream that
//! never ends its event is refused, not buffered without bound.

/// One server-sent event: its optional `event:` name and its joined data.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SseEvent {
    pub(super) event: Option<String>,
    pub(super) data: String,
}

/// The most one event may hold, its unfinished line included: far above any
/// event a provider sends (a delta, a usage chunk, a whole reply from a proxy
/// that sends it at once), so only a broken stream reaches it.
pub(super) const MAX_EVENT_BYTES: usize = 4 << 20;

/// An event grew past [`MAX_EVENT_BYTES`] before it ended.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct EventTooLarge;

#[derive(Default)]
pub(super) struct SseDecoder {
    /// The unfinished line, after the last read's complete lines.
    pending: Vec<u8>,
    /// How much of `pending` is already scanned: none of it ends a line.
    scanned: usize,
    started: bool,
    event: Option<String>,
    data: Vec<String>,
    /// Bytes the open event's data already holds.
    event_bytes: usize,
    /// The last read ended on a CR: an LF opening the next read is its pair.
    skip_lf: bool,
}

const BOM: &[u8] = b"\xEF\xBB\xBF";

impl SseDecoder {
    /// Feeds one read. Returns every event it completed, or refuses an
    /// event that grew past [`MAX_EVENT_BYTES`].
    pub(super) fn push(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>, EventTooLarge> {
        self.pending.extend_from_slice(bytes);
        if !self.started {
            if self.pending.len() < BOM.len() && BOM.starts_with(&self.pending) {
                return Ok(Vec::new());
            }
            if self.pending.starts_with(BOM) {
                self.pending.drain(..BOM.len());
            }
            self.started = true;
        }
        let mut events = Vec::new();
        let mut start = 0;
        let mut index = self.scanned;
        while index < self.pending.len() {
            let byte = self.pending[index];
            // A CR ends its line at once; an LF right after it is its pair.
            if std::mem::take(&mut self.skip_lf) && byte == b'\n' {
                index += 1;
                start = index;
                continue;
            }
            if byte != b'\n' && byte != b'\r' {
                index += 1;
                continue;
            }
            let line = String::from_utf8_lossy(&self.pending[start..index]).into_owned();
            self.line(&line, &mut events);
            if self.event_bytes > MAX_EVENT_BYTES {
                return Err(EventTooLarge);
            }
            self.skip_lf = byte == b'\r';
            index += 1;
            start = index;
        }
        self.pending.drain(..start);
        self.scanned = self.pending.len();
        if self.event_bytes.saturating_add(self.pending.len()) > MAX_EVENT_BYTES {
            return Err(EventTooLarge);
        }
        Ok(events)
    }

    /// The stream ended: a last line and event without their blank line
    /// still count.
    pub(super) fn finish(&mut self) -> Vec<SseEvent> {
        let mut events = Vec::new();
        self.scanned = 0;
        let rest = std::mem::take(&mut self.pending);
        let line = String::from_utf8_lossy(&rest).into_owned();
        if !line.is_empty() {
            self.line(&line, &mut events);
        }
        self.dispatch(&mut events);
        events
    }

    fn line(&mut self, line: &str, events: &mut Vec<SseEvent>) {
        if line.is_empty() {
            self.dispatch(events);
            return;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => self.event = Some(value.to_owned()),
            "data" => {
                self.event_bytes = self.event_bytes.saturating_add(value.len() + 1);
                self.data.push(value.to_owned());
            }
            _ => {}
        }
    }

    fn dispatch(&mut self, events: &mut Vec<SseEvent>) {
        self.event_bytes = 0;
        let event = self.event.take();
        if !self.data.is_empty() {
            events.push(SseEvent {
                event,
                data: std::mem::take(&mut self.data).join("\n"),
            });
        }
    }
}
