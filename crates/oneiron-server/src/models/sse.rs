//! An incremental server-sent-events decoder (WHATWG event-stream parsing):
//! LF, CRLF or lone CR line ends, a CR/LF pair split across reads, and one
//! leading byte-order mark. Comments and fields other than `event` and `data`
//! are dropped; an event dispatches on its blank line, or at the end of the
//! stream.

/// One server-sent event: its optional `event:` name and its joined data.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SseEvent {
    pub(super) event: Option<String>,
    pub(super) data: String,
}

#[derive(Default)]
pub(super) struct SseDecoder {
    pending: Vec<u8>,
    started: bool,
    event: Option<String>,
    data: Vec<String>,
    /// The last read ended on a CR: an LF opening the next read is its pair.
    skip_lf: bool,
}

const BOM: &[u8] = b"\xEF\xBB\xBF";

impl SseDecoder {
    /// Feeds one read. Returns every event it completed.
    pub(super) fn push(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        self.pending.extend_from_slice(bytes);
        if !self.started {
            if self.pending.len() < BOM.len() && BOM.starts_with(&self.pending) {
                return Vec::new();
            }
            if self.pending.starts_with(BOM) {
                self.pending.drain(..BOM.len());
            }
            self.started = true;
        }
        let mut events = Vec::new();
        let mut start = 0;
        let mut index = 0;
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
            self.skip_lf = byte == b'\r';
            index += 1;
            start = index;
        }
        self.pending.drain(..start);
        events
    }

    /// The stream ended: a last line and event without their blank line
    /// still count.
    pub(super) fn finish(&mut self) -> Vec<SseEvent> {
        let mut events = Vec::new();
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
            "data" => self.data.push(value.to_owned()),
            _ => {}
        }
    }

    fn dispatch(&mut self, events: &mut Vec<SseEvent>) {
        let event = self.event.take();
        if !self.data.is_empty() {
            events.push(SseEvent {
                event,
                data: std::mem::take(&mut self.data).join("\n"),
            });
        }
    }
}
