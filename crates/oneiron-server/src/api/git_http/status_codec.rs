//! Receive-pack status pkt-line codec.

// Reframe Git report-status and report-status-v2, with or without side-band-64k.
// Channel 1 may split a nested pkt-line anywhere, including its length header.
// The report is read and written as a stream, one pkt-line at a time, so a
// push of any number of refs is rewritten in memory bounded by one line.

use oneiron::origin::smart_http;
use oneiron::origin::smart_http::HeldBytes;
use std::collections::HashMap;
use std::io::{self, Read, Write};

/// The most bytes one side-band packet carries after its channel byte.
const SIDEBAND_PAYLOAD: usize = 65515;

/// Why a held report was not rewritten.
pub(super) enum StatusFault {
    /// The backend's report is not a complete, well-formed status for the refs
    /// the landing settled.
    Unreadable,
    /// Holding the report failed (the disk).
    Held(io::Error),
}

impl From<io::Error> for StatusFault {
    fn from(error: io::Error) -> Self {
        if is_malformed(&error) {
            Self::Unreadable
        } else {
            Self::Held(error)
        }
    }
}

/// Rewrites the held report `input` into `output`, each ref's line saying
/// what the landing did with it.
pub(super) fn rewrite_receive_pack_status(
    input: &mut HeldBytes,
    results: &[smart_http::ReceivePackRefResult],
    output: &mut impl Write,
) -> Result<(), StatusFault> {
    if results.is_empty() {
        return Err(StatusFault::Unreadable);
    }
    let sideband = Packets::new(input.reader()?)
        .next_packet()?
        .ok_or_else(malformed)?
        .first()
        .is_some_and(|channel| matches!(channel, 1..=3));
    let reader = input.reader()?;
    if sideband {
        let mut framed = SidebandFrames {
            output,
            pending: Vec::with_capacity(SIDEBAND_PAYLOAD),
        };
        rewrite(Packets::new(Sideband::new(reader)), results, &mut framed)?;
        framed.finish()?;
    } else {
        rewrite(Packets::new(reader), results, output)?;
    }
    Ok(())
}

fn rewrite(
    mut input: Packets<impl Read>,
    results: &[smart_http::ReceivePackRefResult],
    output: &mut impl Write,
) -> io::Result<()> {
    if input.next_packet()? != Some(b"unpack ok\n".as_slice()) {
        return Err(malformed());
    }
    write_status_packet(output, b"unpack ok\n")?;
    let mut seen = vec![false; results.len()];
    let index_of: HashMap<&str, usize> = results
        .iter()
        .enumerate()
        .map(|(index, result)| (result.name.as_str(), index))
        .collect();
    let mut suppress_options = true;
    loop {
        let packet = input.next_packet()?.ok_or_else(malformed)?;
        if packet.is_empty() {
            // The flush ends the report: nothing may follow it.
            if input.next_packet()?.is_some() {
                return Err(malformed());
            }
            write_status_packet(output, &[])?;
            break;
        }
        let accepted = packet.strip_prefix(b"ok ");
        let refused = packet.strip_prefix(b"ng ");
        if let Some(tail) = accepted.or(refused) {
            let text = std::str::from_utf8(tail)
                .ok()
                .and_then(|text| text.strip_suffix('\n'))
                .ok_or_else(malformed)?;
            let name = if refused.is_some() {
                text.split_once(' ').ok_or_else(malformed)?.0
            } else {
                text
            };
            let index = *index_of.get(name).ok_or_else(malformed)?;
            if std::mem::replace(&mut seen[index], true) {
                return Err(malformed());
            }
            let status = results[index].status;
            suppress_options =
                refused.is_some() || status != smart_http::ReceivePackRefStatus::Published;
            let reason = match status {
                smart_http::ReceivePackRefStatus::Pending => {
                    Some("publication pending; ref effects may exist")
                }
                smart_http::ReceivePackRefStatus::Superseded => {
                    Some("observed ref effect was superseded")
                }
                smart_http::ReceivePackRefStatus::NotApplied => Some("ref was not applied"),
                smart_http::ReceivePackRefStatus::Uncertified => {
                    Some("ref needs objects its earlier publication never certified")
                }
                smart_http::ReceivePackRefStatus::Published if refused.is_some() => {
                    Some("backend refused ref update")
                }
                smart_http::ReceivePackRefStatus::Published => None,
            };
            if let Some(reason) = reason {
                write_status_packet(output, format!("ng {name} {reason}\n").as_bytes())?;
            } else {
                write_status_packet(output, packet)?;
            }
        } else if packet.starts_with(b"option ") {
            if !suppress_options {
                write_status_packet(output, packet)?;
            }
        } else {
            return Err(malformed());
        }
    }
    if seen.iter().any(|seen| !seen) {
        return Err(malformed());
    }
    Ok(())
}

/// Reads pkt-lines off a byte stream.
struct Packets<R> {
    input: R,
    payload: Vec<u8>,
}

impl<R: Read> Packets<R> {
    fn new(input: R) -> Self {
        Self {
            input,
            payload: Vec::new(),
        }
    }

    /// The next line's payload, empty for a flush; `None` at a clean end of
    /// the stream. A malformed or cut line is an error [`is_malformed`] names.
    fn next_packet(&mut self) -> io::Result<Option<&[u8]>> {
        let mut header = [0; 4];
        let mut read = 0;
        while read < header.len() {
            match self.input.read(&mut header[read..]) {
                Ok(0) => break,
                Ok(count) => read += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        if read == 0 {
            return Ok(None);
        }
        let len = std::str::from_utf8(&header[..read])
            .ok()
            .filter(|_| read == header.len())
            .and_then(|header| usize::from_str_radix(header, 16).ok())
            .ok_or_else(malformed)?;
        if len == 0 {
            self.payload.clear();
            return Ok(Some(&self.payload));
        }
        if !(4..=65520).contains(&len) {
            return Err(malformed());
        }
        self.payload.resize(len - 4, 0);
        self.input
            .read_exact(&mut self.payload)
            .map_err(|error| match error.kind() {
                io::ErrorKind::UnexpectedEof => malformed(),
                _ => error,
            })?;
        Ok(Some(&self.payload))
    }
}

/// Channel 1 of a side-band stream, as the bytes it carries. Progress on
/// channel 2 and flushes between packets are dropped; channel 3 is fatal,
/// even with a complete status and published refs.
struct Sideband<R> {
    packets: Packets<R>,
    data: Vec<u8>,
    at: usize,
}

impl<R: Read> Sideband<R> {
    fn new(input: R) -> Self {
        Self {
            packets: Packets::new(input),
            data: Vec::new(),
            at: 0,
        }
    }
}

impl<R: Read> Read for Sideband<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        while self.at == self.data.len() {
            let Some(packet) = self.packets.next_packet()? else {
                return Ok(0);
            };
            match packet.split_first() {
                Some((1, payload)) => {
                    self.data.clear();
                    self.data.extend_from_slice(payload);
                    self.at = 0;
                }
                Some((2, _)) | None => {}
                Some(_) => return Err(malformed()),
            }
        }
        let count = buffer.len().min(self.data.len() - self.at);
        buffer[..count].copy_from_slice(&self.data[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}

/// Writes a byte stream as channel-1 packets of at most
/// [`SIDEBAND_PAYLOAD`] bytes each, then a flush.
struct SidebandFrames<'a, W> {
    output: &'a mut W,
    pending: Vec<u8>,
}

impl<W: Write> SidebandFrames<'_, W> {
    fn emit(&mut self) -> io::Result<()> {
        write!(self.output, "{:04x}", self.pending.len() + 5)?;
        self.output.write_all(&[1])?;
        self.output.write_all(&self.pending)?;
        self.pending.clear();
        Ok(())
    }

    fn finish(mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            self.emit()?;
        }
        self.output.write_all(b"0000")
    }
}

impl<W: Write> Write for SidebandFrames<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(SIDEBAND_PAYLOAD - self.pending.len());
        self.pending.extend_from_slice(&bytes[..count]);
        if self.pending.len() == SIDEBAND_PAYLOAD {
            self.emit()?;
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_status_packet(output: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() {
        return output.write_all(b"0000");
    }
    if payload.len() > 65516 {
        return Err(malformed());
    }
    write!(output, "{:04x}", payload.len() + 4)?;
    output.write_all(payload)
}

/// A report the codec cannot read: told apart from the holder's own I/O.
#[derive(Debug)]
struct Malformed;

impl std::fmt::Display for Malformed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("malformed receive-pack status")
    }
}

impl std::error::Error for Malformed {}

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, Malformed)
}

fn is_malformed(error: &io::Error) -> bool {
    matches!(error.get_ref(), Some(inner) if inner.is::<Malformed>())
}

/// One pkt-line, appended to `output`; for building reports in tests.
#[cfg(test)]
pub(super) fn append_status_packet(output: &mut Vec<u8>, payload: &[u8]) -> Option<()> {
    write_status_packet(output, payload).ok()
}

/// The next pkt-line of `input`, as tests read a rewritten report.
#[cfg(test)]
pub(super) fn status_packet<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let header = std::str::from_utf8(input.get(..4)?).ok()?;
    let len = usize::from_str_radix(header, 16).ok()?;
    if len == 0 {
        *input = &input[4..];
        return Some(&[]);
    }
    if !(4..=65520).contains(&len) || len > input.len() {
        return None;
    }
    let payload = &input[4..len];
    *input = &input[len..];
    Some(payload)
}

/// [`rewrite_receive_pack_status`] over a report held in memory.
#[cfg(test)]
pub(super) fn rewrite_status_bytes(
    body: &[u8],
    results: &[smart_http::ReceivePackRefResult],
) -> Option<Vec<u8>> {
    let mut input = HeldBytes::new(usize::MAX, None);
    input.write_all(body).ok()?;
    let mut output = Vec::new();
    rewrite_receive_pack_status(&mut input, results, &mut output).ok()?;
    Some(output)
}
