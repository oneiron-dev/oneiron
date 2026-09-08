//! Receive-pack status pkt-line codec.

// Reframe Git report-status and report-status-v2, with or without side-band-64k.
// Channel 1 may split a nested pkt-line anywhere, including its length header.

use super::serve::GIT_HTTP_MAX_HELD_BYTES;
use axum::body::Bytes;
use oneiron::origin::smart_http;

pub(super) fn rewrite_receive_pack_status(
    body: &[u8],
    results: &[smart_http::ReceivePackRefResult],
) -> Option<Vec<u8>> {
    if body.len() > GIT_HTTP_MAX_HELD_BYTES
        || results.is_empty()
        || results.len() > smart_http::ORIGIN_MAX_REF_UPDATES
    {
        return None;
    }
    let mut probe = body;
    let first = status_packet(&mut probe)?;
    let sideband = first
        .first()
        .is_some_and(|channel| matches!(channel, 1..=3));
    let mut data = Vec::new();
    if sideband {
        let mut input = body;
        while !input.is_empty() {
            let packet = status_packet(&mut input)?;
            match packet.split_first() {
                Some((1, payload)) => data.extend_from_slice(payload),
                Some((2, _)) | None => {}
                // Channel 3 is fatal, even with a complete status and published refs.
                Some((3, _)) => return None,
                _ => return None,
            }
        }
    } else {
        data.extend_from_slice(body);
    }
    let mut input = data.as_slice();
    if status_packet(&mut input)? != b"unpack ok\n" {
        return None;
    }
    let mut rewritten = Vec::new();
    append_status_packet(&mut rewritten, b"unpack ok\n")?;
    let mut seen = vec![false; results.len()];
    let mut suppress_options = true;
    let mut flushed = false;
    while !input.is_empty() {
        let packet = status_packet(&mut input)?;
        if packet.is_empty() {
            if !input.is_empty() {
                return None;
            }
            append_status_packet(&mut rewritten, packet)?;
            flushed = true;
            break;
        }
        let accepted = packet.strip_prefix(b"ok ");
        let refused = packet.strip_prefix(b"ng ");
        if let Some(tail) = accepted.or(refused) {
            let text = std::str::from_utf8(tail).ok()?.strip_suffix('\n')?;
            let name = if refused.is_some() {
                text.split_once(' ')?.0
            } else {
                text
            };
            let index = results.iter().position(|result| result.name == name)?;
            if std::mem::replace(&mut seen[index], true) {
                return None;
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
                smart_http::ReceivePackRefStatus::Published if refused.is_some() => {
                    Some("backend refused ref update")
                }
                smart_http::ReceivePackRefStatus::Published => None,
            };
            if let Some(reason) = reason {
                append_status_packet(&mut rewritten, format!("ng {name} {reason}\n").as_bytes())?;
            } else {
                append_status_packet(&mut rewritten, packet)?;
            }
        } else if packet.starts_with(b"option ") {
            if !suppress_options {
                append_status_packet(&mut rewritten, packet)?;
            }
        } else {
            return None;
        }
    }
    if !flushed || seen.iter().any(|seen| !seen) {
        return None;
    }
    if !sideband {
        return Some(rewritten);
    }
    let mut framed = Vec::new();
    for chunk in rewritten.chunks(65515) {
        let mut payload = Vec::with_capacity(chunk.len() + 1);
        payload.push(1);
        payload.extend_from_slice(chunk);
        append_status_packet(&mut framed, &payload)?;
    }
    append_status_packet(&mut framed, &[])?;
    Some(framed)
}

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

pub(super) fn append_status_packet(output: &mut Vec<u8>, payload: &[u8]) -> Option<()> {
    if payload.len().checked_add(4)? > GIT_HTTP_MAX_HELD_BYTES.saturating_sub(output.len()) {
        return None;
    }
    if payload.is_empty() {
        output.extend_from_slice(b"0000");
    } else {
        if payload.len() > 65516 {
            return None;
        }
        output.extend_from_slice(format!("{:04x}", payload.len() + 4).as_bytes());
        output.extend_from_slice(payload);
    }
    (output.len() <= GIT_HTTP_MAX_HELD_BYTES).then_some(())
}

pub(super) fn concat_chunks(chunks: Vec<Bytes>) -> Bytes {
    let total = chunks.iter().map(Bytes::len).sum();
    let mut buffer = Vec::with_capacity(total);
    for chunk in chunks {
        buffer.extend_from_slice(&chunk);
    }
    Bytes::from(buffer)
}
