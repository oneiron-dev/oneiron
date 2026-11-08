//! Tip record headers preserve UTF-8 labels and losslessly quote raw byte paths.

use crate::error::Result;

use super::super::paths::serve_failed;

/// The path is the last field because it may contain spaces. Only its label
/// can be non-UTF-8; object IDs and lengths keep their original validation.
pub(super) fn parse_blob_record_header(header: &[u8]) -> Result<(String, u64, String)> {
    let mut fields = header.splitn(4, |byte| *byte == b' ');
    let unshaped = || serve_failed("door blob record header is not `blob <oid> <bytes> <path>`");
    if fields.next() != Some(b"blob".as_slice()) {
        return Err(unshaped());
    }
    let oid = fields.next().ok_or_else(unshaped)?;
    let len = fields.next().ok_or_else(unshaped)?;
    let path = fields.next().ok_or_else(unshaped)?;
    if oid.is_empty() || !oid.iter().all(u8::is_ascii_hexdigit) || path.is_empty() {
        return Err(unshaped());
    }
    let oid = std::str::from_utf8(oid).map_err(|_| unshaped())?;
    let len = std::str::from_utf8(len)
        .ok()
        .and_then(|len| len.parse::<u64>().ok())
        .ok_or_else(|| serve_failed("door blob record declares an unparsable length"))?;
    Ok((oid.to_owned(), len, path_label(path)?))
}

/// UTF-8 labels keep the scanner's existing path-dependent behavior. A raw
/// byte path, previously rejected at the header, uses Git's printable label.
fn path_label(path: &[u8]) -> Result<String> {
    if let Ok(label) = std::str::from_utf8(path) {
        return Ok(label.to_owned());
    }
    // quotePath=false can leave high bytes inside an otherwise C-quoted
    // name. Decode that framing before quoting the actual path again.
    let path = decode_tip_path_bytes(path)?;
    let mut label = String::from("\"");
    for byte in path {
        match byte {
            b'"' => label.push_str("\\\""),
            b'\\' => label.push_str("\\\\"),
            7 => label.push_str("\\a"),
            8 => label.push_str("\\b"),
            b'\t' => label.push_str("\\t"),
            b'\n' => label.push_str("\\n"),
            11 => label.push_str("\\v"),
            12 => label.push_str("\\f"),
            b'\r' => label.push_str("\\r"),
            b' '..=b'~' => label.push(char::from(byte)),
            _ => {
                label.push('\\');
                label.push(char::from(b'0' + (byte >> 6)));
                label.push(char::from(b'0' + ((byte >> 3) & 7)));
                label.push(char::from(b'0' + (byte & 7)));
            }
        }
    }
    label.push('"');
    Ok(label)
}

/// Decode a TIP-stream label for LFS attribution and receive marks. History
/// labels never reach this door; the scanner keeps its textual label.
pub(in crate::origin::smart_http) fn decode_tip_path(path: &str) -> Result<Vec<u8>> {
    decode_tip_path_bytes(path.as_bytes())
}

fn decode_tip_path_bytes(path: &[u8]) -> Result<Vec<u8>> {
    if !path.starts_with(b"\"") {
        return Ok(path.to_vec());
    }
    let input = gix::bstr::BStr::new(path);
    let (decoded, consumed) = gix_quote::ansi_c::undo(input)
        .map_err(|_| serve_failed("door tip path quoting is malformed"))?;
    if consumed != input.len() {
        return Err(serve_failed("door tip path quoting is malformed"));
    }
    // undo also accepts an unterminated quote; require a genuine unescaped
    // closing quote, with an even run of preceding backslashes.
    let mut backslashes = 0;
    for &byte in path[..path.len().saturating_sub(1)].iter().rev() {
        if byte == b'\\' {
            backslashes += 1;
        } else {
            break;
        }
    }
    if path.last() != Some(&b'"') || backslashes % 2 == 1 {
        return Err(serve_failed("door tip path quoting is malformed"));
    }
    let decoded_bstr: &gix::bstr::BStr = &decoded;
    Ok(decoded_bstr.to_vec())
}
