//! The first tools/call data fields, consumed without a whole line String.

use std::io::{BufRead, Cursor, Read};

use oneiron::Vault;
use zeroize::Zeroizing;

use super::event_body::Data;

/// `None` is one consumed data or ignored line; id and blank lines stay native.
pub(super) fn read(
    reader: &mut impl BufRead,
    data: &mut Data,
    line: &mut String,
    vault: &Vault,
) -> Result<Option<usize>, ()> {
    let mut prefix = Zeroizing::new(Vec::new());
    while prefix.len() < b"data:".len() {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(()),
        };
        let Some(&byte) = available.first() else {
            break;
        };
        prefix.push(byte);
        reader.consume(1);
        if byte == b'\n' {
            break;
        }
    }
    if prefix.as_slice() != b"data:" {
        if !prefix.starts_with(b"id") && prefix.iter().any(|&byte| byte != b'\r' && byte != b'\n') {
            discard_line(&mut Cursor::new(prefix.as_slice()).chain(reader))?;
            return Ok(None);
        }
        return Cursor::new(prefix.as_slice())
            .chain(reader)
            .read_line(line)
            .map(Some)
            .map_err(|_| ());
    }

    data.append_fragment("", true, Some(vault))?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut first = true;
    let mut trailing_cr = 0_usize;
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(()),
        };
        if available.is_empty() {
            break;
        }
        let newline = available.iter().position(|&byte| byte == b'\n');
        let count = newline.map_or(available.len(), |at| at + 1);
        let mut field = &available[..newline.unwrap_or(count)];
        if first {
            first = false;
            field = field.strip_prefix(b" ").unwrap_or(field);
        }
        bytes.extend_from_slice(field);
        reader.consume(count);

        let valid = match std::str::from_utf8(&bytes) {
            Ok(_) => bytes.len(),
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => return Err(()),
        };
        let text = std::str::from_utf8(&bytes[..valid]).map_err(|_| ())?;
        let retained = text.trim_end_matches('\r');
        if !retained.is_empty() {
            data.append_crs(trailing_cr, vault)?;
            data.append_fragment(retained, false, Some(vault))?;
            trailing_cr = text.len() - retained.len();
        } else {
            trailing_cr = trailing_cr.checked_add(text.len()).ok_or(())?;
        }
        let remaining = bytes.len() - valid;
        bytes.copy_within(valid.., 0);
        bytes[remaining..].fill(0);
        bytes.truncate(remaining);
        if newline.is_some() {
            break;
        }
    }
    if !bytes.is_empty() {
        return Err(());
    }
    Ok(None)
}

/// A prefix already proved this line neither blank nor an id/data field.
fn discard_line(reader: &mut impl BufRead) -> Result<(), ()> {
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(()),
        };
        if available.is_empty() {
            break;
        }
        let newline = available.iter().position(|&byte| byte == b'\n');
        let count = newline.map_or(available.len(), |at| at + 1);
        bytes.extend_from_slice(&available[..newline.unwrap_or(count)]);
        reader.consume(count);
        let valid = match std::str::from_utf8(&bytes) {
            Ok(_) => bytes.len(),
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => return Err(()),
        };
        let remaining = bytes.len() - valid;
        bytes.copy_within(valid.., 0);
        bytes[remaining..].fill(0);
        bytes.truncate(remaining);
        if newline.is_some() {
            break;
        }
    }
    if !bytes.is_empty() {
        return Err(());
    }
    Ok(())
}
