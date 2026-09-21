//! Linear lexical framing; the PDF parser validates the single bounded operand.
use super::*;

pub(super) fn leading_dictionary(bytes: &[u8]) -> Result<(Dictionary, usize)> {
    let end = bytes.len().min(64 * 1024);
    let mut cursor = 0;
    let mut nesting = Vec::new();
    let mut started = false;
    while cursor < end {
        match bytes[cursor] {
            b'%' => {
                while cursor < end && !matches!(bytes[cursor], b'\r' | b'\n') {
                    cursor += 1;
                }
                continue;
            }
            byte if byte.is_ascii_whitespace() || byte == 0 => {}
            b'<' if bytes.get(cursor + 1) == Some(&b'<') => {
                nesting.push(b'>');
                started = true;
                cursor += 1;
            }
            _ if !started => return Err(PdfPreparationError::MalformedPdf),
            b'(' => {
                cursor += 1;
                let mut depth = 1;
                while cursor < end && depth != 0 {
                    match bytes[cursor] {
                        b'\\' => cursor += 1,
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    if depth > 32 {
                        return Err(PdfPreparationError::Limit);
                    }
                    cursor += 1;
                }
                if depth != 0 {
                    return Err(PdfPreparationError::MalformedPdf);
                }
                continue;
            }
            b'<' => {
                cursor += 1;
                while cursor < end && bytes[cursor] != b'>' {
                    cursor += 1;
                }
                if cursor == end {
                    return Err(PdfPreparationError::MalformedPdf);
                }
            }
            b'[' => nesting.push(b']'),
            b']' => {
                if nesting.pop() != Some(b']') {
                    return Err(PdfPreparationError::MalformedPdf);
                }
            }
            b'>' => {
                if bytes.get(cursor + 1) != Some(&b'>') || nesting.pop() != Some(b'>') {
                    return Err(PdfPreparationError::MalformedPdf);
                }
                cursor += 1;
                if nesting.is_empty() {
                    let object = super::operand(&bytes[..=cursor])?;
                    return Ok((object.as_dict()?.clone(), cursor + 1));
                }
            }
            _ => {}
        }
        if nesting.len() > 32 {
            return Err(PdfPreparationError::Limit);
        }
        cursor += 1;
    }
    Err(PdfPreparationError::MalformedPdf)
}
