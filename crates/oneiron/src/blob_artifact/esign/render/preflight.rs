//! Classic, single-revision PDF framing checked before lopdf loads any objects.
use super::*;

// lopdf merges /Prev and eagerly inflates object streams. This profile excludes
// both, before parsing objects, so hidden old signatures and per-stream expansion
// cannot evade the rewrite guard. The trailer uses lopdf's native dictionary
// parser (as a content operand), including escaped names and indirect references.
pub(super) fn inspect(bytes: &[u8]) -> Result<BTreeSet<ObjectId>> {
    let start = bytes
        .windows(9)
        .rposition(|v| v == b"startxref")
        .ok_or(PdfPreparationError::MalformedPdf)?;
    let tail =
        std::str::from_utf8(&bytes[start + 9..]).map_err(|_| PdfPreparationError::MalformedPdf)?;
    let mut tokens = tail.split_ascii_whitespace();
    let offset = integer(tokens.next())?;
    if tokens.next() != Some("%%EOF") || tokens.next().is_some() || offset >= start {
        return Err(PdfPreparationError::MalformedPdf);
    }
    let xref = &bytes[offset..start];
    if !xref.starts_with(b"xref") {
        return Err(PdfPreparationError::UnsupportedPdf);
    }
    let trailer_start = xref
        .windows(7)
        .position(|v| v == b"trailer")
        .ok_or(PdfPreparationError::MalformedPdf)?;
    let table = std::str::from_utf8(&xref[..trailer_start])
        .map_err(|_| PdfPreparationError::MalformedPdf)?;
    let mut entries = table.split_ascii_whitespace();
    if entries.next() != Some("xref") {
        return Err(PdfPreparationError::MalformedPdf);
    }
    let mut ids = BTreeSet::new();
    let mut live_ids = BTreeSet::new();
    while let Some(first) = entries.next() {
        let first = integer(Some(first))?;
        let count = integer(entries.next())?;
        let end = first.checked_add(count).ok_or(PdfPreparationError::Limit)?;
        if count == 0 || end > MAX_OBJECTS + 1 || ids.len() + count > MAX_OBJECTS + 1 {
            return Err(PdfPreparationError::Limit);
        }
        for id in first..end {
            let offset = integer(entries.next())?;
            let generation = integer(entries.next())?;
            let kind = entries.next();
            if !ids.insert(id)
                || generation > u16::MAX as usize
                || !matches!(kind, Some("n" | "f"))
                || (kind == Some("n") && (id == 0 || offset >= bytes.len()))
            {
                return Err(PdfPreparationError::MalformedPdf);
            }
            if kind == Some("n") {
                live_ids.insert((id as u32, generation as u16));
            }
        }
    }
    let mut dictionary = xref[trailer_start + 7..].to_vec();
    dictionary.extend_from_slice(b"\nESIGNTRAILER");
    let trailer = Content::decode_strict(&dictionary)?;
    if trailer.operations.len() != 1 {
        return Err(PdfPreparationError::MalformedPdf);
    }
    let operation = &trailer.operations[0];
    if operation.operator != "ESIGNTRAILER" || operation.operands.len() != 1 {
        return Err(PdfPreparationError::MalformedPdf);
    }
    let trailer = operation.operands[0].as_dict()?;
    if trailer.has(b"Encrypt") {
        return Err(PdfPreparationError::EncryptedPdf);
    }
    if trailer.has(b"Prev") || trailer.has(b"XRefStm") {
        return Err(PdfPreparationError::UnsupportedPdf);
    }
    let size = trailer.get(b"Size")?.as_i64()?;
    if size <= 0 || size > (MAX_OBJECTS + 1) as i64 {
        return Err(PdfPreparationError::Limit);
    }
    Ok(live_ids)
}
fn integer(value: Option<&str>) -> Result<usize> {
    value
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse().ok())
        .ok_or(PdfPreparationError::MalformedPdf)
}

pub(super) fn exclude_object_streams(
    id: ObjectId,
    object: &mut Object,
) -> Option<(ObjectId, Object)> {
    if object.as_stream().is_ok_and(|s| s.dict.has_type(b"ObjStm")) {
        None
    } else {
        // The loader ignores this returned value for ordinary objects; Null
        // avoids cloning attacker-controlled stream bytes just for admission.
        Some((id, Object::Null))
    }
}
