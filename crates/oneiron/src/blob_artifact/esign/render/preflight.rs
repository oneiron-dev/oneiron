//! Budgeted xref framing and lossless object-stream expansion before rewriting.
use super::streams::decode_stream;
use super::*;
use lopdf::xref::XrefEntry;

struct Frame {
    entries: BTreeMap<u32, XrefEntry>,
    revisions: Vec<usize>,
    nodes: usize,
}

/// Neutralize ObjStm before lopdf eagerly inflates it. We expand it ourselves
/// with an aggregate budget, exact Flate checks, and exact object indexes.
fn defer_object_streams(object: &mut Object) {
    if let Ok(stream) = object.as_stream_mut()
        && stream.dict.has_type(b"ObjStm")
    {
        stream.dict.set("Type", "ESignObjectStream");
    }
}

pub(super) fn load(bytes: &[u8]) -> Result<Document> {
    let start = bytes
        .windows(9)
        .rposition(|v| v == b"startxref")
        .ok_or(PdfPreparationError::MalformedPdf)?;
    let mut tail = std::str::from_utf8(&bytes[start + 9..])
        .map_err(|_| PdfPreparationError::MalformedPdf)?
        .split_ascii_whitespace();
    let offset = integer(tail.next())?;
    if tail.next() != Some("%%EOF") || tail.next().is_some() || offset >= start {
        return Err(PdfPreparationError::MalformedPdf);
    }
    let mut frame = Frame {
        entries: BTreeMap::new(),
        revisions: Vec::new(),
        nodes: 0,
    };
    frame.read(bytes, offset, &mut BTreeSet::new())?;
    let mut remaining = MAX_OUTPUT;
    // Inspect superseded revisions too: rewriting must not erase a prior seal.
    for previous in frame.revisions.iter().skip(1) {
        let mut snapshot = bytes.to_vec();
        snapshot.extend_from_slice(format!("\nstartxref\n{previous}\n%%EOF\n").as_bytes());
        let old = load_objects(&snapshot, &mut remaining)?;
        reject_signatures(&old)?;
    }
    let document = load_objects(bytes, &mut remaining)?;
    for (id, entry) in &frame.entries {
        match entry {
            XrefEntry::Normal { generation, .. } => {
                if !document.objects.contains_key(&(*id, *generation)) {
                    return Err(PdfPreparationError::MalformedPdf);
                }
            }
            XrefEntry::Compressed { .. } if !document.objects.contains_key(&(*id, 0)) => {
                return Err(PdfPreparationError::MalformedPdf);
            }
            _ => {}
        }
    }
    Ok(document)
}

fn load_objects(bytes: &[u8], remaining: &mut usize) -> Result<Document> {
    let mut doc = Document::load_mem_with_options(
        bytes,
        LoadOptions {
            strict: true,
            filter: Some(|id, object| {
                defer_object_streams(object);
                Some((id, Object::Null))
            }),
            max_decompressed_size: Some(MAX_INPUT),
            ..Default::default()
        },
    )?;
    if doc.is_encrypted() || doc.was_encrypted() {
        return Err(PdfPreparationError::EncryptedPdf);
    }
    if doc.reference_table.entries.len() > MAX_OBJECTS || doc.objects.len() > MAX_OBJECTS {
        return Err(PdfPreparationError::Limit);
    }
    let ids: Vec<_> = doc
        .objects
        .iter()
        .filter_map(|(id, o)| {
            o.as_stream()
                .ok()
                .filter(|s| s.dict.has_type(b"ESignObjectStream"))
                .map(|_| *id)
        })
        .collect();
    for id in ids {
        let stream = doc.get_object(id)?.as_stream()?;
        let decoded = decode_stream(stream, (*remaining).min(MAX_INPUT))?;
        *remaining = remaining
            .checked_sub(decoded.len())
            .ok_or(PdfPreparationError::Limit)?;
        let first = natural(stream.dict.get(b"First")?)?;
        let count = natural(stream.dict.get(b"N")?)?;
        if count == 0 || count > MAX_OBJECTS || first > decoded.len() {
            return Err(PdfPreparationError::MalformedPdf);
        }
        let header = std::str::from_utf8(&decoded[..first])
            .map_err(|_| PdfPreparationError::MalformedPdf)?;
        let mut tokens = header.split_ascii_whitespace();
        let mut index = Vec::new();
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let object = integer(tokens.next())?;
            let offset = integer(tokens.next())?;
            if object == 0
                || object > u32::MAX as usize
                || !seen.insert(object)
                || offset >= decoded.len() - first
                || index.last().is_some_and(|(_, prev)| *prev >= offset)
            {
                return Err(PdfPreparationError::MalformedPdf);
            }
            index.push((object as u32, offset));
        }
        if tokens.next().is_some() {
            return Err(PdfPreparationError::MalformedPdf);
        }
        for (position, &(number, offset)) in index.iter().enumerate() {
            let end = index
                .get(position + 1)
                .map_or(decoded.len(), |v| first + v.1);
            let object = operand(&decoded[first + offset..end])?;
            // Check every embedded object for signatures, including stale entries.
            // Signature names normally are direct. Full indirect checks follow on doc.
            reject_direct_signature(&object)?;
            if matches!(doc.reference_table.entries.get(&number),
                Some(XrefEntry::Compressed { container, index }) if *container == id.0 && usize::from(*index) == position)
            {
                doc.objects.insert((number, 0), object);
            }
            if doc.objects.len() > MAX_OBJECTS {
                return Err(PdfPreparationError::Limit);
            }
        }
    }
    for (id, entry) in &doc.reference_table.entries {
        let key = match entry {
            XrefEntry::Normal { generation, .. } => (*id, *generation),
            XrefEntry::Compressed { .. } => (*id, 0),
            _ => continue,
        };
        if !doc.objects.contains_key(&key) {
            return Err(PdfPreparationError::MalformedPdf);
        }
    }
    Ok(doc)
}
fn reject_direct_signature(object: &Object) -> Result<()> {
    fn scan(o: &Object) -> Result<()> {
        match o {
            Object::Dictionary(d) => {
                if [b"ByteRange".as_slice(), b"DocMDP", b"FieldMDP"]
                    .iter()
                    .any(|k| d.has(k))
                    || [b"Type".as_slice(), b"FT"].iter().any(|k| {
                        d.get(k)
                            .ok()
                            .and_then(|o| o.as_name().ok())
                            .is_some_and(|n| matches!(n, b"Sig" | b"DocTimeStamp"))
                    })
                {
                    return Err(PdfPreparationError::AlreadySigned);
                }
                for (_, v) in d {
                    scan(v)?;
                }
            }
            Object::Array(v) => {
                for o in v {
                    scan(o)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    scan(object)
}

impl Frame {
    fn read(&mut self, bytes: &[u8], offset: usize, seen: &mut BTreeSet<usize>) -> Result<()> {
        if !seen.insert(offset) || seen.len() > 32 || offset >= bytes.len() {
            return Err(PdfPreparationError::MalformedPdf);
        }
        self.revisions.push(offset);
        let part = &bytes[offset..];
        let mut entries = BTreeMap::new();
        let trailer = if part.starts_with(b"xref") {
            let end = part
                .windows(7)
                .position(|v| v == b"trailer")
                .ok_or(PdfPreparationError::MalformedPdf)?;
            let mut tokens = std::str::from_utf8(&part[4..end])
                .map_err(|_| PdfPreparationError::MalformedPdf)?
                .split_ascii_whitespace();
            while let Some(first) = tokens.next() {
                let first = integer(Some(first))?;
                let count = integer(tokens.next())?;
                self.charge(count)?;
                for id in first..first.checked_add(count).ok_or(PdfPreparationError::Limit)? {
                    let offset = integer(tokens.next())?;
                    let generation = integer(tokens.next())?;
                    let entry = match tokens.next() {
                        Some("n") if offset < bytes.len() && generation <= u16::MAX as usize => {
                            XrefEntry::Normal {
                                offset: offset
                                    .try_into()
                                    .map_err(|_| PdfPreparationError::Limit)?,
                                generation: generation as u16,
                            }
                        }
                        Some("f") => XrefEntry::Free,
                        _ => return Err(PdfPreparationError::MalformedPdf),
                    };
                    insert(&mut entries, id, entry)?;
                }
            }
            leading_dictionary(&part[end + 7..])?.0
        } else {
            let header = part
                .windows(3)
                .position(|v| v == b"obj")
                .filter(|v| *v < 64)
                .ok_or(PdfPreparationError::MalformedPdf)?;
            let (dict, consumed) = leading_dictionary(&part[header + 3..])?;
            if !dict.has_type(b"XRef") {
                return Err(PdfPreparationError::MalformedPdf);
            }
            let after = &part[header + 3 + consumed..];
            let after = after
                .strip_prefix(b"\r\n")
                .or_else(|| after.strip_prefix(b"\n"))
                .unwrap_or(after);
            let after = trim_start(after)
                .strip_prefix(b"stream")
                .ok_or(PdfPreparationError::MalformedPdf)?;
            let after = after
                .strip_prefix(b"\r\n")
                .or_else(|| after.strip_prefix(b"\n"))
                .ok_or(PdfPreparationError::MalformedPdf)?;
            let length = natural(dict.get(b"Length")?)?;
            let raw = after
                .get(..length)
                .ok_or(PdfPreparationError::MalformedPdf)?;
            if !trim_start(&after[length..]).starts_with(b"endstream") {
                return Err(PdfPreparationError::MalformedPdf);
            }
            let decoded = decode_stream(&Stream::new(dict.clone(), raw.to_vec()), MAX_INPUT)?;
            let widths = dict
                .get(b"W")?
                .as_array()?
                .iter()
                .map(natural)
                .collect::<Result<Vec<_>>>()?;
            if widths.len() != 3
                || widths.iter().any(|v| *v > 8)
                || widths.iter().sum::<usize>() == 0
            {
                return Err(PdfPreparationError::MalformedPdf);
            }
            let size = natural(dict.get(b"Size")?)?;
            let index = if let Ok(value) = dict.get(b"Index") {
                value
                    .as_array()?
                    .iter()
                    .map(natural)
                    .collect::<Result<Vec<_>>>()?
            } else {
                vec![0, size]
            };
            if index.len() % 2 != 0 {
                return Err(PdfPreparationError::MalformedPdf);
            }
            let mut cursor = 0;
            for pair in index.chunks_exact(2) {
                self.charge(pair[1])?;
                for id in pair[0]
                    ..pair[0]
                        .checked_add(pair[1])
                        .ok_or(PdfPreparationError::Limit)?
                {
                    let mut values = [0u64; 3];
                    for (slot, width) in widths.iter().enumerate() {
                        let data = decoded
                            .get(cursor..cursor + width)
                            .ok_or(PdfPreparationError::MalformedPdf)?;
                        for b in data {
                            values[slot] = (values[slot] << 8) | u64::from(*b);
                        }
                        cursor += width;
                    }
                    if widths[0] == 0 {
                        values[0] = 1;
                    }
                    let entry = match values[0] {
                        0 => XrefEntry::Free,
                        1 if values[1] < bytes.len() as u64 => XrefEntry::Normal {
                            offset: values[1]
                                .try_into()
                                .map_err(|_| PdfPreparationError::Limit)?,
                            generation: values[2]
                                .try_into()
                                .map_err(|_| PdfPreparationError::MalformedPdf)?,
                        },
                        2 => XrefEntry::Compressed {
                            container: values[1]
                                .try_into()
                                .map_err(|_| PdfPreparationError::Limit)?,
                            index: values[2]
                                .try_into()
                                .map_err(|_| PdfPreparationError::Limit)?,
                        },
                        _ => return Err(PdfPreparationError::MalformedPdf),
                    };
                    insert(&mut entries, id, entry)?;
                }
            }
            if cursor != decoded.len() {
                return Err(PdfPreparationError::MalformedPdf);
            }
            dict
        };
        if natural(trailer.get(b"Size")?)? > u32::MAX as usize {
            return Err(PdfPreparationError::Limit);
        }
        if trailer.has(b"Encrypt") {
            return Err(PdfPreparationError::EncryptedPdf);
        }
        for (id, entry) in entries {
            if let XrefEntry::Normal { offset, generation } = &entry {
                let header = &bytes[*offset as usize..];
                let end = header
                    .windows(3)
                    .position(|v| v == b"obj")
                    .filter(|v| *v < 64)
                    .ok_or(PdfPreparationError::MalformedPdf)?;
                let mut numbers = std::str::from_utf8(&header[..end])
                    .map_err(|_| PdfPreparationError::MalformedPdf)?
                    .split_ascii_whitespace();
                if integer(numbers.next())? != id as usize
                    || integer(numbers.next())? != usize::from(*generation)
                    || numbers.next().is_some()
                {
                    return Err(PdfPreparationError::MalformedPdf);
                }
            }
            self.entries.entry(id).or_insert(entry);
        }
        for key in [b"XRefStm".as_slice(), b"Prev"] {
            if let Ok(previous) = trailer.get(key) {
                self.read(bytes, natural(previous)?, seen)?;
            }
        }
        Ok(())
    }
    fn charge(&mut self, count: usize) -> Result<()> {
        self.nodes = self
            .nodes
            .checked_add(count)
            .ok_or(PdfPreparationError::Limit)?;
        if count == 0 || self.nodes > MAX_OBJECTS {
            return Err(PdfPreparationError::Limit);
        }
        Ok(())
    }
}
fn insert(entries: &mut BTreeMap<u32, XrefEntry>, id: usize, entry: XrefEntry) -> Result<()> {
    let id = u32::try_from(id).map_err(|_| PdfPreparationError::Limit)?;
    if entries.insert(id, entry).is_some() {
        return Err(PdfPreparationError::MalformedPdf);
    }
    Ok(())
}
fn natural(value: &Object) -> Result<usize> {
    value
        .as_i64()?
        .try_into()
        .map_err(|_| PdfPreparationError::MalformedPdf)
}
fn integer(value: Option<&str>) -> Result<usize> {
    value
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse().ok())
        .ok_or(PdfPreparationError::MalformedPdf)
}
fn trim_start(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    bytes
}
fn operand(bytes: &[u8]) -> Result<Object> {
    source::reject_inline_images(bytes)?;
    let mut input = bytes.to_vec();
    input.extend_from_slice(b"\nESIGNOPERAND");
    let mut content = Content::decode_strict(&input)?;
    if content.operations.len() != 1 {
        return Err(PdfPreparationError::MalformedPdf);
    }
    let mut operation = content.operations.remove(0);
    if operation.operator != "ESIGNOPERAND" || operation.operands.len() != 1 {
        return Err(PdfPreparationError::MalformedPdf);
    }
    Ok(operation.operands.remove(0))
}
fn leading_dictionary(bytes: &[u8]) -> Result<(Dictionary, usize)> {
    // Let the PDF parser recognize strings, escaped names and nested dictionaries.
    // A candidate ending inside a string is not a complete single operand.
    for (end, _) in bytes
        .iter()
        .enumerate()
        .take(64 * 1024)
        .filter(|(i, _)| *i > 0 && bytes[*i - 1..=*i] == *b">>")
    {
        if let Ok(Object::Dictionary(dict)) = operand(&bytes[..=end]) {
            return Ok((dict, end + 1));
        }
    }
    Err(PdfPreparationError::MalformedPdf)
}
