//! A PDF's streams: each stream object decoded (no filter, or one Flate
//! filter with a PNG predictor, exactly, by the e-sign renderer's decoder;
//! an ASCII85, LZW and Flate chain by lopdf's bounded decoder), and each
//! object stream decoded and expanded here, under the walk's budget. An image
//! codec's bytes are pixels, read only as the file's own bytes are.
//! Every object the cross-reference names must load, and an encrypted PDF is
//! not read. The rebuilt copy writes each object again, a masked stream with
//! its plain bytes; the object streams and the superseded revisions are left
//! out, and the objects an object stream held are written whole.
//!
//! Each object's text strings are one member too (FIX 2469): lopdf reads a
//! literal's escapes and a hex string's digits, and each string is read as
//! text after its byte-order mark (UTF-16BE, UTF-8) or in PDFDocEncoding.
//! The rebuilt copy writes a string whose text changed again as lopdf
//! encodes text.
//!
//! A scan reads the superseded revisions too (FIX 2470): the document as
//! each earlier cross-reference the bytes name reads it, each object that
//! differs from the latest's handed as the latest's are.

use lopdf::xref::XrefEntry;
use lopdf::{Document, LoadOptions, Object, ObjectId, ObjectStream, Stream};

use super::{
    Budget, MAX_EXPANDED_BYTES, Stop, Walked, encode_failed, hidden_member, over_budget, unreadable,
};
use crate::blob_artifact::esign::render::{PdfPreparationError, decode_stream};
use crate::secret_custody::MemberStep;

/// The type an object stream carries until this reader expands it: lopdf
/// expands an `ObjStm` as it loads, with no bound over all of them.
const DEFERRED: &[u8] = b"SecretScanObjectStream";

/// Filters whose bytes are pixels: a stream that ends in one is read as the
/// file's own bytes hold it.
const IMAGE_FILTERS: [&[u8]; 4] = [
    b"DCTDecode",
    b"JPXDecode",
    b"CCITTFaxDecode",
    b"JBIG2Decode",
];

/// Filters lopdf decodes in a chain, under a limit. A filter outside these
/// (ASCIIHex, RunLength, Crypt) leaves the PDF unread.
const CHAIN_FILTERS: [&[u8]; 3] = [b"ASCII85Decode", b"LZWDecode", b"FlateDecode"];

/// What parts one string's text from the next in an object's strings
/// member: no text a rule reads runs across it.
const STRING_BREAK: u8 = 0;

/// What escapes a string's own break and escape bytes in an object's
/// strings member (FIX 11551): the member of an object none of whose
/// strings holds a break reads exactly as before.
const STRING_ESCAPE: u8 = 1;

/// The byte an escaped break reads as after the escape.
const ESCAPED_BREAK: u8 = 2;

/// The keywords each cross-reference offset in a PDF's bytes follows.
const XREF_OFFSET_KEYWORDS: [&[u8]; 2] = [b"startxref", b"/Prev"];

fn defer(object: &mut Object) {
    if let Ok(stream) = object.as_stream_mut()
        && stream.dict.has_type(b"ObjStm")
    {
        stream.dict.set("Type", Object::Name(DEFERRED.to_vec()));
    }
}

fn read_error(error: lopdf::Error) -> Stop {
    match error {
        lopdf::Error::Decompress(lopdf::DecompressError::MemoryLimitExceeded { .. }) => {
            over_budget()
        }
        _ => unreadable(),
    }
}

fn step((object, generation): ObjectId) -> MemberStep {
    MemberStep::PdfStream { object, generation }
}

fn strings_step((object, generation): ObjectId) -> MemberStep {
    MemberStep::PdfStrings { object, generation }
}

/// Whether `bytes`' frame parses as a PDF: its header, cross-reference and
/// trailer, no object kept (FIX 2474).
pub(super) fn opens(bytes: &[u8]) -> bool {
    Document::load_mem_with_options(
        bytes,
        LoadOptions {
            filter: Some(|_, _| None),
            max_decompressed_size: Some(MAX_EXPANDED_BYTES),
            ..LoadOptions::default()
        },
    )
    .is_ok()
}

/// A stream's decoded bytes, charged to the walk; `None` for an image
/// codec's.
fn decode(stream: &Stream, budget: &mut Budget) -> Walked<Option<Vec<u8>>> {
    let filters = if stream.dict.has(b"Filter") {
        stream.filters().map_err(|_| unreadable())?
    } else {
        Vec::new()
    };
    if filters
        .last()
        .is_some_and(|last| IMAGE_FILTERS.contains(last))
    {
        return Ok(None);
    }
    let limit = budget.limit();
    let decoded = match filters.as_slice() {
        [] | [b"FlateDecode"] => match decode_stream(stream, limit) {
            Ok(decoded) => decoded,
            Err(PdfPreparationError::Limit) => return Err(over_budget()),
            // A predictor the exact decoder does not take.
            Err(PdfPreparationError::UnsupportedPdf) => stream
                .decompressed_content_with_limit(limit)
                .map_err(read_error)?,
            Err(_) => return Err(unreadable()),
        },
        chain if chain.iter().all(|filter| CHAIN_FILTERS.contains(filter)) => stream
            .decompressed_content_with_limit(limit)
            .map_err(read_error)?,
        _ => return Err(unreadable()),
    };
    budget.spend(decoded.len())?;
    Ok(Some(decoded))
}

/// A stream the reader decodes as part of the file's frame, never as a
/// member: an object stream (read as it loads) and a cross-reference stream.
fn framing(stream: &Stream) -> bool {
    stream.dict.has_type(DEFERRED) || stream.dict.has_type(b"XRef")
}

/// Whether `object` is framing: such a stream, whose strings are no member
/// either.
fn frames(object: &Object) -> bool {
    object.as_stream().is_ok_and(framing)
}

/// The text a string object reads as (FIX 2469): UTF-16BE or UTF-8 after
/// its byte-order mark, else PDFDocEncoding. A unit that does not decode
/// reads as the replacement character.
fn text(string: &Object) -> String {
    let Ok(bytes) = string.as_str() else {
        return String::new();
    };
    if let Some(utf16) = bytes.strip_prefix(b"\xFE\xFF") {
        let units: Vec<u16> = utf16
            .chunks(2)
            .map(|unit| u16::from_be_bytes([unit[0], unit.get(1).copied().unwrap_or(0)]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(utf8) = bytes.strip_prefix(b"\xEF\xBB\xBF") {
        return String::from_utf8_lossy(utf8).into_owned();
    }
    lopdf::decode_text_string(string).unwrap_or_default()
}

/// Each text string `object` holds, in its order: a dictionary's values, an
/// array's items and a stream's dictionary. A reference is not followed.
fn strings_of<'o>(object: &'o Object, found: &mut Vec<&'o Object>) {
    match object {
        Object::String(..) => found.push(object),
        Object::Array(items) => items.iter().for_each(|item| strings_of(item, found)),
        Object::Dictionary(dict) => dict.iter().for_each(|(_, value)| strings_of(value, found)),
        Object::Stream(stream) => stream
            .dict
            .iter()
            .for_each(|(_, value)| strings_of(value, found)),
        _ => {}
    }
}

/// [`strings_of`], each string to write again.
fn strings_of_mut<'o>(object: &'o mut Object, found: &mut Vec<&'o mut Object>) {
    if matches!(object, Object::String(..)) {
        found.push(object);
        return;
    }
    match object {
        Object::Array(items) => items
            .iter_mut()
            .for_each(|item| strings_of_mut(item, found)),
        Object::Dictionary(dict) => dict
            .iter_mut()
            .for_each(|(_, value)| strings_of_mut(value, found)),
        Object::Stream(stream) => stream
            .dict
            .iter_mut()
            .for_each(|(_, value)| strings_of_mut(value, found)),
        _ => {}
    }
}

/// `object`'s text strings as one member: each string's text, in order,
/// [`STRING_BREAK`] between two. `None` when it holds none. When a string
/// holds the break byte itself its member is escaped (FIX 11551): each
/// string's breaks and escapes read escaped, so the breaks between two
/// strings stay the member's only bare ones.
fn strings_member(object: &Object) -> Option<Vec<u8>> {
    let mut strings = Vec::new();
    strings_of(object, &mut strings);
    if strings.is_empty() {
        return None;
    }
    let texts: Vec<String> = strings.iter().map(|string| text(string)).collect();
    let escaped = texts
        .iter()
        .any(|text| text.as_bytes().contains(&STRING_BREAK));
    let mut member = Vec::new();
    for (at, text) in texts.iter().enumerate() {
        if at > 0 {
            member.push(STRING_BREAK);
        }
        if escaped {
            escape_string(text.as_bytes(), &mut member);
        } else {
            member.extend_from_slice(text.as_bytes());
        }
    }
    Some(member)
}

/// `text`'s bytes with each break and each escape escaped (FIX 11551): a
/// break reads as the escape and [`ESCAPED_BREAK`], an escape as itself
/// twice, so an escaped string holds no bare break.
fn escape_string(text: &[u8], out: &mut Vec<u8>) {
    for &byte in text {
        if byte == STRING_BREAK {
            out.extend_from_slice(&[STRING_ESCAPE, ESCAPED_BREAK]);
        } else if byte == STRING_ESCAPE {
            out.extend_from_slice(&[STRING_ESCAPE, STRING_ESCAPE]);
        } else {
            out.push(byte);
        }
    }
}

/// The reverse of [`escape_string`], over one masked part (FIX 11551). An
/// escape the mask overwrote half of reads as its bytes are: never a
/// refusal, and the overwritten bytes stay overwritten.
fn unescape_string(part: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(part.len());
    let mut bytes = part.iter();
    while let Some(&byte) = bytes.next() {
        if byte != STRING_ESCAPE {
            out.push(byte);
            continue;
        }
        match bytes.next().copied() {
            Some(next) if next == STRING_ESCAPE => out.push(STRING_ESCAPE),
            Some(next) if next == ESCAPED_BREAK => out.push(STRING_BREAK),
            Some(next) => {
                out.push(STRING_ESCAPE);
                out.push(next);
            }
            None => out.push(STRING_ESCAPE),
        }
    }
    out
}

/// Writes `masked`, an object's strings member once masked, back into
/// `object`: each string whose text changed, encoded again. A member that no
/// longer parts into the object's strings is a copy no reader here builds.
/// A member an escaped object wrote (FIX 11551) parts the same way, each
/// part unescaped before it is read back; the object still holds its plain
/// strings here, so the escape reads from them exactly as the member did.
fn write_strings(object: &mut Object, masked: &[u8]) -> Walked<()> {
    let mut strings = Vec::new();
    strings_of_mut(object, &mut strings);
    let escaped = strings
        .iter()
        .any(|string| text(string).as_bytes().contains(&STRING_BREAK));
    let parts: Vec<&[u8]> = masked.split(|byte| *byte == STRING_BREAK).collect();
    if parts.len() != strings.len() {
        return Err(unreadable());
    }
    for (string, part) in strings.into_iter().zip(parts) {
        let plain = text(string);
        if escaped {
            let part = unescape_string(part);
            if plain.as_bytes() != part.as_slice() {
                *string = lopdf::text_string(&String::from_utf8_lossy(&part));
            }
        } else if plain.as_bytes() != part {
            *string = lopdf::text_string(&String::from_utf8_lossy(part));
        }
    }
    Ok(())
}

/// The PDF in `bytes`, each object stream expanded from the bytes `carrier`
/// returns for its decoded bytes.
fn load(
    bytes: &[u8],
    budget: &mut Budget,
    carrier: &mut dyn FnMut(ObjectId, Vec<u8>, &mut Budget) -> Walked<Vec<u8>>,
) -> Walked<Document> {
    let mut document = Document::load_mem_with_options(
        bytes,
        LoadOptions {
            filter: Some(|id, object| {
                defer(object);
                Some((id, Object::Null))
            }),
            max_decompressed_size: budget.decompressed_ceiling(),
            ..LoadOptions::default()
        },
    )
    .map_err(read_error)?;
    if document.trailer.has(b"Encrypt") || document.is_encrypted() || document.was_encrypted() {
        return Err(unreadable());
    }
    let carriers: Vec<ObjectId> = document
        .objects
        .iter()
        .filter(|(_, object)| {
            object
                .as_stream()
                .is_ok_and(|stream| stream.dict.has_type(DEFERRED))
        })
        .map(|(id, _)| *id)
        .collect();
    for id in carriers {
        let (decoded, dict) = match document.objects.get(&id).map(Object::as_stream) {
            Some(Ok(stream)) => (decode(stream, budget)?, stream.dict.clone()),
            _ => return Err(unreadable()),
        };
        let decoded = carrier(id, decoded.ok_or_else(unreadable)?, budget)?;
        let mut plain = Stream::new(dict, decoded);
        plain.dict.remove(b"Filter");
        plain.dict.remove(b"DecodeParms");
        let objects = ObjectStream::new(&mut plain)
            .map_err(|_| unreadable())?
            .objects;
        for (held, object) in objects {
            // As lopdf places them: a copy the cross-reference puts in
            // another stream is stale, and a direct object wins.
            let stale = matches!(
                document.reference_table.get(held.0),
                Some(XrefEntry::Compressed { container, .. }) if *container != id.0
            );
            if !stale {
                document.objects.entry(held).or_insert(object);
            }
        }
    }
    // lopdf passes over an object it cannot parse: each one the
    // cross-reference names must be there.
    for (number, entry) in &document.reference_table.entries {
        let id = match entry {
            XrefEntry::Normal { generation, .. } => (*number, *generation),
            XrefEntry::Compressed { .. } => (*number, 0),
            _ => continue,
        };
        if !document.objects.contains_key(&id) {
            return Err(unreadable());
        }
    }
    Ok(document)
}

pub(super) fn members(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<()>,
) -> Walked<()> {
    let mut carrier = |id: ObjectId, decoded: Vec<u8>, budget: &mut Budget| -> Walked<Vec<u8>> {
        each(step(id), &decoded, budget)?;
        Ok(decoded)
    };
    let document = load(bytes, budget, &mut carrier)?;
    for (id, object) in &document.objects {
        if frames(object) {
            continue;
        }
        if let Ok(stream) = object.as_stream()
            && let Some(decoded) = decode(stream, budget)?
        {
            each(step(*id), &decoded, budget)?;
        }
        if let Some(strings) = strings_member(object) {
            each(strings_step(*id), &strings, budget)?;
        }
    }
    if budget.hidden {
        superseded(bytes, &document, budget, each)?;
    }
    Ok(())
}

/// The cross-reference offsets `bytes` name, after each `startxref` and each
/// `/Prev`, in order, each once.
fn xref_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    for keyword in XREF_OFFSET_KEYWORDS {
        let mut from = 0;
        while let Some(found) = bytes
            .get(from..)
            .and_then(|rest| rest.windows(keyword.len()).position(|word| word == keyword))
        {
            let after = from + found + keyword.len();
            let digits: Vec<u8> = bytes[after..]
                .iter()
                .skip_while(|byte| byte.is_ascii_whitespace())
                .take_while(|byte| byte.is_ascii_digit())
                .copied()
                .collect();
            if let Some(offset) = std::str::from_utf8(&digits)
                .ok()
                .and_then(|digits| digits.parse().ok())
            {
                offsets.push(offset);
            }
            from = after;
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

/// Each superseded revision of the PDF `bytes` hold (FIX 2470): the document
/// as the cross-reference at each earlier offset the bytes name reads it,
/// each object that differs from `latest`'s handed to `each` as the latest's
/// are. A revision, stream or member no reader here reads is left to the
/// scan of the file's own bytes; a visitor's stop is the walk's.
fn superseded(
    bytes: &[u8],
    latest: &Document,
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<()>,
) -> Walked<()> {
    for offset in xref_offsets(bytes) {
        if offset == latest.xref_start {
            continue;
        }
        // The loader reads the last `startxref` before the last `%%EOF`.
        let mut view = bytes.to_vec();
        view.extend_from_slice(format!("\nstartxref\n{offset}\n%%EOF\n").as_bytes());
        let mut visited_stop = false;
        let mut carrier =
            |id: ObjectId, decoded: Vec<u8>, budget: &mut Budget| -> Walked<Vec<u8>> {
                if hidden_member(&decoded) {
                    each(step(id), &decoded, budget).inspect_err(|_| visited_stop = true)?;
                }
                Ok(decoded)
            };
        let revision = match load(&view, budget, &mut carrier) {
            Ok(revision) => revision,
            Err(stop @ Stop::Fail(_)) => return Err(stop),
            Err(stop) if visited_stop => return Err(stop),
            Err(Stop::Refuse(_)) => continue,
        };
        for (id, object) in &revision.objects {
            if frames(object) || latest.objects.get(id) == Some(object) {
                continue;
            }
            if let Ok(stream) = object.as_stream() {
                match decode(stream, budget) {
                    Ok(Some(decoded)) if hidden_member(&decoded) => {
                        each(step(*id), &decoded, budget)?;
                    }
                    Ok(_) | Err(Stop::Refuse(_)) => {}
                    Err(stop) => return Err(stop),
                }
            }
            if let Some(strings) = strings_member(object) {
                each(strings_step(*id), &strings, budget)?;
            }
        }
    }
    Ok(())
}

pub(super) fn rebuilt(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<Option<Vec<u8>>>,
) -> Walked<Vec<u8>> {
    let mut carrier = |id: ObjectId, decoded: Vec<u8>, budget: &mut Budget| -> Walked<Vec<u8>> {
        Ok(each(step(id), &decoded, budget)?.unwrap_or(decoded))
    };
    let mut document = load(bytes, budget, &mut carrier)?;
    let ids: Vec<ObjectId> = document.objects.keys().copied().collect();
    for id in ids {
        let Some(object) = document.objects.get_mut(&id) else {
            continue;
        };
        if frames(object) {
            continue;
        }
        if let Ok(stream) = object.as_stream_mut()
            && let Some(decoded) = decode(stream, budget)?
            && let Some(masked) = each(step(id), &decoded, budget)?
        {
            stream.set_plain_content(masked);
        }
        if let Some(strings) = strings_member(object)
            && let Some(masked) = each(strings_step(id), &strings, budget)?
        {
            write_strings(object, &masked)?;
        }
    }
    // A carrier still holds its stored bytes; its objects are written whole.
    document.objects.retain(|_, object| {
        !object
            .as_stream()
            .is_ok_and(|stream| stream.dict.has_type(DEFERRED))
    });
    let mut out = Vec::new();
    document.save_to(&mut out).map_err(|_| encode_failed())?;
    Ok(out)
}
