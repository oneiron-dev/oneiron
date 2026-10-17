//! A PDF's streams: each stream object decoded (no filter, or one Flate
//! filter with a PNG predictor, exactly, by the e-sign renderer's decoder;
//! an ASCII85, LZW and Flate chain by lopdf's bounded decoder), and each
//! object stream decoded and expanded here, under the walk's budget. An image
//! codec's bytes are pixels, read only as the file's own bytes are.
//! Every object the cross-reference names must load, and an encrypted PDF is
//! not read. The rebuilt copy writes each object again, a masked stream with
//! its plain bytes; the object streams and the superseded revisions are left
//! out, and the objects an object stream held are written whole.

use lopdf::xref::XrefEntry;
use lopdf::{Document, LoadOptions, Object, ObjectId, ObjectStream, Stream};

use super::{
    Budget, MAX_MEMBER_BYTES, MAX_PDF_OBJECTS, Stop, Walked, encode_failed, over_budget, unreadable,
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
    budget.member()?;
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
            max_decompressed_size: Some(MAX_MEMBER_BYTES),
            ..LoadOptions::default()
        },
    )
    .map_err(read_error)?;
    if document.trailer.has(b"Encrypt") || document.is_encrypted() || document.was_encrypted() {
        return Err(unreadable());
    }
    if document.objects.len() > MAX_PDF_OBJECTS
        || document.reference_table.entries.len() > MAX_PDF_OBJECTS
    {
        return Err(over_budget());
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
        if document.objects.len() > MAX_PDF_OBJECTS {
            return Err(over_budget());
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
        let Ok(stream) = object.as_stream() else {
            continue;
        };
        if framing(stream) {
            continue;
        }
        if let Some(decoded) = decode(stream, budget)? {
            each(step(*id), &decoded, budget)?;
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
        let Some(Ok(stream)) = document.objects.get_mut(&id).map(Object::as_stream_mut) else {
            continue;
        };
        if framing(stream) {
            continue;
        }
        if let Some(decoded) = decode(stream, budget)?
            && let Some(masked) = each(step(id), &decoded, budget)?
        {
            stream.set_plain_content(masked);
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
