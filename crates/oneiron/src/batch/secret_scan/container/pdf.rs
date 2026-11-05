//! Core half of `batch::secret_scan::container::pdf`: its store-layer items live in `oneiron_store::batch::secret_scan::container::pdf` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::secret_scan::container::pdf::*;

use super::{
    Budget, Stop, Walked, encode_failed, expanded_floor, hidden_member, over_budget, unreadable,
};
use crate::blob_artifact::esign::render::{PdfPreparationError, decode_stream};
use crate::file_secret_marks::MemberStep;
use lopdf::xref::XrefEntry;
use lopdf::{Document, LoadOptions, Object, ObjectId, ObjectStream, Stream};

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
        each(objstm_step(id), &decoded, budget)?;
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
                    each(objstm_step(id), &decoded, budget).inspect_err(|_| visited_stop = true)?;
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
        Ok(each(objstm_step(id), &decoded, budget)?.unwrap_or(decoded))
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
            // A content stream's masked bytes run longer or shorter than
            // the key (FIX 11550): the plain write sets its length, and a
            // decoded length with it.
            let len = masked.len();
            stream.set_plain_content(masked);
            if stream.dict.has(b"DL") {
                stream.dict.set("DL", len as i64);
            }
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
