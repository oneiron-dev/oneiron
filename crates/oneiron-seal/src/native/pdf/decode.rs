//! Strict loads with every stream decoded whole (Rule 5).
//!
//! The loader decodes object and cross-reference streams as it reads them.
//! None is refused on its decoded size: the largest one goes to the
//! invocation's counts, which the host measures against its
//! `seal_stream_decode_bytes` row. Only the PDF format bounds refuse.

use lopdf::{Document, LoadOptions, Object};

use crate::api::{Counter, SealObservations};

/// A strict parse of `bytes`, each stream decoded whole, with the bytes its
/// largest stream decoded to noted in `observed`.
pub(crate) fn load_strict(bytes: &[u8], observed: &SealObservations) -> lopdf::Result<Document> {
    let doc = Document::load_mem_with_options(
        bytes,
        LoadOptions {
            strict: true,
            ..LoadOptions::default()
        },
    )?;
    observed.note(Counter::StreamDecodeBytes, largest_loaded_stream(&doc));
    Ok(doc)
}

/// The bytes the largest stream the loader decoded came to: an object
/// stream's, which the loader leaves decoded in place, or a cross-reference
/// stream's, decoded again here to be measured.
fn largest_loaded_stream(doc: &Document) -> usize {
    doc.objects
        .values()
        .filter_map(|object| object.as_stream().ok())
        .filter_map(
            |stream| match stream.dict.get(b"Type").and_then(Object::as_name) {
                Ok(b"ObjStm") if !stream.is_compressed() => Some(stream.content.len()),
                Ok(b"ObjStm" | b"XRef") => stream
                    .decompressed_content()
                    .ok()
                    .map(|content| content.len()),
                _ => None,
            },
        )
        .max()
        .unwrap_or(0)
}
