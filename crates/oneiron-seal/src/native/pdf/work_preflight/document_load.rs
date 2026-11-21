//! Strict document load: the admitted parse of the input plus the
//! object load that expands deferred object streams behind it.

use super::*;

/// The strict parse of `bytes`, each allocation its tables, decodes and
/// snapshots make admitted first on the call's operation ledger, which
/// outlives the document.
pub(crate) fn load(bytes: &[u8], limits: &WorkLimits) -> Result<Document, WorkError> {
    let start = bytes
        .windows(9)
        .rposition(|v| v == b"startxref")
        .ok_or(WorkError::Invalid(InputInvalidCode::MalformedXref))?;
    let mut tail = std::str::from_utf8(&bytes[start + 9..])
        .map_err(|_| WorkError::Invalid(InputInvalidCode::MalformedXref))?
        .split_ascii_whitespace();
    let offset = integer(tail.next(), InputInvalidCode::MalformedXref)?;
    if tail.next() != Some("%%EOF") || tail.next().is_some() || offset >= start {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
    }
    let mut frame = Frame {
        entries: BTreeMap::new(),
        revisions: Vec::new(),
        limits,
        scope: Scope::new(limits.ledger),
    };
    frame.read(bytes, offset)?;
    // Inspect superseded revisions too: rewriting must not erase a prior seal.
    // Each snapshot is the input plus a short startxref trailer, read one at a
    // time into one buffer, however many revisions the file carries; each
    // earlier revision's load gives its memory back before the next.
    {
        let snapshots = Scope::new(limits.ledger);
        let mut snapshot = Vec::new();
        for previous in frame.revisions.iter().skip(1) {
            let trailer = format!("\nstartxref\n{previous}\n%%EOF\n");
            let size = bytes.len() + trailer.len();
            snapshot.clear();
            if size > snapshot.capacity() {
                snapshots.take(size)?;
                snapshot.reserve_exact(size);
            }
            snapshot.extend_from_slice(bytes);
            snapshot.extend_from_slice(trailer.as_bytes());
            let revision = Scope::new(limits.ledger);
            let old = load_objects(&snapshot, limits, revision.admission())?;
            reject_signatures(&old, limits)?;
        }
    }
    let held = Admission {
        ledger: Arc::clone(limits.ledger),
        taken: None,
    };
    let document = load_objects(bytes, limits, held)?;
    for (id, entry) in &frame.entries {
        match entry {
            XrefEntry::Normal { generation, .. } => {
                if !document.objects.contains_key(&(*id, *generation)) {
                    return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
                }
            }
            XrefEntry::Compressed { .. } if !document.objects.contains_key(&(*id, 0)) => {
                return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
            }
            _ => {}
        }
    }
    Ok(document)
}

fn load_objects(
    bytes: &[u8],
    limits: &WorkLimits,
    admission: Admission,
) -> Result<Document, WorkError> {
    let admission: Arc<dyn DecodeAdmission> = Arc::new(admission);
    let mut doc = Document::load_mem_with_options(
        bytes,
        LoadOptions {
            strict: true,
            filter: Some(|id, object| {
                defer_object_streams(object);
                Some((id, Object::Null))
            }),
            // organ: admitted, not refused (FIX 7980)
            max_decompressed_size: limits.stream_decode_bytes,
            decode_admission: Some(admission),
            ..Default::default()
        },
    )
    // organ: admitted, not refused (FIX 7980)
    .map_err(|error| structure_error(limits, &error))?;
    if doc.is_encrypted() || doc.was_encrypted() {
        return Err(WorkError::Invalid(InputInvalidCode::EncryptedPdf));
    }
    let ids: Vec<_> = doc
        .objects
        .iter()
        .filter_map(|(id, object)| {
            object
                .as_stream()
                .ok()
                .filter(|stream| stream.dict.has_type(b"ESignObjectStream"))
                .map(|_| *id)
        })
        .collect();
    for id in ids {
        expand_object_stream(&mut doc, id, limits)?;
    }
    for (id, entry) in &doc.reference_table.entries {
        let key = match entry {
            XrefEntry::Normal { generation, .. } => (*id, *generation),
            XrefEntry::Compressed { .. } => (*id, 0),
            _ => continue,
        };
        if !doc.objects.contains_key(&key) {
            return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
        }
    }
    Ok(doc)
}
