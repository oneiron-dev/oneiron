//! Exact xref framing and lossless object-stream expansion before rewriting (FIX 7980/8157).
//!
//! Port of the engine's `render/preflight` (with its `dictionary` child
//! inlined below): each stream decodes admitted, retaining an inspection
//! caller's per-stream codec bound, and the operation ledger admits every
//! table, decode and snapshot before it is allocated. Behavior-identical
//! except admission and bounds: `&Stage` becomes `&WorkLimits`, nested
//! scopes become ledger takes released when the scope ends, and engine
//! `Limit` refuses become the PDF format codes (`TooLarge` for byte
//! offsets past `u32`, `ObjectLimitExceeded` for object addresses past it).

use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use lopdf::content::Content;
use lopdf::xref::XrefEntry;
use lopdf::{
    DecodeAdmission, DecodeAdmissionError, Dictionary, Document, LoadOptions, Object, Stream,
};

use super::work::{WorkError, WorkLimits};
use super::work_source::{reject_inline_images, reject_signatures};
use super::work_streams::decoded_admitted;
use crate::error::InputInvalidCode;
use crate::memory::MemoryLedger;

/// One engine `Stage::nested` scope on the call's operation ledger: what it
/// takes is counted and given back when the scope ends, so the call holds
/// the parse's peak, not its sum.
struct Scope<'a> {
    ledger: &'a Arc<MemoryLedger>,
    taken: Arc<AtomicU64>,
}

impl<'a> Scope<'a> {
    fn new(ledger: &'a Arc<MemoryLedger>) -> Self {
        Self {
            ledger,
            taken: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Admits `bytes` about to be allocated under this scope.
    fn take(&self, bytes: usize) -> Result<(), WorkError> {
        let wide = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.ledger
            .admit_transient(bytes)
            .map_err(WorkError::Memory)?;
        self.taken.fetch_add(wide, Ordering::Relaxed);
        Ok(())
    }

    /// This scope as the admission lopdf's load asks: takes pass through to
    /// the ledger and count here, releases pass through and stop counting.
    fn admission(&self) -> Admission {
        Admission {
            ledger: Arc::clone(self.ledger),
            taken: Some(Arc::clone(&self.taken)),
        }
    }
}

impl Drop for Scope<'_> {
    fn drop(&mut self) {
        self.ledger.release(self.taken.load(Ordering::Relaxed));
    }
}

/// The call's operation ledger as lopdf's decode admission: takes pass
/// through, and count toward `taken` while a scope holds them.
struct Admission {
    ledger: Arc<MemoryLedger>,
    taken: Option<Arc<AtomicU64>>,
}

impl DecodeAdmission for Admission {
    fn admit(&self, bytes: usize) -> Result<(), DecodeAdmissionError> {
        <MemoryLedger as DecodeAdmission>::admit(self.ledger.as_ref(), bytes)?;
        if let Some(taken) = self.taken.as_ref() {
            taken.fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
        }
        Ok(())
    }

    fn release(&self, bytes: usize) {
        <MemoryLedger as DecodeAdmission>::release(self.ledger.as_ref(), bytes);
        if let Some(taken) = self.taken.as_ref() {
            let wide = u64::try_from(bytes).unwrap_or(u64::MAX);
            while taken
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                    Some(held.saturating_sub(wide))
                })
                .is_err()
            {}
        }
    }

    fn decoded(&self, bytes: usize) {
        <MemoryLedger as DecodeAdmission>::decoded(self.ledger.as_ref(), bytes);
    }
}

struct Frame<'a> {
    entries: BTreeMap<u32, XrefEntry>,
    revisions: Vec<usize>,
    limits: &'a WorkLimits<'a>,
    /// The frame's own scope: `entries` is freed when the load returns.
    scope: Scope<'a>,
}

/// What one xref entry takes in a table of them.
const XREF_ENTRY_BYTES: usize =
    (11 * (size_of::<u32>() + size_of::<XrefEntry>()) + 12 * size_of::<usize>() + 64).div_ceil(5);

/// Neutralize ObjStm before lopdf eagerly inflates it. We expand it ourselves
/// with exact Flate checks and exact object indexes.
fn defer_object_streams(object: &mut Object) {
    if let Ok(stream) = object.as_stream_mut()
        && stream.dict.has_type(b"ObjStm")
    {
        stream.dict.set("Type", "ESignObjectStream");
    }
}

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

/// Expands one deferred object stream's objects into the document: the
/// decoded stream is admitted on the call's ledger while its objects are
/// expanded, and every embedded object is checked for signatures.
fn expand_object_stream(
    doc: &mut Document,
    id: (u32, u16),
    limits: &WorkLimits,
) -> Result<(), WorkError> {
    let stream = doc
        .get_object(id)
        .map_err(|error| structure_error(limits, &error))?
        .as_stream()
        .map_err(|error| structure_error(limits, &error))?;
    // organ: admitted, not refused (FIX 7980)
    let decoded = decoded_admitted(stream, limits)?;
    let first = natural(
        limits.ledger,
        stream
            .dict
            .get(b"First")
            .map_err(|error| structure_error(limits, &error))?,
        InputInvalidCode::MalformedPdf,
    )?;
    // N is checked against the header's own tokens below, so no count
    // is reserved ahead of them.
    let count = natural(
        limits.ledger,
        stream
            .dict
            .get(b"N")
            .map_err(|error| structure_error(limits, &error))?,
        InputInvalidCode::MalformedPdf,
    )?;
    if count == 0 || first > decoded.len() {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    let header = std::str::from_utf8(&decoded[..first])
        .map_err(|_| WorkError::Invalid(InputInvalidCode::MalformedPdf))?;
    let mut tokens = header.split_ascii_whitespace();
    let mut index = Vec::new();
    let mut seen = BTreeSet::new();
    for _ in 0..count {
        let object = integer(tokens.next(), InputInvalidCode::MalformedPdf)?;
        let offset = integer(tokens.next(), InputInvalidCode::MalformedPdf)?;
        if object == 0
            || object > u32::MAX as usize
            || !seen.insert(object)
            || offset >= decoded.len() - first
            || index.last().is_some_and(|(_, prev)| *prev >= offset)
        {
            return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
        }
        index.push((object as u32, offset));
    }
    if tokens.next().is_some() {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    for (position, &(number, offset)) in index.iter().enumerate() {
        let end = index
            .get(position + 1)
            .map_or(decoded.len(), |next| first + next.1);
        let object = operand(
            limits.ledger,
            &decoded[first + offset..end],
            InputInvalidCode::MalformedPdf,
        )?;
        // Check every embedded object for signatures, including stale entries.
        // Signature names normally are direct. Full indirect checks follow on doc.
        reject_direct_signature(&object)?;
        if matches!(doc.reference_table.entries.get(&number),
            Some(XrefEntry::Compressed { container, index }) if *container == id.0 && usize::from(*index) == position)
        {
            doc.objects.insert((number, 0), object);
        }
    }
    Ok(())
}

fn reject_direct_signature(object: &Object) -> Result<(), WorkError> {
    fn scan(object: &Object) -> Result<(), WorkError> {
        match object {
            Object::Dictionary(dictionary) => {
                if [b"ByteRange".as_slice(), b"DocMDP", b"FieldMDP"]
                    .iter()
                    .any(|key| dictionary.has(key))
                    || [b"Type".as_slice(), b"FT"].iter().any(|key| {
                        dictionary
                            .get(key)
                            .ok()
                            .and_then(|value| value.as_name().ok())
                            .is_some_and(|name| matches!(name, b"Sig" | b"DocTimeStamp"))
                    })
                {
                    return Err(WorkError::Invalid(InputInvalidCode::ExistingSignature));
                }
                for (_, value) in dictionary {
                    scan(value)?;
                }
            }
            Object::Array(values) => {
                for value in values {
                    scan(value)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    scan(object)
}

impl Frame<'_> {
    /// Reads the xref section at `offset` and every section it chains to
    /// (`/XRefStm` first, then `/Prev`), newest first, as many as the file
    /// holds. A section named twice is a cycle and malformed.
    fn read(&mut self, bytes: &[u8], offset: usize) -> Result<(), WorkError> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![offset];
        while let Some(offset) = pending.pop() {
            if !seen.insert(offset) || offset >= bytes.len() {
                return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
            }
            for previous in self.section(bytes, offset)?.into_iter().rev() {
                pending.push(previous);
            }
        }
        Ok(())
    }

    /// Reads one xref section and returns the sections its trailer chains
    /// to, in the order they are read.
    fn section(&mut self, bytes: &[u8], offset: usize) -> Result<Vec<usize>, WorkError> {
        self.revisions.push(offset);
        let part = &bytes[offset..];
        // The section's own table and stream, freed once it is read.
        let table = Scope::new(self.limits.ledger);
        let mut entries = BTreeMap::new();
        let trailer = if part.starts_with(b"xref") {
            section_table(self.limits.ledger, bytes, offset, &mut entries, &table)?
        } else {
            section_stream(self.limits, bytes, offset, &mut entries, &table)?
        };
        if natural(
            self.limits.ledger,
            trailer
                .get(b"Size")
                .map_err(|error| xref_error(self.limits, &error))?,
            InputInvalidCode::MalformedXref,
        )? > u32::MAX as usize
        {
            return Err(WorkError::Invalid(InputInvalidCode::ObjectLimitExceeded));
        }
        if trailer.has(b"Encrypt") {
            return Err(WorkError::Invalid(InputInvalidCode::EncryptedPdf));
        }
        for (id, entry) in entries {
            if let XrefEntry::Normal { offset, generation } = &entry {
                let header = &bytes[*offset as usize..];
                let end = header
                    .windows(3)
                    .position(|v| v == b"obj")
                    .filter(|v| *v < 64)
                    .ok_or(WorkError::Invalid(InputInvalidCode::MalformedXref))?;
                let mut numbers = std::str::from_utf8(&header[..end])
                    .map_err(|_| WorkError::Invalid(InputInvalidCode::MalformedXref))?
                    .split_ascii_whitespace();
                if integer(numbers.next(), InputInvalidCode::MalformedXref)? != id as usize
                    || integer(numbers.next(), InputInvalidCode::MalformedXref)?
                        != usize::from(*generation)
                    || numbers.next().is_some()
                {
                    return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
                }
            }
            if let std::collections::btree_map::Entry::Vacant(slot) = self.entries.entry(id) {
                self.scope.take(XREF_ENTRY_BYTES)?;
                slot.insert(entry);
            }
        }
        let mut chained = Vec::new();
        for key in [b"XRefStm".as_slice(), b"Prev"] {
            if let Ok(previous) = trailer.get(key) {
                chained.push(natural(
                    self.limits.ledger,
                    previous,
                    InputInvalidCode::MalformedXref,
                )?);
            }
        }
        Ok(chained)
    }
}

/// Reads one classic xref table into `entries` and returns its trailer.
fn section_table(
    ledger: &MemoryLedger,
    bytes: &[u8],
    offset: usize,
    entries: &mut BTreeMap<u32, XrefEntry>,
    scope: &Scope,
) -> Result<Dictionary, WorkError> {
    let part = &bytes[offset..];
    let end = part
        .windows(7)
        .position(|v| v == b"trailer")
        .ok_or(WorkError::Invalid(InputInvalidCode::MalformedXref))?;
    let mut tokens = std::str::from_utf8(&part[4..end])
        .map_err(|_| WorkError::Invalid(InputInvalidCode::MalformedXref))?
        .split_ascii_whitespace();
    while let Some(first) = tokens.next() {
        let first = integer(Some(first), InputInvalidCode::MalformedXref)?;
        let count = integer(tokens.next(), InputInvalidCode::MalformedXref)?;
        subsection(count)?;
        for id in first
            ..first
                .checked_add(count)
                .ok_or(WorkError::Invalid(InputInvalidCode::ObjectLimitExceeded))?
        {
            let offset = integer(tokens.next(), InputInvalidCode::MalformedXref)?;
            let generation = integer(tokens.next(), InputInvalidCode::MalformedXref)?;
            let entry = match tokens.next() {
                Some("n") if offset < bytes.len() && generation <= u16::MAX as usize => {
                    XrefEntry::Normal {
                        offset: offset
                            .try_into()
                            .map_err(|_| WorkError::Invalid(InputInvalidCode::TooLarge))?,
                        generation: generation as u16,
                    }
                }
                Some("f") => XrefEntry::Free,
                _ => return Err(WorkError::Invalid(InputInvalidCode::MalformedXref)),
            };
            insert(entries, id, entry, scope)?;
        }
    }
    Ok(dictionary::leading_dictionary(ledger, &part[end + 7..])?.0)
}

/// Reads one cross-reference stream into `entries` and returns its trailer.
fn section_stream(
    limits: &WorkLimits,
    bytes: &[u8],
    offset: usize,
    entries: &mut BTreeMap<u32, XrefEntry>,
    scope: &Scope,
) -> Result<Dictionary, WorkError> {
    let part = &bytes[offset..];
    let header = part
        .windows(3)
        .position(|v| v == b"obj")
        .filter(|v| *v < 64)
        .ok_or(WorkError::Invalid(InputInvalidCode::MalformedXref))?;
    let (dict, consumed) = dictionary::leading_dictionary(limits.ledger, &part[header + 3..])?;
    if !dict.has_type(b"XRef") {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
    }
    let after = &part[header + 3 + consumed..];
    let after = after
        .strip_prefix(b"\r\n")
        .or_else(|| after.strip_prefix(b"\n"))
        .unwrap_or(after);
    let after = trim_start(after)
        .strip_prefix(b"stream")
        .ok_or(WorkError::Invalid(InputInvalidCode::MalformedXref))?;
    let after = after
        .strip_prefix(b"\r\n")
        .or_else(|| after.strip_prefix(b"\n"))
        .ok_or(WorkError::Invalid(InputInvalidCode::MalformedXref))?;
    let length = natural(
        limits.ledger,
        dict.get(b"Length")
            .map_err(|error| xref_error(limits, &error))?,
        InputInvalidCode::MalformedXref,
    )?;
    let raw = after
        .get(..length)
        .ok_or(WorkError::Invalid(InputInvalidCode::MalformedXref))?;
    if !trim_start(&after[length..]).starts_with(b"endstream") {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
    }
    scope.take(raw.len())?;
    let stream = Stream::new(dict.clone(), raw.to_vec());
    // organ: admitted, not refused (FIX 7980)
    let decoded = decoded_admitted(&stream, limits)?;
    let widths = dict
        .get(b"W")
        .map_err(|error| xref_error(limits, &error))?
        .as_array()
        .map_err(|error| xref_error(limits, &error))?
        .iter()
        .map(|value| natural(limits.ledger, value, InputInvalidCode::MalformedXref))
        .collect::<Result<Vec<_>, _>>()?;
    if widths.len() != 3 || widths.iter().any(|v| *v > 8) || widths.iter().sum::<usize>() == 0 {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
    }
    let size = natural(
        limits.ledger,
        dict.get(b"Size")
            .map_err(|error| xref_error(limits, &error))?,
        InputInvalidCode::MalformedXref,
    )?;
    let index = if let Ok(value) = dict.get(b"Index") {
        value
            .as_array()
            .map_err(|error| xref_error(limits, &error))?
            .iter()
            .map(|value| natural(limits.ledger, value, InputInvalidCode::MalformedXref))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        vec![0, size]
    };
    if index.len() % 2 != 0 {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
    }
    let mut cursor = 0;
    for pair in index.chunks_exact(2) {
        subsection(pair[1])?;
        for id in pair[0]
            ..pair[0]
                .checked_add(pair[1])
                .ok_or(WorkError::Invalid(InputInvalidCode::ObjectLimitExceeded))?
        {
            let (entry, next) = stream_entry(&decoded, cursor, &widths, bytes.len())?;
            cursor = next;
            insert(entries, id, entry, scope)?;
        }
    }
    if cursor != decoded.len() {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
    }
    Ok(dict)
}

/// Reads one cross-reference stream entry at `cursor`: its fields under
/// `widths`, then the entry they frame. Returns the entry and the cursor
/// past its row.
fn stream_entry(
    decoded: &[u8],
    cursor: usize,
    widths: &[usize],
    bytes_len: usize,
) -> Result<(XrefEntry, usize), WorkError> {
    let mut cursor = cursor;
    let mut values = [0u64; 3];
    for (slot, width) in widths.iter().enumerate() {
        let data = decoded
            .get(cursor..cursor + width)
            .ok_or(WorkError::Invalid(InputInvalidCode::MalformedXref))?;
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
        1 if values[1] < bytes_len as u64 => XrefEntry::Normal {
            offset: values[1]
                .try_into()
                .map_err(|_| WorkError::Invalid(InputInvalidCode::TooLarge))?,
            generation: values[2]
                .try_into()
                .map_err(|_| WorkError::Invalid(InputInvalidCode::MalformedXref))?,
        },
        2 => XrefEntry::Compressed {
            container: values[1]
                .try_into()
                .map_err(|_| WorkError::Invalid(InputInvalidCode::ObjectLimitExceeded))?,
            index: values[2]
                .try_into()
                .map_err(|_| WorkError::Invalid(InputInvalidCode::ObjectLimitExceeded))?,
        },
        _ => return Err(WorkError::Invalid(InputInvalidCode::MalformedXref)),
    };
    Ok((entry, cursor))
}

/// An xref subsection names at least one entry. Its entries are read from the
/// section's own bytes, so no count is reserved ahead of them.
fn subsection(count: usize) -> Result<(), WorkError> {
    if count == 0 {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
    }
    Ok(())
}

fn insert(
    entries: &mut BTreeMap<u32, XrefEntry>,
    id: usize,
    entry: XrefEntry,
    scope: &Scope,
) -> Result<(), WorkError> {
    let id =
        u32::try_from(id).map_err(|_| WorkError::Invalid(InputInvalidCode::ObjectLimitExceeded))?;
    scope.take(XREF_ENTRY_BYTES)?;
    if entries.insert(id, entry).is_some() {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
    }
    Ok(())
}

fn natural(
    ledger: &MemoryLedger,
    value: &Object,
    code: InputInvalidCode,
) -> Result<usize, WorkError> {
    value
        .as_i64()
        .map_err(|error| lopdf_error(ledger, &error, code))?
        .try_into()
        .map_err(|_| WorkError::Invalid(code))
}

fn integer(value: Option<&str>, code: InputInvalidCode) -> Result<usize, WorkError> {
    value
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse().ok())
        .ok_or(WorkError::Invalid(code))
}

fn trim_start(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    bytes
}

fn operand(
    ledger: &MemoryLedger,
    bytes: &[u8],
    code: InputInvalidCode,
) -> Result<Object, WorkError> {
    reject_inline_images(bytes)?;
    let mut input = bytes.to_vec();
    input.extend_from_slice(b"\nESIGNOPERAND");
    let mut content =
        Content::decode_strict(&input).map_err(|error| lopdf_error(ledger, &error, code))?;
    if content.operations.len() != 1 {
        return Err(WorkError::Invalid(code));
    }
    let mut operation = content.operations.remove(0);
    if operation.operator != "ESIGNOPERAND" || operation.operands.len() != 1 {
        return Err(WorkError::Invalid(code));
    }
    Ok(operation.operands.remove(0))
}

/// A lopdf read failure as the organ reads it: a kept memory refusal as
/// itself, anything else as `code`, never the reverse.
fn lopdf_error(ledger: &MemoryLedger, error: &lopdf::Error, code: InputInvalidCode) -> WorkError {
    ledger
        .refusal_of(error)
        .map_or(WorkError::Invalid(code), WorkError::Memory)
}

/// A lopdf read failure in xref framing: a kept memory refusal as itself,
/// anything else as a malformed xref.
fn xref_error(limits: &WorkLimits, error: &lopdf::Error) -> WorkError {
    lopdf_error(limits.ledger, error, InputInvalidCode::MalformedXref)
}

/// A lopdf read failure in document structure: a kept memory refusal as
/// itself, anything else as a malformed PDF.
fn structure_error(limits: &WorkLimits, error: &lopdf::Error) -> WorkError {
    lopdf_error(limits.ledger, error, InputInvalidCode::MalformedPdf)
}

mod dictionary {
    //! Linear lexical framing; the PDF parser validates the single bounded operand.

    use lopdf::Dictionary;

    use super::{WorkError, lopdf_error, operand};
    use crate::error::InputInvalidCode;
    use crate::memory::MemoryLedger;

    pub(super) fn leading_dictionary(
        ledger: &MemoryLedger,
        bytes: &[u8],
    ) -> Result<(Dictionary, usize), WorkError> {
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
                _ if !started => {
                    return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
                }
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
                            return Err(WorkError::Invalid(InputInvalidCode::ObjectLimitExceeded));
                        }
                        cursor += 1;
                    }
                    if depth != 0 {
                        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
                    }
                    continue;
                }
                b'<' => {
                    cursor += 1;
                    while cursor < end && bytes[cursor] != b'>' {
                        cursor += 1;
                    }
                    if cursor == end {
                        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
                    }
                }
                b'[' => nesting.push(b']'),
                b']' => {
                    if nesting.pop() != Some(b']') {
                        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
                    }
                }
                b'>' => {
                    if bytes.get(cursor + 1) != Some(&b'>') || nesting.pop() != Some(b'>') {
                        return Err(WorkError::Invalid(InputInvalidCode::MalformedXref));
                    }
                    cursor += 1;
                    if nesting.is_empty() {
                        let object =
                            operand(ledger, &bytes[..=cursor], InputInvalidCode::MalformedXref)?;
                        return Ok((
                            object
                                .as_dict()
                                .map_err(|error| {
                                    lopdf_error(ledger, &error, InputInvalidCode::MalformedXref)
                                })?
                                .clone(),
                            cursor + 1,
                        ));
                    }
                }
                _ => {}
            }
            if nesting.len() > 32 {
                return Err(WorkError::Invalid(InputInvalidCode::ObjectLimitExceeded));
            }
            cursor += 1;
        }
        Err(WorkError::Invalid(InputInvalidCode::MalformedXref))
    }
}
