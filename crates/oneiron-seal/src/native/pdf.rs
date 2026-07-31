//! Read-only PDF parse plus byte-exact incremental-update writer (§7.1, §7.2).
//!
//! `lopdf` is used only to inspect objects and references. Signed-output
//! bytes are emitted by the writer here; every pre-existing input byte is
//! preserved and all changes are appended revisions.

use lopdf::{Dictionary, Document, LoadOptions, Object, ObjectId};

use crate::api::SealResourceLimits;
use crate::error::{FatalCode, InputInvalidCode, SealError, SealStage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XrefStyle {
    Table,
    Stream,
}

/// Trailer/xref state needed to append one incremental revision.
#[derive(Debug, Clone)]
pub(crate) struct RevisionState {
    pub max_obj: u32,
    pub root: ObjectId,
    pub info: Option<ObjectId>,
    pub id: Option<Vec<Object>>,
    pub prev_startxref: u64,
    pub xref_style: XrefStyle,
    pub acroform: Option<ObjectId>,
    pub acroform_fields: Vec<Object>,
    pub first_page: ObjectId,
    pub root_dict: Dictionary,
    pub acroform_dict: Option<Dictionary>,
}

/// Prepared input: validated bytes plus the revision state.
#[derive(Debug)]
pub(crate) struct PreparedInput {
    pub bytes: Vec<u8>,
    pub state: RevisionState,
}

fn fatal_pdf(code: FatalCode) -> SealError {
    SealError::Fatal {
        stage: SealStage::PdfIncrementalUpdate,
        code,
    }
}

fn input_invalid(code: InputInvalidCode) -> SealError {
    SealError::InputInvalid { code }
}

fn name_is(obj: &Object, expected: &[u8]) -> bool {
    matches!(obj, Object::Name(n) if n == expected)
}

fn deref_dict<'d>(doc: &'d Document, obj: &'d Object) -> Option<&'d Dictionary> {
    match obj {
        Object::Dictionary(d) => Some(d),
        Object::Reference(r) => doc.get_object(*r).ok().and_then(|o| o.as_dict().ok()),
        _ => None,
    }
}

/// Scan every object for prepared-input contract violations (§7.1 rules 6-7).
fn scan_objects(doc: &Document) -> Result<(), SealError> {
    for obj in doc.objects.values() {
        let Some(dict) = deref_dict(doc, obj) else { continue };
        if let Ok(t) = dict.get(b"Type") {
            if name_is(t, b"Sig") {
                return Err(input_invalid(InputInvalidCode::ExistingSignature));
            }
            if name_is(t, b"Filespec") {
                return Err(input_invalid(InputInvalidCode::EmbeddedFilePresent));
            }
        }
        if dict.get(b"FT").is_ok_and(|ft| name_is(ft, b"Sig")) {
            return Err(input_invalid(InputInvalidCode::ExistingSignature));
        }
        if dict.has(b"AA") {
            return Err(input_invalid(InputInvalidCode::ActiveContentPresent));
        }
        if dict.has(b"Lock") {
            return Err(input_invalid(InputInvalidCode::ExistingSignature));
        }
        if dict
            .get(b"S")
            .is_ok_and(|s| name_is(s, b"JavaScript") || name_is(s, b"Launch"))
        {
            return Err(input_invalid(InputInvalidCode::ActiveContentPresent));
        }
    }
    Ok(())
}

/// Catalog-level checks: OpenAction, /Names JavaScript + EmbeddedFiles,
/// DocMDP/FieldMDP in /Perms.
fn scan_catalog(doc: &Document, root: &Dictionary) -> Result<(), SealError> {
    if root.has(b"OpenAction") {
        return Err(input_invalid(InputInvalidCode::ActiveContentPresent));
    }
    if let Ok(names) = root.get(b"Names")
        && let Some(nd) = deref_dict(doc, names)
    {
        if nd.has(b"JavaScript") {
            return Err(input_invalid(InputInvalidCode::ActiveContentPresent));
        }
        if nd.has(b"EmbeddedFiles") {
            return Err(input_invalid(InputInvalidCode::EmbeddedFilePresent));
        }
    }
    if let Ok(perms) = root.get(b"Perms")
        && let Some(pd) = deref_dict(doc, perms)
        && (pd.has(b"DocMDP") || pd.has(b"FieldMDP") || pd.has(b"UR3"))
    {
        return Err(input_invalid(InputInvalidCode::ExistingSignature));
    }
    Ok(())
}

/// Offset recorded by the last `startxref` marker in the byte buffer.
fn last_startxref(bytes: &[u8]) -> Result<u64, SealError> {
    const MARKER: &[u8] = b"startxref";
    let i = bytes
        .windows(MARKER.len())
        .rposition(|window| window == MARKER)
        .ok_or_else(|| fatal_pdf(FatalCode::PdfInvariantFailed))?;
    let rest = &bytes[i + MARKER.len()..];
    let mut num = 0u64;
    let mut seen = false;
    for &b in rest {
        match b {
            b'0'..=b'9' => {
                seen = true;
                num = num
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(u64::from(b - b'0')))
                    .ok_or_else(|| fatal_pdf(FatalCode::PdfInvariantFailed))?;
            }
            _ if seen => break,
            b' ' | b'\r' | b'\n' | b'\t' if !seen => continue,
            _ => break,
        }
    }
    if seen {
        Ok(num)
    } else {
        Err(fatal_pdf(FatalCode::PdfInvariantFailed))
    }
}

/// Classic-table vs xref-stream detection at the last startxref target.
fn detect_xref_style(bytes: &[u8], startxref: u64) -> XrefStyle {
    let at = usize::try_from(startxref).unwrap_or(0);
    if bytes.len() >= at + 4 && &bytes[at..at + 4] == b"xref" {
        XrefStyle::Table
    } else {
        XrefStyle::Stream
    }
}

fn ref_of(obj: &Object) -> Option<ObjectId> {
    match obj {
        Object::Reference(r) => Some(*r),
        _ => None,
    }
}

/// Extract the trailer/xref revision state from a parsed document.
fn revision_state(doc: &Document, bytes: &[u8]) -> Result<RevisionState, SealError> {
    let trailer = &doc.trailer;
    let root = trailer
        .get(b"Root")
        .ok()
        .and_then(ref_of)
        .ok_or_else(|| fatal_pdf(FatalCode::PdfInvariantFailed))?;
    let info = trailer.get(b"Info").ok().and_then(ref_of);
    let id = match trailer.get(b"ID") {
        Ok(Object::Array(a)) => Some(a.clone()),
        _ => None,
    };
    let prev = last_startxref(bytes)?;
    let pages = doc.get_pages();
    let first_page = *pages
        .values()
        .next()
        .ok_or_else(|| input_invalid(InputInvalidCode::MissingPage))?;
    let root_dict = doc
        .get_object(root)
        .ok()
        .and_then(|o| o.as_dict().ok())
        .ok_or_else(|| fatal_pdf(FatalCode::PdfInvariantFailed))?;
    let acroform = root_dict.get(b"AcroForm").ok().and_then(ref_of);
    let acroform_dict = acroform
        .and_then(|a| doc.get_object(a).ok())
        .and_then(|o| o.as_dict().ok())
        .cloned();
    let acroform_fields = acroform_dict
        .as_ref()
        .and_then(|d| d.get(b"Fields").ok())
        .and_then(|f| f.as_array().ok().cloned())
        .unwrap_or_default();
    let max_obj = doc
        .objects
        .keys()
        .map(|(num, _)| *num)
        .max()
        .unwrap_or(0);
    Ok(RevisionState {
        max_obj,
        root,
        info,
        id,
        prev_startxref: prev,
        xref_style: detect_xref_style(bytes, prev),
        acroform,
        acroform_fields,
        first_page,
        root_dict: root_dict.clone(),
        acroform_dict,
    })
}

/// §7.1 rule 2: reject malformed or repaired xref structures. Every
/// uncompressed in-use xref entry must point at its object header; a reader
/// that silently skipped unloadable objects leaves exactly this signature.
fn xref_offsets_consistent(doc: &Document, bytes: &[u8]) -> bool {
    doc.reference_table
        .entries
        .iter()
        .all(|(id, entry)| match entry {
            lopdf::xref::XrefEntry::Normal { offset, generation } => {
                let off = usize::try_from(*offset).unwrap_or(usize::MAX);
                let header = format!("{id} {generation} obj");
                bytes
                    .get(off..off + header.len())
                    .is_some_and(|w| w == header.as_bytes())
            }
            _ => true,
        })
}

fn load_strict(bytes: &[u8], limits: &SealResourceLimits) -> Result<Document, SealError> {
    let options = LoadOptions {
        strict: true,
        max_decompressed_size: Some(limits.max_input_bytes),
        ..LoadOptions::default()
    };
    Document::load_mem_with_options(bytes, options)
        .map_err(|_| input_invalid(InputInvalidCode::MalformedXref))
}

/// Full prepared-input validation (§7.1). Rejects instead of signing any
/// input that violates the upstream preparation contract.
pub(crate) fn validate_prepared(
    bytes: &[u8],
    limits: &SealResourceLimits,
) -> Result<PreparedInput, SealError> {
    if bytes.is_empty() {
        return Err(input_invalid(InputInvalidCode::Empty));
    }
    if bytes.len() > limits.max_input_bytes {
        return Err(input_invalid(InputInvalidCode::TooLarge));
    }
    if !bytes.starts_with(b"%PDF-") {
        return Err(input_invalid(InputInvalidCode::NotPdf));
    }
    let doc = load_strict(bytes, limits)?;
    if doc.is_encrypted() || doc.was_encrypted() {
        return Err(input_invalid(InputInvalidCode::EncryptedPdf));
    }
    if doc.trailer.has(b"XRefStm") {
        return Err(input_invalid(InputInvalidCode::UnsupportedHybridXref));
    }
    if doc.objects.len() > limits.max_pdf_objects {
        return Err(input_invalid(InputInvalidCode::ObjectLimitExceeded));
    }
    if !xref_offsets_consistent(&doc, bytes) {
        return Err(input_invalid(InputInvalidCode::MalformedXref));
    }
    if doc.get_pages().is_empty() {
        return Err(input_invalid(InputInvalidCode::MissingPage));
    }
    scan_objects(&doc)?;
    let root_id = doc
        .trailer
        .get(b"Root")
        .ok()
        .and_then(ref_of)
        .ok_or_else(|| input_invalid(InputInvalidCode::MalformedXref))?;
    let root_dict = doc
        .get_object(root_id)
        .ok()
        .and_then(|o| o.as_dict().ok())
        .ok_or_else(|| input_invalid(InputInvalidCode::MalformedXref))?;
    scan_catalog(&doc, root_dict)?;
    let state = revision_state(&doc, bytes)?;
    Ok(PreparedInput {
        bytes: bytes.to_vec(),
        state,
    })
}

/// Lighter re-parse for stacking later revisions (DSS, DocTimeStamp) on top
/// of a candidate revision this engine just produced. Skips the prepared
/// content checks — those ran once on the original input.
pub(crate) fn reparse_revision(
    bytes: &[u8],
    limits: &SealResourceLimits,
) -> Result<RevisionState, SealError> {
    let doc = load_strict(bytes, limits)
        .map_err(|_| fatal_pdf(FatalCode::PdfInvariantFailed))?;
    revision_state(&doc, bytes)
}

// ---------------------------------------------------------------------------
// Byte-exact incremental writer
// ---------------------------------------------------------------------------

const BYTERANGE_DIGITS: usize = 20;

/// Serialize the subset of PDF objects the writer re-emits (catalog and
/// AcroForm updates). Streams are never re-emitted; existing stream objects
/// stay reachable by reference.
fn write_object(obj: &Object, out: &mut Vec<u8>) -> Result<(), SealError> {
    match obj {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Object::Integer(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Object::Real(r) => out.extend_from_slice(format!("{r:.6}").as_bytes()),
        Object::Name(n) => write_name(n, out),
        Object::String(s, _) => write_hex_string(s, out),
        Object::Array(a) => {
            out.push(b'[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_object(item, out)?;
            }
            out.push(b']');
        }
        Object::Dictionary(d) => {
            out.extend_from_slice(b"<< ");
            for (k, v) in d {
                write_name(k, out);
                out.push(b' ');
                write_object(v, out)?;
                out.push(b' ');
            }
            out.extend_from_slice(b">>");
        }
        Object::Reference(r) => {
            out.extend_from_slice(format!("{} {} R", r.0, r.1).as_bytes());
        }
        Object::Stream(_) => return Err(fatal_pdf(FatalCode::PdfInvariantFailed)),
    }
    Ok(())
}

fn write_name(name: &[u8], out: &mut Vec<u8>) {
    out.push(b'/');
    for &b in name {
        let safe = b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+' | b'*');
        if safe {
            out.push(b);
        } else {
            out.extend_from_slice(format!("#{b:02X}").as_bytes());
        }
    }
}

fn write_hex_string(data: &[u8], out: &mut Vec<u8>) {
    out.push(b'<');
    for &b in data {
        out.extend_from_slice(format!("{b:02X}").as_bytes());
    }
    out.push(b'>');
}

/// Literal-string escape for `/T` field names and `/M` dates.
fn write_literal_string(data: &str, out: &mut Vec<u8>) {
    out.push(b'(');
    for &b in data.as_bytes() {
        match b {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            _ => out.push(b),
        }
    }
    out.push(b')');
}

/// Which kind of revision the writer appends.
#[derive(Debug)]
pub(crate) enum RevisionKind {
    /// Invisible signature field + widget + AcroForm update + sig dictionary.
    Signature { field_name: String, date_str: String },
    /// DSS dictionary plus validation-material stream objects, and a catalog
    /// update pointing at it. No signature dictionary in this revision.
    Dss { material_objects: Vec<(u32, Vec<u8>)>, dss_obj: u32 },
    /// Archival document timestamp: sig dictionary only, no field/widget.
    DocumentTimestamp,
}

/// A candidate revision with placeholders, ready for ByteRange/Contents
/// patching.
#[derive(Debug)]
pub(crate) struct DraftRevision {
    pub bytes: Vec<u8>,
    /// Offsets of the `<` and `>` delimiting the `/Contents` hex gap.
    pub contents_gap: Option<(usize, usize)>,
    pub byte_range: Option<[u64; 4]>,
}

#[derive(Clone)]
struct ObjOut {
    num: u32,
    generation: u16,
    offset: u64,
}

fn sig_dict_body(
    kind_is_ts: bool,
    date_str: Option<&str>,
    capacity: usize,
) -> (Vec<u8>, usize, usize) {
    // Returns (body, byterange_patch_rel, contents_lt_rel).
    let mut body = Vec::with_capacity(capacity * 2 + 256);
    body.extend_from_slice(b"<< /Type ");
    body.extend_from_slice(if kind_is_ts { b"/DocTimeStamp" } else { b"/Sig" });
    body.extend_from_slice(b" /Filter /Adobe.PPKLite /SubFilter ");
    body.extend_from_slice(if kind_is_ts {
        b"/ETSI.RFC3161"
    } else {
        b"/ETSI.CAdES.detached"
    });
    if let Some(d) = date_str {
        body.extend_from_slice(b" /M ");
        write_literal_string(d, &mut body);
    }
    body.extend_from_slice(b" /ByteRange [0 ");
    let br_rel = body.len();
    for i in 0..3 {
        body.extend_from_slice(b"00000000000000000000");
        if i < 2 {
            body.push(b' ');
        }
    }
    body.extend_from_slice(b"] /Contents <");
    let lt_rel = body.len() - 1;
    body.extend(std::iter::repeat_n(b'0', capacity * 2));
    body.extend_from_slice(b"> >>");
    (body, br_rel, lt_rel)
}

/// Build the new/updated indirect objects for one revision. Returns
/// `(object number, generation, body)` triples plus the sig-dict-relative
/// placeholder offsets when the revision carries a signature dictionary.
#[allow(clippy::too_many_lines)]
type NewObjects = (Vec<(u32, u16, Vec<u8>)>, Option<(u32, usize, usize)>);

fn build_objects(
    state: &RevisionState,
    kind: &RevisionKind,
    capacity: usize,
) -> Result<NewObjects, SealError> {
    let mut next = state.max_obj + 1;
    let mut objs: Vec<(u32, u16, Vec<u8>)> = Vec::new();
    let mut sig_info = None;
    match kind {
        RevisionKind::Signature { field_name, date_str } => {
            let (sig_body, br_rel, lt_rel) = sig_dict_body(false, Some(date_str), capacity);
            let sig_num = next;
            next += 1;
            let field_num = next;
            next += 1;
            let widget_num = next;
            next += 1;
            let mut field = Vec::new();
            field.extend_from_slice(b"<< /FT /Sig /T ");
            write_literal_string(field_name, &mut field);
            field.extend_from_slice(
                format!(" /V {sig_num} 0 R /Kids [{widget_num} 0 R] >>").as_bytes(),
            );
            let widget = format!(
                "<< /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /F 4 \
                 /P {} {} R /Parent {field_num} 0 R >>",
                state.first_page.0, state.first_page.1
            );
            objs.push((sig_num, 0, sig_body));
            objs.push((field_num, 0, field));
            objs.push((widget_num, 0, widget.into_bytes()));
            sig_info = Some((sig_num, br_rel, lt_rel));
            match (state.acroform, state.acroform_dict.clone()) {
                (Some(af_id), Some(af_dict)) => {
                    let mut af = af_dict;
                    let mut fields = state.acroform_fields.clone();
                    fields.push(Object::Reference((field_num, 0)));
                    af.set(b"Fields", Object::Array(fields));
                    af.set(b"SigFlags", Object::Integer(3));
                    let mut body = Vec::new();
                    write_object(&Object::Dictionary(af), &mut body)?;
                    objs.push((af_id.0, af_id.1, body));
                }
                _ => {
                    // No AcroForm: new AcroForm object + catalog update.
                    let af_num = next;
                    let af = format!(
                        "<< /Fields [{field_num} 0 R] /SigFlags 3 >>"
                    );
                    objs.push((af_num, 0, af.into_bytes()));
                    let mut catalog = state.root_dict.clone();
                    catalog.set(b"AcroForm", Object::Reference((af_num, 0)));
                    let mut body = Vec::new();
                    write_object(&Object::Dictionary(catalog), &mut body)?;
                    objs.push((state.root.0, state.root.1, body));
                }
            }
        }
        RevisionKind::DocumentTimestamp => {
            let (sig_body, br_rel, lt_rel) = sig_dict_body(true, None, capacity);
            let sig_num = next;
            objs.push((sig_num, 0, sig_body));
            sig_info = Some((sig_num, br_rel, lt_rel));
        }
        RevisionKind::Dss {
            material_objects,
            dss_obj,
        } => {
            for (num, body) in material_objects {
                objs.push((*num, 0, body.clone()));
            }
            let mut catalog = state.root_dict.clone();
            catalog.set(b"DSS", Object::Reference((*dss_obj, 0)));
            let mut body = Vec::new();
            write_object(&Object::Dictionary(catalog), &mut body)?;
            objs.push((state.root.0, state.root.1, body));
        }
    }
    Ok((objs, sig_info))
}

fn write_trailer_entries(state: &RevisionState, size: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(format!("/Size {size} /Prev {} ", state.prev_startxref).as_bytes());
    out.extend_from_slice(format!("/Root {} {} R ", state.root.0, state.root.1).as_bytes());
    if let Some(info) = state.info {
        out.extend_from_slice(format!("/Info {} {} R ", info.0, info.1).as_bytes());
    }
    if let Some(id) = &state.id {
        out.extend_from_slice(b"/ID [");
        for item in id {
            if let Object::String(s, _) = item {
                write_hex_string(s, out);
                out.push(b' ');
            }
        }
        out.push(b']');
    }
}

fn emit_xref_table(state: &RevisionState, objs: &[ObjOut], size: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(b"xref\n");
    let mut sorted: Vec<&ObjOut> = objs.iter().collect();
    sorted.sort_by_key(|o| o.num);
    let mut idx = 0;
    while idx < sorted.len() {
        let start = sorted[idx].num;
        let mut end = start;
        while idx + 1 < sorted.len() && sorted[idx + 1].num == end + 1 {
            idx += 1;
            end = sorted[idx].num;
        }
        let count = end - start + 1;
        out.extend_from_slice(format!("{start} {count}\n").as_bytes());
        for o in &sorted[idx + 1 - count as usize..=idx] {
            out.extend_from_slice(format!("{:010} {:05} n\r\n", o.offset, o.generation).as_bytes());
        }
        idx += 1;
    }
    out.extend_from_slice(b"trailer\n<< ");
    write_trailer_entries(state, size, out);
    out.extend_from_slice(b">>\n");
}

/// Xref-stream entry layout: /W [1 8 2] (type, 8-byte offset, 2-byte gen).
fn emit_xref_stream(
    state: &RevisionState,
    objs: &[ObjOut],
    xref_num: u32,
    xref_offset: u64,
    size: u32,
    out: &mut Vec<u8>,
) {
    let mut all: Vec<ObjOut> = objs.to_vec();
    all.push(ObjOut {
        num: xref_num,
        generation: 0,
        offset: xref_offset,
    });
    all.sort_by_key(|o| o.num);
    let mut data = Vec::with_capacity(all.len() * 11);
    let mut index: Vec<(u32, u32)> = Vec::new();
    let mut i = 0;
    while i < all.len() {
        let start = all[i].num;
        let mut count = 0u32;
        while i < all.len() && all[i].num == start + count {
            data.push(1u8);
            data.extend_from_slice(&all[i].offset.to_be_bytes());
            data.extend_from_slice(&all[i].generation.to_be_bytes());
            count += 1;
            i += 1;
        }
        index.push((start, count));
    }
    out.extend_from_slice(format!("{xref_num} 0 obj\n<< /Type /XRef /W [1 8 2] ").as_bytes());
    out.extend_from_slice(b"/Index [");
    for (s, c) in &index {
        out.extend_from_slice(format!("{s} {c} ").as_bytes());
    }
    out.extend_from_slice(b"] ");
    write_trailer_entries(state, size, out);
    out.extend_from_slice(format!("/Length {} >>\nstream\n", data.len()).as_bytes());
    out.extend_from_slice(&data);
    out.extend_from_slice(b"\nendstream\nendobj\n");
}

/// Append one revision to `input` bytes. Placeholder `/ByteRange` values are
/// patched before return; `/Contents` stays zero-filled until
/// [`patch_contents`]. The buffer ends exactly at the final `%%EOF`.
pub(crate) fn append_revision(
    input: &[u8],
    state: &RevisionState,
    kind: &RevisionKind,
    capacity: usize,
) -> Result<DraftRevision, SealError> {
    let (objs, sig_info) = build_objects(state, kind, capacity)?;
    let mut out = input.to_vec();
    let mut written: Vec<ObjOut> = Vec::with_capacity(objs.len());
    let mut contents_gap = None;
    let mut br_patch = None;
    for (num, generation, body) in &objs {
        let offset = out.len() as u64;
        out.extend_from_slice(format!("{num} {generation} obj\n").as_bytes());
        if let Some((sig_num, br_rel, lt_rel)) = sig_info
            && sig_num == *num
        {
            let base = out.len();
            br_patch = Some(base + br_rel);
            contents_gap = Some((base + lt_rel, base + lt_rel + 1 + capacity * 2));
        }
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
        written.push(ObjOut {
            num: *num,
            generation: *generation,
            offset,
        });
    }
    let max_used = written.iter().map(|o| o.num).max().unwrap_or(state.max_obj);
    let xref_offset = out.len() as u64;
    let (xref_num, size) = match state.xref_style {
        XrefStyle::Table => (None, max_used + 1),
        XrefStyle::Stream => (Some(max_used + 1), max_used + 2),
    };
    match xref_num {
        None => emit_xref_table(state, &written, size, &mut out),
        Some(n) => emit_xref_stream(state, &written, n, xref_offset, size, &mut out),
    }
    out.extend_from_slice(format!("startxref\n{xref_offset}\n%%EOF").as_bytes());
    let byte_range = match (br_patch, contents_gap) {
        (Some(p), Some((lt, gt))) => {
            let total = out.len() as u64;
            let br = [0u64, lt as u64, gt as u64 + 1, total - (gt as u64 + 1)];
            patch_byterange(&mut out, p, br)?;
            Some(br)
        }
        _ => None,
    };
    Ok(DraftRevision {
        bytes: out,
        contents_gap,
        byte_range,
    })
}

fn patch_byterange(out: &mut [u8], pos: usize, br: [u64; 4]) -> Result<(), SealError> {
    for (i, v) in br[1..4].iter().enumerate() {
        let at = pos + i * (BYTERANGE_DIGITS + 1);
        let field = format!("{v:0BYTERANGE_DIGITS$}");
        if field.len() != BYTERANGE_DIGITS || at + BYTERANGE_DIGITS > out.len() {
            return Err(fatal_pdf(FatalCode::PdfInvariantFailed));
        }
        out[at..at + BYTERANGE_DIGITS].copy_from_slice(field.as_bytes());
    }
    Ok(())
}

/// Write the DER CMS into the `/Contents` hex gap, zero-padding the rest.
/// Returns `Err(ContentsCapacityExceeded)` when the DER does not fit; the
/// caller discards this candidate and rebuilds at the next capacity.
pub(crate) fn patch_contents(
    draft: &mut DraftRevision,
    der: &[u8],
) -> Result<(), SealError> {
    let (lt, gt) = draft
        .contents_gap
        .ok_or_else(|| fatal_pdf(FatalCode::PdfInvariantFailed))?;
    let gap = gt - lt - 1;
    if der.len() * 2 > gap {
        return Err(SealError::Fatal {
            stage: SealStage::PdfIncrementalUpdate,
            code: FatalCode::ContentsCapacityExceeded,
        });
    }
    let mut hex = Vec::with_capacity(gap);
    for &b in der {
        hex.extend_from_slice(format!("{b:02X}").as_bytes());
    }
    hex.resize(gap, b'0');
    draft.bytes[lt + 1..gt].copy_from_slice(&hex);
    Ok(())
}

/// SHA-256 over the two ByteRange spans (span1 then span2).
pub(crate) fn hash_byte_range(bytes: &[u8], br: [u64; 4]) -> Result<[u8; 32], SealError> {
    use sha2::Digest;
    let spans = [(br[0], br[1]), (br[2], br[3])];
    let mut h = sha2::Sha256::new();
    for (off, len) in spans {
        let (off, len) = (off as usize, len as usize);
        let end = off
            .checked_add(len)
            .filter(|e| *e <= bytes.len())
            .ok_or_else(|| fatal_pdf(FatalCode::PdfInvariantFailed))?;
        h.update(&bytes[off..end]);
    }
    Ok(h.finalize().into())
}

/// Deterministic invisible-signature field name from the operation ID.
pub(crate) fn field_name_for(operation_id: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(operation_id.as_bytes());
    let mut name = String::from("Seal-");
    for b in &digest[..6] {
        name.push_str(&format!("{b:02X}"));
    }
    name
}

/// PDF date representation of a unix-time-ms clock value.
pub(crate) fn pdf_date(unix_ms: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    let secs = i64::try_from(unix_ms / 1000).unwrap_or(i64::MAX);
    let dt = time::OffsetDateTime::from_unix_timestamp(secs)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    // D:YYYYMMDDHHmmSSZ
    let rfc = dt.format(&Rfc3339).unwrap_or_default();
    let digits: String = rfc.chars().filter(char::is_ascii_digit).take(14).collect();
    format!("D:{digits}Z")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use sha2::Digest;

    use super::*;

    fn classic_pdf() -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/pdf-input/classic_1page.pdf",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("fixture")
    }

    fn stream_pdf() -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/pdf-input/stream_1page.pdf",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("fixture")
    }

    fn prepared(bytes: &[u8]) -> PreparedInput {
        validate_prepared(bytes, &SealResourceLimits::default()).expect("prepared")
    }

    fn sign_revision(p: &PreparedInput, capacity: usize) -> DraftRevision {
        let kind = RevisionKind::Signature {
            field_name: field_name_for("unit-op"),
            date_str: pdf_date(1_785_398_400_000),
        };
        append_revision(&p.bytes, &p.state, &kind, capacity).expect("revision")
    }

    #[test]
    fn byterange_patch_is_length_preserving_and_spans_cover_all_but_gap() {
        let p = prepared(&classic_pdf());
        let draft = sign_revision(&p, 1024);
        let br = draft.byte_range.expect("br");
        let (lt, gt) = draft.contents_gap.expect("gap");
        assert_eq!(br[0], 0);
        assert_eq!(br[1] as usize, lt, "span1 ends at the '<'");
        assert_eq!(br[2] as usize, gt + 1, "span2 starts after the '>'");
        assert_eq!(
            (br[2] + br[3]) as usize,
            draft.bytes.len(),
            "span2 ends at final EOF"
        );
        // Hash spans cover everything except the gap, angle brackets included.
        let digest = hash_byte_range(&draft.bytes, br).expect("hash");
        let mut h = sha2::Sha256::new();
        h.update(&draft.bytes[..lt]);
        h.update(&draft.bytes[gt + 1..]);
        assert_eq!(digest, <[u8; 32]>::from(h.finalize()));
    }

    #[test]
    fn append_preserves_prior_bytes_prev_size_root_and_eof() {
        for fixture in [classic_pdf(), stream_pdf()] {
            let p = prepared(&fixture);
            let prev_sx = last_startxref(&fixture).expect("sx");
            let draft = sign_revision(&p, 2048);
            assert!(draft.bytes.starts_with(&fixture), "prior bytes preserved");
            assert!(draft.bytes.ends_with(b"%%EOF"));
            let body = String::from_utf8_lossy(&draft.bytes);
            assert!(
                body.contains(&format!("/Prev {prev_sx} ")),
                "Prev points at the immediately preceding startxref"
            );
            assert!(body.contains("/Root 1 0 R"), "Root preserved");
        }
    }

    #[test]
    fn xref_style_of_revision_matches_input() {
        let classic = prepared(&classic_pdf());
        let d1 = sign_revision(&classic, 1024);
        let tail1 = &d1.bytes[classic.bytes.len()..];
        let sx1 = last_startxref(&d1.bytes).expect("sx1");
        assert_eq!(&d1.bytes[sx1 as usize..sx1 as usize + 4], b"xref");
        assert!(tail1.windows(7).any(|w| w == b"trailer"));

        let stream = prepared(&stream_pdf());
        let d2 = sign_revision(&stream, 1024);
        let sx2 = last_startxref(&d2.bytes).expect("sx2");
        assert_ne!(&d2.bytes[sx2 as usize..sx2 as usize + 4], b"xref");
    }

    #[test]
    fn patch_contents_overflow_reports_capacity_not_truncation() {
        let p = prepared(&classic_pdf());
        let mut draft = sign_revision(&p, 64);
        let der = vec![0xABu8; 65];
        let err = patch_contents(&mut draft, &der).unwrap_err();
        assert!(matches!(
            err,
            SealError::Fatal {
                code: FatalCode::ContentsCapacityExceeded,
                ..
            }
        ));
        // Fitting DER lands at the start with zero padding after.
        let der = vec![0xCDu8; 40];
        patch_contents(&mut draft, &der).expect("patch");
        let (lt, _gt) = draft.contents_gap.expect("gap");
        assert_eq!(draft.bytes[lt + 1], b'C');
        assert_eq!(draft.bytes[lt + 2], b'D');
        assert_eq!(draft.bytes[lt + 1 + 80], b'0');
    }

    #[test]
    fn field_name_is_deterministic_and_op_scoped() {
        assert_eq!(field_name_for("op-a"), field_name_for("op-a"));
        assert_ne!(field_name_for("op-a"), field_name_for("op-b"));
    }

    #[test]
    fn pdf_date_format() {
        assert_eq!(pdf_date(1_785_398_400_000), "D:20260730080000Z");
    }
}

