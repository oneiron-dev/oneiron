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
    pub first_page_dict: Dictionary,
    /// Resolved `/Annots` entries of the first page (empty when absent).
    pub first_page_annots: Vec<Object>,
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

/// Resolve an object to its dictionary, seeing through both plain
/// dictionaries and STREAM dictionaries: a security-slot name hidden in a
/// stream object's dict must not bypass the prepared-input scan.
fn deref_dict<'d>(doc: &'d Document, obj: &'d Object) -> Option<&'d Dictionary> {
    match obj {
        Object::Dictionary(d) => Some(d),
        Object::Stream(s) => Some(&s.dict),
        Object::Reference(r) => match doc.get_object(*r) {
            Ok(Object::Dictionary(d)) => Some(d),
            Ok(Object::Stream(s)) => Some(&s.dict),
            _ => None,
        },
        _ => None,
    }
}

/// Resolve bounded indirection for security-critical name slots: `/Type`,
/// `/FT`, and `/S` hidden behind a reference chain must still be compared
/// against the denied names (§7.1 rules 6-7, §7.6 closing law). Returns
/// `None` when the chain dangles or exceeds the 8-reference budget: an
/// unresolvable security slot is a rejection in the matching violation
/// class, never a silent non-match (a 9-hop `/S -> … -> /JavaScript`
/// must not bypass the prepared-input rejection).
fn resolved<'d>(doc: &'d Document, mut obj: &'d Object) -> Option<&'d Object> {
    for _ in 0..8 {
        match obj {
            Object::Reference(r) => match doc.get_object(*r) {
                Ok(next) => obj = next,
                Err(_) => return None,
            },
            _ => return Some(obj),
        }
    }
    None
}

/// Scan every object for prepared-input contract violations (§7.1 rules 6-7).
fn scan_objects(doc: &Document) -> Result<(), SealError> {
    for obj in doc.objects.values() {
        let Some(dict) = deref_dict(doc, obj) else {
            continue;
        };
        if let Ok(t) = dict.get(b"Type") {
            let Some(t) = resolved(doc, t) else {
                return Err(input_invalid(InputInvalidCode::ExistingSignature));
            };
            if name_is(t, b"Sig") || name_is(t, b"DocTimeStamp") {
                return Err(input_invalid(InputInvalidCode::ExistingSignature));
            }
            if name_is(t, b"Filespec") {
                return Err(input_invalid(InputInvalidCode::EmbeddedFilePresent));
            }
        }
        if let Ok(ft) = dict.get(b"FT") {
            let Some(ft) = resolved(doc, ft) else {
                return Err(input_invalid(InputInvalidCode::ExistingSignature));
            };
            if name_is(ft, b"Sig") {
                return Err(input_invalid(InputInvalidCode::ExistingSignature));
            }
        }
        // A signature-shaped dictionary is rejected even without a /Type
        // marker: /ByteRange + /Contents together only exist for signing.
        if dict.has(b"ByteRange") && dict.has(b"Contents") {
            return Err(input_invalid(InputInvalidCode::ExistingSignature));
        }
        // A filespec-shaped dictionary is rejected even without the
        // /Type /Filespec marker: an /EF (embedded files) key is the tell.
        if dict.has(b"EF") {
            return Err(input_invalid(InputInvalidCode::EmbeddedFilePresent));
        }
        if dict.has(b"AA") {
            return Err(input_invalid(InputInvalidCode::ActiveContentPresent));
        }
        if dict.has(b"Lock") {
            return Err(input_invalid(InputInvalidCode::ExistingSignature));
        }
        if let Ok(s) = dict.get(b"S") {
            let Some(s) = resolved(doc, s) else {
                return Err(input_invalid(InputInvalidCode::ActiveContentPresent));
            };
            if name_is(s, b"JavaScript") || name_is(s, b"Launch") {
                return Err(input_invalid(InputInvalidCode::ActiveContentPresent));
            }
        }
    }
    Ok(())
}

/// Catalog-level checks: OpenAction, /Names JavaScript + EmbeddedFiles,
/// DocMDP/FieldMDP in /Perms, associated files at catalog and page dicts,
/// and XFA active form content.
fn scan_catalog(doc: &Document, root: &Dictionary) -> Result<(), SealError> {
    if root.has(b"OpenAction") {
        return Err(input_invalid(InputInvalidCode::ActiveContentPresent));
    }
    if let Ok(names) = root.get(b"Names")
        && let Some(names_dict) = deref_dict(doc, names)
    {
        if names_dict.has(b"JavaScript") {
            return Err(input_invalid(InputInvalidCode::ActiveContentPresent));
        }
        if names_dict.has(b"EmbeddedFiles") {
            return Err(input_invalid(InputInvalidCode::EmbeddedFilePresent));
        }
    }
    if let Ok(perms) = root.get(b"Perms")
        && let Some(pd) = deref_dict(doc, perms)
        && (pd.has(b"DocMDP") || pd.has(b"FieldMDP") || pd.has(b"UR3"))
    {
        return Err(input_invalid(InputInvalidCode::ExistingSignature));
    }
    // /AF (associated files) at the catalog or any page dict is embedded-file
    // content outside the /Names tree; it rides the same rejection class.
    if root.has(b"AF") {
        return Err(input_invalid(InputInvalidCode::EmbeddedFilePresent));
    }
    for page_id in doc.get_pages().values() {
        if let Ok(page) = doc.get_object(*page_id)
            && let Ok(page_dict) = page.as_dict()
            && page_dict.has(b"AF")
        {
            return Err(input_invalid(InputInvalidCode::EmbeddedFilePresent));
        }
    }
    // An /AcroForm carrying /XFA is active form content (XML Forms
    // Architecture), never a static AcroForm: reject, never sign over it.
    if let Ok(af) = root.get(b"AcroForm")
        && let Some(af_dict) = deref_dict(doc, af)
        && af_dict.has(b"XFA")
    {
        return Err(input_invalid(InputInvalidCode::ActiveContentPresent));
    }
    Ok(())
}

/// Offset recorded by the last `startxref` marker in the byte buffer.
pub(crate) fn last_startxref(bytes: &[u8]) -> Result<u64, SealError> {
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
    let at = usize::try_from(startxref).unwrap_or(usize::MAX);
    match at.checked_add(4).and_then(|end| bytes.get(at..end)) {
        Some(w) if w == b"xref" => XrefStyle::Table,
        _ => XrefStyle::Stream,
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
    // /AcroForm may be an indirect reference OR a direct dictionary; both
    // shapes must survive signing with their fields intact (a direct dict
    // treated as absent would be clobbered by a fresh AcroForm).
    let (acroform, acroform_dict) = match root_dict.get(b"AcroForm") {
        Ok(Object::Reference(r)) => {
            let dict = doc
                .get_object(*r)
                .ok()
                .and_then(|o| o.as_dict().ok())
                .cloned();
            (Some(*r), dict)
        }
        Ok(Object::Dictionary(d)) => (None, Some(d.clone())),
        _ => (None, None),
    };
    // /Fields may itself be an INDIRECT array (a valid direct /AcroForm can
    // hold `/Fields 7 0 R`): dereference through the document — bounded by
    // lopdf's chain limit — so register_field rewrites the FULL field list.
    // A present /Fields that does not resolve to an array fails closed:
    // rewriting an unreadable list would silently orphan every field.
    let acroform_fields = match acroform_dict.as_ref().and_then(|d| d.get(b"Fields").ok()) {
        Some(f) => doc
            .dereference(f)
            .ok()
            .and_then(|(_, o)| o.as_array().ok().cloned())
            .ok_or_else(|| input_invalid(InputInvalidCode::MalformedXref))?,
        None => Vec::new(),
    };
    let first_page_dict = doc
        .get_object(first_page)
        .ok()
        .and_then(|o| o.as_dict().ok())
        .ok_or_else(|| fatal_pdf(FatalCode::PdfInvariantFailed))?
        .clone();
    let first_page_annots = first_page_dict
        .get(b"Annots")
        .ok()
        .and_then(|a| {
            doc.dereference(a)
                .ok()
                .and_then(|(_, o)| o.as_array().ok().cloned())
        })
        .unwrap_or_default();
    // Allocation starts past BOTH the highest referenced object number and
    // the trailer /Size: free or unreferenced numbers below /Size stay out
    // of reach of the new revision's object numbers. A /Size that does not
    // fit the object-number space cannot be honored — reject it instead of
    // silently allocating inside its claimed range.
    let max_existing = doc.objects.keys().map(|(num, _)| *num).max().unwrap_or(0);
    let size_max = match trailer.get(b"Size") {
        Ok(s) => s
            .as_i64()
            .ok()
            .and_then(|v| u64::try_from(v).ok())
            .and_then(|v| v.checked_sub(1))
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| input_invalid(InputInvalidCode::ObjectLimitExceeded))?,
        Err(_) => 0,
    };
    let max_obj = max_existing.max(size_max);
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
        first_page_dict,
        first_page_annots,
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
                off.checked_add(header.len())
                    .and_then(|end| bytes.get(off..end))
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
    let doc = load_strict(bytes, limits).map_err(|_| fatal_pdf(FatalCode::PdfInvariantFailed))?;
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
    Signature {
        field_name: String,
        date_str: String,
    },
    /// DSS dictionary plus validation-material stream objects, and a catalog
    /// update pointing at it. No signature dictionary in this revision.
    Dss {
        material_objects: Vec<(u32, Vec<u8>)>,
        dss_obj: u32,
    },
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
    body.extend_from_slice(if kind_is_ts {
        b"/DocTimeStamp"
    } else {
        b"/Sig"
    });
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

/// Object numbers are allocated strictly past `state.max_obj` with checked
/// arithmetic: a crafted trailer `/Size` near `u32::MAX` must yield an
/// input-invalid rejection, never a wrap or panic.
fn next_obj(next: &mut u32) -> Result<u32, SealError> {
    let n = *next;
    *next = n
        .checked_add(1)
        .ok_or_else(|| input_invalid(InputInvalidCode::ObjectLimitExceeded))?;
    Ok(n)
}

/// Create-or-update `/AcroForm` so it lists `field_num`, preserving every
/// pre-existing entry and field. An absent AcroForm is created; a DIRECT
/// AcroForm dictionary is hoisted into its own indirect object so its
/// fields survive (the catalog is re-emitted pointing at it).
fn register_field(
    state: &RevisionState,
    objs: &mut Vec<(u32, u16, Vec<u8>)>,
    next: &mut u32,
    field_num: u32,
) -> Result<(), SealError> {
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
        (referenced, seed) => {
            let af_num = next_obj(next)?;
            let mut af = seed.unwrap_or_default();
            // A dangling /AcroForm reference keeps no fields to preserve.
            let mut fields = if referenced.is_some() {
                Vec::new()
            } else {
                state.acroform_fields.clone()
            };
            fields.push(Object::Reference((field_num, 0)));
            af.set(b"Fields", Object::Array(fields));
            af.set(b"SigFlags", Object::Integer(3));
            let mut af_body = Vec::new();
            write_object(&Object::Dictionary(af), &mut af_body)?;
            objs.push((af_num, 0, af_body));
            let mut catalog = state.root_dict.clone();
            catalog.set(b"AcroForm", Object::Reference((af_num, 0)));
            let mut body = Vec::new();
            write_object(&Object::Dictionary(catalog), &mut body)?;
            objs.push((state.root.0, state.root.1, body));
        }
    }
    Ok(())
}

fn build_objects(
    state: &RevisionState,
    kind: &RevisionKind,
    capacity: usize,
) -> Result<NewObjects, SealError> {
    let mut next = state
        .max_obj
        .checked_add(1)
        .ok_or_else(|| input_invalid(InputInvalidCode::ObjectLimitExceeded))?;
    let mut objs: Vec<(u32, u16, Vec<u8>)> = Vec::new();
    let mut sig_info = None;
    match kind {
        RevisionKind::Signature {
            field_name,
            date_str,
        } => {
            let (sig_body, br_rel, lt_rel) = sig_dict_body(false, Some(date_str), capacity);
            let sig_num = next_obj(&mut next)?;
            let field_num = next_obj(&mut next)?;
            let widget_num = next_obj(&mut next)?;
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
            // The widget must hang off the page's /Annots, not only carry a
            // /P back-reference: viewers and validators discover annotations
            // through the page.
            let mut page = state.first_page_dict.clone();
            let mut annots = state.first_page_annots.clone();
            annots.push(Object::Reference((widget_num, 0)));
            page.set(b"Annots", Object::Array(annots));
            let mut page_body = Vec::new();
            write_object(&Object::Dictionary(page), &mut page_body)?;
            objs.push((state.first_page.0, state.first_page.1, page_body));
            register_field(state, &mut objs, &mut next, field_num)?;
        }
        RevisionKind::DocumentTimestamp => {
            let (sig_body, br_rel, lt_rel) = sig_dict_body(true, None, capacity);
            let sig_num = next_obj(&mut next)?;
            let field_num = next_obj(&mut next)?;
            // External validators discover document timestamps through
            // signature FIELDS, not by scanning for /Type: register the DTS
            // dictionary as the value of an /FT /Sig field in /AcroForm
            // /Fields (no widget — an archival timestamp has no appearance).
            let field = format!("<< /FT /Sig /V {sig_num} 0 R >>");
            objs.push((sig_num, 0, sig_body));
            objs.push((field_num, 0, field.into_bytes()));
            sig_info = Some((sig_num, br_rel, lt_rel));
            register_field(state, &mut objs, &mut next, field_num)?;
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

fn write_trailer_entries(state: &RevisionState, size: u64, out: &mut Vec<u8>) {
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

fn emit_xref_table(state: &RevisionState, objs: &[ObjOut], size: u64, out: &mut Vec<u8>) {
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
    size: u64,
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
    // EOF glue: the first appended object header must start on its own
    // line even when the input's final %%EOF carries no trailing EOL
    // (a bare `%%EOF4 0 obj` line would corrupt both the marker and the
    // object). Emit exactly one EOL boundary: a missing newline is added;
    // a trailing '\r' is completed into CRLF.
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
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
    // /Size in u64: max_used sits at most at u32::MAX - 1 (next_obj bounds
    // allocation), so +2 can exceed the u32 space but never u64.
    let (xref_num, size) = match state.xref_style {
        XrefStyle::Table => (None, u64::from(max_used) + 1),
        XrefStyle::Stream => (
            Some(
                max_used
                    .checked_add(1)
                    .ok_or_else(|| input_invalid(InputInvalidCode::ObjectLimitExceeded))?,
            ),
            u64::from(max_used) + 2,
        ),
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
pub(crate) fn patch_contents(draft: &mut DraftRevision, der: &[u8]) -> Result<(), SealError> {
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
    let dt =
        time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
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
    fn stream_dictionary_sig_marker_is_rejected() {
        // A /Type /Sig hidden in a STREAM object's dictionary is the same
        // existing-signature violation as a plain dictionary.
        let mut doc = Document::with_version("1.4");
        let mut dict = Dictionary::new();
        dict.set("Type", Object::Name(b"Sig".to_vec()));
        dict.set("ByteRange", Object::Array(vec![Object::Integer(0)]));
        dict.set("Contents", Object::string_literal(b"x".to_vec()));
        doc.add_object(Object::Stream(lopdf::Stream::new(dict, Vec::new())));
        let err = scan_objects(&doc).unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: InputInvalidCode::ExistingSignature
            }
        ));
    }

    #[test]
    fn signature_revision_appends_widget_to_page_annots() {
        let p = prepared(&classic_pdf());
        let draft = sign_revision(&p, 1024);
        let doc = Document::load_mem(&draft.bytes).expect("reparse");
        let pages = doc.get_pages();
        let page_id = *pages.values().next().expect("page");
        let page = doc
            .get_object(page_id)
            .and_then(Object::as_dict)
            .expect("page dict");
        let annots = page
            .get(b"Annots")
            .and_then(Object::as_array)
            .expect("Annots array");
        let widget_present = annots.iter().any(|a| {
            let Object::Reference(r) = a else {
                return false;
            };
            doc.get_object(*r)
                .and_then(Object::as_dict)
                .is_ok_and(|d| d.get(b"Subtype").is_ok_and(|s| name_is(s, b"Widget")))
        });
        assert!(
            widget_present,
            "widget annotation must be on the page /Annots"
        );
    }

    #[test]
    fn max_obj_respects_trailer_size_beyond_referenced_objects() {
        let bytes = classic_pdf();
        let mut doc = Document::load_mem(&bytes).expect("load");
        let referenced_max = doc.objects.keys().map(|(n, _)| *n).max().unwrap_or(0);
        let size = i64::from(referenced_max) + 11;
        doc.trailer.set("Size", Object::Integer(size));
        let state = revision_state(&doc, &bytes).expect("state");
        assert_eq!(
            state.max_obj,
            u32::try_from(size - 1).unwrap(),
            "allocation must start past trailer /Size, not collide with free numbers"
        );
    }

    #[test]
    fn xref_helpers_never_overflow_on_extreme_offsets() {
        assert!(matches!(
            detect_xref_style(b"%PDF-1.4 garbage", u64::MAX),
            XrefStyle::Stream
        ));
        let mut doc = Document::with_version("1.4");
        doc.reference_table.entries.insert(
            1,
            lopdf::xref::XrefEntry::Normal {
                offset: u32::MAX,
                generation: 0,
            },
        );
        assert!(!xref_offsets_consistent(&doc, b"tiny"));
    }

    #[test]
    fn pdf_date_format() {
        assert_eq!(pdf_date(1_785_398_400_000), "D:20260730080000Z");
    }

    #[test]
    fn bare_eof_input_gets_exactly_one_eol_boundary() {
        // The classic fixture ends in a bare %%EOF with no trailing EOL:
        // the first appended object header must start on its OWN line,
        // exactly one '\n' boundary — never `%%EOF4 0 obj`.
        let input = classic_pdf();
        assert!(input.ends_with(b"%%EOF"), "fixture must end in bare %%EOF");
        let p = prepared(&input);
        let draft = sign_revision(&p, 1024);
        assert_eq!(draft.bytes[input.len()], b'\n', "missing EOL must be added");
        assert_ne!(
            draft.bytes[input.len() + 1],
            b'\n',
            "exactly one EOL boundary"
        );
        let first_obj = p.state.max_obj + 1;
        let header = format!("{first_obj} 0 obj\n");
        assert_eq!(
            &draft.bytes[input.len() + 1..input.len() + 1 + header.len()],
            header.as_bytes(),
            "object header on its own line"
        );
        // The emitted revision round-trips through our own loader.
        let state = reparse_revision(&draft.bytes, &SealResourceLimits::default())
            .expect("revision must reparse");
        assert_eq!(state.max_obj, first_obj + 3, "all four objects visible");
        // An input already carrying its trailing EOL gets no extra byte.
        let mut eol = classic_pdf();
        eol.push(b'\n');
        let p2 = prepared(&eol);
        let d2 = sign_revision(&p2, 1024);
        assert_eq!(
            d2.bytes[eol.len()],
            b'4',
            "no double boundary after a present EOL"
        );
    }

    /// Minimal in-memory catalog + one-page tree; `page_extra` keys are
    /// set on the page dict, `catalog_extra` on the catalog.
    fn doc_with_page(
        page_extra: &[(&[u8], Object)],
        catalog_extra: &[(&[u8], Object)],
    ) -> (Document, Dictionary) {
        let mut doc = Document::with_version("1.4");
        let mut page = Dictionary::new();
        page.set("Type", Object::Name(b"Page".to_vec()));
        for (k, v) in page_extra {
            page.set(*k, v.clone());
        }
        let page_id = doc.add_object(Object::Dictionary(page));
        let mut pages = Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
        pages.set("Count", Object::Integer(1));
        let pages_id = doc.add_object(Object::Dictionary(pages));
        let Ok(Object::Dictionary(p)) = doc.get_object_mut(page_id) else {
            panic!("page object");
        };
        p.set("Parent", Object::Reference(pages_id));
        let mut catalog = Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        for (k, v) in catalog_extra {
            catalog.set(*k, v.clone());
        }
        let catalog_id = doc.add_object(Object::Dictionary(catalog.clone()));
        doc.trailer.set("Root", Object::Reference(catalog_id));
        (doc, catalog)
    }

    #[test]
    fn catalog_and_page_af_are_rejected_as_embedded_files() {
        let af = || Object::Array(vec![Object::Reference((9, 0))]);
        let (doc, catalog) = doc_with_page(&[], &[(b"AF", af())]);
        let err = scan_catalog(&doc, &catalog).unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: InputInvalidCode::EmbeddedFilePresent
            }
        ));
        let (doc, catalog) = doc_with_page(&[(b"AF", af())], &[]);
        let err = scan_catalog(&doc, &catalog).unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: InputInvalidCode::EmbeddedFilePresent
            }
        ));
    }

    #[test]
    fn acroform_xfa_is_rejected_as_active_content() {
        let mut af = Dictionary::new();
        af.set("XFA", Object::Array(vec![]));
        let (doc, catalog) = doc_with_page(&[], &[(b"AcroForm", Object::Dictionary(af))]);
        let err = scan_catalog(&doc, &catalog).unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: InputInvalidCode::ActiveContentPresent
            }
        ));
    }

    #[test]
    fn dts_revision_registers_a_signature_field_in_acroform() {
        // External validators discover timestamps through FIELDS: the DTS
        // revision must add an /FT /Sig field whose /V is the DTS dict.
        let p = prepared(&classic_pdf());
        let signed = sign_revision(&p, 1024);
        let state = reparse_revision(&signed.bytes, &SealResourceLimits::default())
            .expect("reparse signed");
        let dts = append_revision(
            &signed.bytes,
            &state,
            &RevisionKind::DocumentTimestamp,
            1024,
        )
        .expect("dts revision");
        let doc = Document::load_mem(&dts.bytes).expect("load dts output");
        let catalog = doc.catalog().expect("catalog");
        let af = doc
            .dereference(catalog.get(b"AcroForm").expect("acroform"))
            .ok()
            .and_then(|(_, o)| o.as_dict().ok().cloned())
            .expect("acroform dict");
        let fields = af
            .get(b"Fields")
            .and_then(Object::as_array)
            .expect("fields");
        let dts_registered = fields.iter().any(|f| {
            let Ok(field) = doc.dereference(f).map(|(_, o)| o) else {
                return false;
            };
            let Ok(field) = field.as_dict() else {
                return false;
            };
            let ft_ok = field.get(b"FT").is_ok_and(|ft| name_is(ft, b"Sig"));
            let v_is_dts = field.get(b"V").is_ok_and(|v| {
                doc.dereference(v)
                    .ok()
                    .and_then(|(_, o)| o.as_dict().ok())
                    .is_some_and(|d| d.get(b"Type").is_ok_and(|t| name_is(t, b"DocTimeStamp")))
            });
            ft_ok && v_is_dts
        });
        assert!(
            dts_registered,
            "AcroForm /Fields must contain an /FT /Sig field whose /V is the DTS dict"
        );
    }

    #[test]
    fn direct_acroform_dict_fields_survive_signing() {
        // A DIRECT /AcroForm dictionary (no indirection) must keep its
        // fields across signing: the writer hoists it instead of replacing
        // it with a fresh one-field AcroForm.
        let mut doc = Document::with_version("1.4");
        let mut text_field = Dictionary::new();
        text_field.set("FT", Object::Name(b"Tx".to_vec()));
        text_field.set("T", Object::string_literal(b"existing".to_vec()));
        let text_id = doc.add_object(Object::Dictionary(text_field));
        let mut page = Dictionary::new();
        page.set("Type", Object::Name(b"Page".to_vec()));
        page.set(
            "MediaBox",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(200),
                Object::Integer(200),
            ]),
        );
        let page_id = doc.add_object(Object::Dictionary(page));
        let mut pages = Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
        pages.set("Count", Object::Integer(1));
        let pages_id = doc.add_object(Object::Dictionary(pages));
        let Ok(Object::Dictionary(p)) = doc.get_object_mut(page_id) else {
            panic!("page");
        };
        p.set("Parent", Object::Reference(pages_id));
        let mut af = Dictionary::new();
        af.set("Fields", Object::Array(vec![Object::Reference(text_id)]));
        let mut catalog = Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        catalog.set("AcroForm", Object::Dictionary(af)); // DIRECT dict
        let catalog_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(catalog_id));
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).expect("save");
        let prepared = prepared(&bytes);
        assert!(
            prepared.state.acroform.is_none() && prepared.state.acroform_dict.is_some(),
            "direct AcroForm must be captured as a dict without a reference"
        );
        let draft = sign_revision(&prepared, 1024);
        let out = Document::load_mem(&draft.bytes).expect("reload");
        let catalog = out.catalog().expect("catalog");
        let af = out
            .dereference(catalog.get(b"AcroForm").expect("acroform"))
            .ok()
            .and_then(|(_, o)| o.as_dict().ok().cloned())
            .expect("acroform dict");
        let fields = af
            .get(b"Fields")
            .and_then(Object::as_array)
            .expect("fields");
        assert!(
            fields
                .iter()
                .any(|f| matches!(f, Object::Reference(r) if *r == text_id)),
            "the pre-existing text field must survive signing: {fields:?}"
        );
        assert_eq!(fields.len(), 2, "text field plus the new signature field");
    }

    #[test]
    fn direct_acroform_indirect_fields_array_survives_signing() {
        // P2-2: a valid DIRECT /AcroForm whose /Fields is an INDIRECT array
        // must keep every old field reference — the array is dereferenced
        // through the document before register_field rewrites it (a raw
        // as_array read saw no array and hoisted an EMPTY field list,
        // silently orphaning every existing field).
        let mut doc = Document::with_version("1.4");
        let mut text_field = Dictionary::new();
        text_field.set("FT", Object::Name(b"Tx".to_vec()));
        text_field.set("T", Object::string_literal(b"existing".to_vec()));
        let text_id = doc.add_object(Object::Dictionary(text_field));
        let fields_id = doc.add_object(Object::Array(vec![Object::Reference(text_id)]));
        let mut page = Dictionary::new();
        page.set("Type", Object::Name(b"Page".to_vec()));
        page.set(
            "MediaBox",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(200),
                Object::Integer(200),
            ]),
        );
        let page_id = doc.add_object(Object::Dictionary(page));
        let mut pages = Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
        pages.set("Count", Object::Integer(1));
        let pages_id = doc.add_object(Object::Dictionary(pages));
        let Ok(Object::Dictionary(p)) = doc.get_object_mut(page_id) else {
            panic!("page");
        };
        p.set("Parent", Object::Reference(pages_id));
        let mut af = Dictionary::new();
        af.set("Fields", Object::Reference(fields_id)); // INDIRECT array
        let mut catalog = Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        catalog.set("AcroForm", Object::Dictionary(af)); // DIRECT dict
        let catalog_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(catalog_id));
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).expect("save");
        let prepared = prepared(&bytes);
        assert_eq!(
            prepared.state.acroform_fields,
            vec![Object::Reference(text_id)],
            "the indirect /Fields array must be dereferenced, not read as absent"
        );
        let draft = sign_revision(&prepared, 1024);
        let out = Document::load_mem(&draft.bytes).expect("reload");
        let catalog = out.catalog().expect("catalog");
        let af = out
            .dereference(catalog.get(b"AcroForm").expect("acroform"))
            .ok()
            .and_then(|(_, o)| o.as_dict().ok().cloned())
            .expect("acroform dict");
        let fields = af
            .get(b"Fields")
            .and_then(Object::as_array)
            .expect("fields");
        assert!(
            fields
                .iter()
                .any(|f| matches!(f, Object::Reference(r) if *r == text_id)),
            "the pre-existing text field must survive signing: {fields:?}"
        );
        assert_eq!(fields.len(), 2, "text field plus the new signature field");
    }

    #[test]
    fn unresolvable_acroform_fields_fail_closed() {
        // P2-2 fail-closed arm: a present /Fields that does not resolve to
        // an array (dangling reference, wrong type) is malformed input —
        // never rewritten as an empty field list.
        for fields in [
            Object::Reference((99, 0)), // dangling
            Object::Integer(7),         // not an array at all
        ] {
            let mut doc = Document::with_version("1.4");
            let mut page = Dictionary::new();
            page.set("Type", Object::Name(b"Page".to_vec()));
            let page_id = doc.add_object(Object::Dictionary(page));
            let mut pages = Dictionary::new();
            pages.set("Type", Object::Name(b"Pages".to_vec()));
            pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
            pages.set("Count", Object::Integer(1));
            let pages_id = doc.add_object(Object::Dictionary(pages));
            let Ok(Object::Dictionary(p)) = doc.get_object_mut(page_id) else {
                panic!("page");
            };
            p.set("Parent", Object::Reference(pages_id));
            let mut af = Dictionary::new();
            af.set("Fields", fields);
            let af_id = doc.add_object(Object::Dictionary(af));
            let mut catalog = Dictionary::new();
            catalog.set("Type", Object::Name(b"Catalog".to_vec()));
            catalog.set("Pages", Object::Reference(pages_id));
            catalog.set("AcroForm", Object::Reference(af_id));
            let catalog_id = doc.add_object(Object::Dictionary(catalog));
            doc.trailer.set("Root", Object::Reference(catalog_id));
            let mut bytes = Vec::new();
            doc.save_to(&mut bytes).expect("save");
            let err = validate_prepared(&bytes, &SealResourceLimits::default()).unwrap_err();
            assert!(matches!(
                err,
                SealError::InputInvalid {
                    code: InputInvalidCode::MalformedXref
                }
            ));
        }
    }

    #[test]
    fn crafted_huge_trailer_size_fails_closed_without_overflow() {
        let bytes = classic_pdf();
        // /Size beyond the u32 object-number space: rejected at state
        // extraction, never silently clamped to 0.
        let mut doc = Document::load_mem(&bytes).expect("load");
        doc.trailer.set("Size", Object::Integer(1i64 << 40));
        let err = revision_state(&doc, &bytes).unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: InputInvalidCode::ObjectLimitExceeded
            }
        ));
        // /Size = u32::MAX + 1: state extracts, but allocation must fail
        // with checked arithmetic — no wrap, no panic.
        let mut doc = Document::load_mem(&bytes).expect("load");
        doc.trailer
            .set("Size", Object::Integer(i64::from(u32::MAX) + 1));
        let state = revision_state(&doc, &bytes).expect("state");
        assert_eq!(state.max_obj, u32::MAX);
        let kind = RevisionKind::Signature {
            field_name: field_name_for("unit-op"),
            date_str: pdf_date(1_785_398_400_000),
        };
        let err = append_revision(&bytes, &state, &kind, 64).unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: InputInvalidCode::ObjectLimitExceeded
            }
        ));
    }
    #[test]
    fn ef_key_dict_is_rejected_without_filespec_type() {
        // A filespec-shaped dictionary without /Type: the /EF key is the
        // tell and must be rejected as embedded-file content.
        let mut doc = Document::with_version("1.4");
        let mut dict = Dictionary::new();
        dict.set("F", Object::string_literal(b"evil.exe".to_vec()));
        dict.set("UF", Object::string_literal(b"evil.exe".to_vec()));
        dict.set("EF", Object::Dictionary(Dictionary::new()));
        doc.add_object(Object::Dictionary(dict));
        let err = scan_objects(&doc).unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: InputInvalidCode::EmbeddedFilePresent
            }
        ));
    }
}
