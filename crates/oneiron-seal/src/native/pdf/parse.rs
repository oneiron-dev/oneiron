//! Prepared-input validation (§7.1): object/catalog scans, strict load, xref consistency, and RevisionState extraction.

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

pub(super) fn fatal_pdf(code: FatalCode) -> SealError {
    SealError::Fatal {
        stage: SealStage::PdfIncrementalUpdate,
        code,
    }
}

pub(super) fn input_invalid(code: InputInvalidCode) -> SealError {
    SealError::InputInvalid { code }
}

pub(super) fn name_is(obj: &Object, expected: &[u8]) -> bool {
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
pub(super) fn scan_objects(doc: &Document) -> Result<(), SealError> {
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
pub(super) fn scan_catalog(doc: &Document, root: &Dictionary) -> Result<(), SealError> {
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
pub(super) fn detect_xref_style(bytes: &[u8], startxref: u64) -> XrefStyle {
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
pub(super) fn revision_state(doc: &Document, bytes: &[u8]) -> Result<RevisionState, SealError> {
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
pub(super) fn xref_offsets_consistent(doc: &Document, bytes: &[u8]) -> bool {
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
