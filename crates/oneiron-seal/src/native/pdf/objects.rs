//! Revision object graphs (§7.2): PDF value serializers, sig-dict placeholders, AcroForm/page updates, checked allocation.

use lopdf::Object;

use super::parse::{RevisionState, fatal_pdf, input_invalid};
use crate::error::{FatalCode, InputInvalidCode, SealError};

// ---------------------------------------------------------------------------
// Byte-exact incremental writer
// ---------------------------------------------------------------------------

pub(super) const BYTERANGE_DIGITS: usize = 20;

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

pub(super) fn write_hex_string(data: &[u8], out: &mut Vec<u8>) {
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
pub(super) struct ObjOut {
    pub(super) num: u32,
    pub(super) generation: u16,
    pub(super) offset: u64,
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

pub(super) fn build_objects(
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
            // The field carries a /T name, unique within the document via
            // the freshly allocated field object number: ISO 32000 requires
            // field names for well-formed AcroForm trees, and some
            // validators reject nameless fields.
            let field =
                format!("<< /FT /Sig /T (Seal-DocTimeStamp-{field_num}) /V {sig_num} 0 R >>");
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
