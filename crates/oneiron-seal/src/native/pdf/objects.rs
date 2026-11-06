//! Revision object graphs (§7.2): PDF value serializers, sig-dict placeholders, AcroForm/page updates, checked allocation.

use std::fmt::Write as _;

use lopdf::{Object, StringFormat};

use super::admitted;
use super::parse::{RevisionState, fatal_pdf, input_invalid};
use crate::api::SealResourceLimits;
use crate::error::{FatalCode, InputInvalidCode, SealError, SealStage};
use crate::memory::SealMemoryRefusal;

// ---------------------------------------------------------------------------
// Byte-exact incremental writer
// ---------------------------------------------------------------------------

pub(super) const BYTERANGE_DIGITS: usize = 20;

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn memory_error(refusal: SealMemoryRefusal) -> SealError {
    refusal.seal_error(SealStage::PdfIncrementalUpdate)
}

fn decimal_len_u64(mut value: u64) -> usize {
    if value == 0 {
        return 1;
    }
    let mut len = 0;
    while value > 0 {
        len += 1;
        value /= 10;
    }
    len
}

/// Decimal bytes of `value` into `out`, without any temporary allocation.
/// The caller admits `decimal_len_u64(value)` first.
fn push_decimal_u64(out: &mut Vec<u8>, value: u64) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut tmp = value;
    let mut len = 0;
    while tmp > 0 {
        buf[19 - len] = b'0' + (tmp % 10) as u8;
        tmp /= 10;
        len += 1;
    }
    out.extend_from_slice(&buf[20 - len..]);
}

/// Stack writer for `f32` display without any heap temporary.
struct DecimalBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl std::fmt::Write for DecimalBuf<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            return Err(std::fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

fn floor_error() -> SealError {
    memory_error(SealMemoryRefusal::Floor {
        needed: u64::MAX,
        available: 0,
    })
}

/// Serialize the subset of PDF objects the writer re-emits (catalog and
/// AcroForm updates). Streams are never re-emitted; existing stream objects
/// stay reachable by reference. Arrays and dictionaries nest to any depth
/// the reader accepted: what is left to write waits on an explicit stack,
/// never the call stack (Rule 5).
fn write_object(
    obj: &Object,
    out: &mut Vec<u8>,
    limits: &SealResourceLimits,
) -> Result<(), SealError> {
    let mut pending = admitted::vec(limits, 1).map_err(memory_error)?;
    pending.push(Emit::Value(obj));
    while let Some(step) = pending.pop() {
        let value = match step {
            Emit::Value(value) => value,
            Emit::Key(name) => {
                write_name(name, out, limits)?;
                continue;
            }
            Emit::Text(text) => {
                admitted::reserve(limits, out, text.len()).map_err(memory_error)?;
                out.extend_from_slice(text);
                continue;
            }
        };
        match value {
            Object::Null => {
                admitted::reserve(limits, out, b"null".len()).map_err(memory_error)?;
                out.extend_from_slice(b"null");
            }
            Object::Boolean(true) => {
                admitted::reserve(limits, out, b"true".len()).map_err(memory_error)?;
                out.extend_from_slice(b"true");
            }
            Object::Boolean(false) => {
                admitted::reserve(limits, out, b"false".len()).map_err(memory_error)?;
                out.extend_from_slice(b"false");
            }
            Object::Integer(i) => {
                let (negative, magnitude) = if *i < 0 {
                    (true, (*i).unsigned_abs())
                } else {
                    (false, *i as u64)
                };
                let len = decimal_len_u64(magnitude) + usize::from(negative);
                admitted::reserve(limits, out, len).map_err(memory_error)?;
                if negative {
                    out.push(b'-');
                }
                push_decimal_u64(out, magnitude);
            }
            Object::Real(r) => write_real(*r, out, limits)?,
            Object::Name(n) => write_name(n, out, limits)?,
            Object::String(s, StringFormat::Literal) => write_literal_bytes(s, out, limits)?,
            Object::String(s, StringFormat::Hexadecimal) => write_hex_string(s, out, limits)?,
            Object::Array(a) => {
                admitted::reserve(limits, out, 1).map_err(memory_error)?;
                out.push(b'[');
                admitted::push(limits, &mut pending, Emit::Text(b"]")).map_err(memory_error)?;
                for (i, item) in a.iter().enumerate().rev() {
                    admitted::push(limits, &mut pending, Emit::Value(item))
                        .map_err(memory_error)?;
                    if i > 0 {
                        admitted::push(limits, &mut pending, Emit::Text(b" "))
                            .map_err(memory_error)?;
                    }
                }
            }
            Object::Dictionary(d) => {
                admitted::reserve(limits, out, b"<< ".len()).map_err(memory_error)?;
                out.extend_from_slice(b"<< ");
                admitted::push(limits, &mut pending, Emit::Text(b">>")).map_err(memory_error)?;
                for (k, v) in d.iter().rev() {
                    admitted::push(limits, &mut pending, Emit::Text(b" ")).map_err(memory_error)?;
                    admitted::push(limits, &mut pending, Emit::Value(v)).map_err(memory_error)?;
                    admitted::push(limits, &mut pending, Emit::Text(b" ")).map_err(memory_error)?;
                    admitted::push(limits, &mut pending, Emit::Key(k)).map_err(memory_error)?;
                }
            }
            Object::Reference(r) => {
                let first_len = decimal_len_u64(u64::from(r.0));
                let second_len = decimal_len_u64(u64::from(r.1));
                admitted::reserve(limits, out, first_len + 1 + second_len + b" R".len())
                    .map_err(memory_error)?;
                push_decimal_u64(out, u64::from(r.0));
                out.push(b' ');
                push_decimal_u64(out, u64::from(r.1));
                out.extend_from_slice(b" R");
            }
            Object::Stream(_) => return Err(fatal_pdf(FatalCode::PdfInvariantFailed)),
        }
    }
    Ok(())
}

/// One step [`write_object`] has left: a value, a dictionary key, or the
/// separator or closing delimiter between them.
enum Emit<'a> {
    Value(&'a Object),
    Key(&'a [u8]),
    Text(&'static [u8]),
}

/// A real as the same real: the shortest decimal that reads back as the
/// same value, with a decimal point so it reads back as a real, not an
/// integer. The verifier compares catalogs by value and type: six places
/// would turn 0.0000004 into 0, and `0` would turn 0.0 into an integer. An
/// infinity, which lopdf reads from a decimal past f32, is written as such a
/// decimal again.
fn write_real(value: f32, out: &mut Vec<u8>, limits: &SealResourceLimits) -> Result<(), SealError> {
    if value.is_finite() {
        let mut buf = [0u8; 128];
        let len = {
            let mut writer = DecimalBuf {
                buf: &mut buf,
                len: 0,
            };
            write!(writer, "{value}").map_err(|_| fatal_pdf(FatalCode::PdfInvariantFailed))?;
            writer.len
        };
        let text = &buf[..len];
        let needs_dot = !text.contains(&b'.');
        let total = len + usize::from(needs_dot) * 2;
        admitted::reserve(limits, out, total).map_err(memory_error)?;
        out.extend_from_slice(text);
        if needs_dot {
            out.extend_from_slice(b".0");
        }
        Ok(())
    } else if value.is_infinite() {
        let negative = value.is_sign_negative();
        let total = usize::from(negative) + 1 + 39 + 2;
        admitted::reserve(limits, out, total).map_err(memory_error)?;
        if negative {
            out.push(b'-');
        }
        out.push(b'1');
        out.extend_from_slice(&[b'0'; 39]);
        out.extend_from_slice(b".0");
        Ok(())
    } else {
        Err(fatal_pdf(FatalCode::PdfInvariantFailed))
    }
}

/// A literal string as the same literal string: `(`, `)` and `\` escaped,
/// and every byte outside printable ASCII as a three-digit octal escape, so
/// no raw end of line is read back as another.
fn write_literal_bytes(
    data: &[u8],
    out: &mut Vec<u8>,
    limits: &SealResourceLimits,
) -> Result<(), SealError> {
    let mut total: usize = 2;
    for &b in data {
        let extra = match b {
            b'(' | b')' | b'\\' => 2,
            b' '..=b'~' => 1,
            _ => 4,
        };
        total = total.checked_add(extra).ok_or_else(floor_error)?;
    }
    admitted::reserve(limits, out, total).map_err(memory_error)?;
    out.push(b'(');
    for &b in data {
        match b {
            b'(' | b')' | b'\\' => out.extend_from_slice(&[b'\\', b]),
            b' '..=b'~' => out.push(b),
            _ => {
                out.push(b'\\');
                out.push(b'0' + ((b >> 6) & 7));
                out.push(b'0' + ((b >> 3) & 7));
                out.push(b'0' + (b & 7));
            }
        }
    }
    out.push(b')');
    Ok(())
}

fn write_name(
    name: &[u8],
    out: &mut Vec<u8>,
    limits: &SealResourceLimits,
) -> Result<(), SealError> {
    let mut total: usize = 1;
    for &b in name {
        let safe = b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+' | b'*');
        total = total
            .checked_add(if safe { 1 } else { 3 })
            .ok_or_else(floor_error)?;
    }
    admitted::reserve(limits, out, total).map_err(memory_error)?;
    out.push(b'/');
    for &b in name {
        let safe = b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+' | b'*');
        if safe {
            out.push(b);
        } else {
            out.push(b'#');
            out.push(HEX_UPPER[(b >> 4) as usize]);
            out.push(HEX_UPPER[(b & 0xF) as usize]);
        }
    }
    Ok(())
}

pub(super) fn write_hex_string(
    data: &[u8],
    out: &mut Vec<u8>,
    limits: &SealResourceLimits,
) -> Result<(), SealError> {
    let total = data
        .len()
        .checked_mul(2)
        .and_then(|hex| hex.checked_add(2))
        .ok_or_else(floor_error)?;
    admitted::reserve(limits, out, total).map_err(memory_error)?;
    out.push(b'<');
    for &b in data {
        out.push(HEX_UPPER[(b >> 4) as usize]);
        out.push(HEX_UPPER[(b & 0xF) as usize]);
    }
    out.push(b'>');
    Ok(())
}

/// Literal-string escape for `/T` field names and `/M` dates.
fn write_literal_string(
    data: &str,
    out: &mut Vec<u8>,
    limits: &SealResourceLimits,
) -> Result<(), SealError> {
    let bytes = data.as_bytes();
    let mut total: usize = 2;
    for &b in bytes {
        let extra = match b {
            b'(' | b')' | b'\\' => 2,
            _ => 1,
        };
        total = total.checked_add(extra).ok_or_else(floor_error)?;
    }
    admitted::reserve(limits, out, total).map_err(memory_error)?;
    out.push(b'(');
    for &b in bytes {
        match b {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            _ => out.push(b),
        }
    }
    out.push(b')');
    Ok(())
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
    limits: &SealResourceLimits,
) -> Result<(Vec<u8>, usize, usize), SealError> {
    // Returns (body, byterange_patch_rel, contents_lt_rel).
    let hex_len = capacity.checked_mul(2).ok_or_else(floor_error)?;
    let total = hex_len.checked_add(256).ok_or_else(floor_error)?;
    let mut body: Vec<u8> = admitted::vec(limits, total).map_err(memory_error)?;
    admitted::reserve(limits, &mut body, b"<< /Type ".len()).map_err(memory_error)?;
    body.extend_from_slice(b"<< /Type ");
    let kind_name: &[u8] = if kind_is_ts {
        b"/DocTimeStamp"
    } else {
        b"/Sig"
    };
    admitted::reserve(limits, &mut body, kind_name.len()).map_err(memory_error)?;
    body.extend_from_slice(kind_name);
    admitted::reserve(
        limits,
        &mut body,
        b" /Filter /Adobe.PPKLite /SubFilter ".len(),
    )
    .map_err(memory_error)?;
    body.extend_from_slice(b" /Filter /Adobe.PPKLite /SubFilter ");
    let subfilter: &[u8] = if kind_is_ts {
        b"/ETSI.RFC3161"
    } else {
        b"/ETSI.CAdES.detached"
    };
    admitted::reserve(limits, &mut body, subfilter.len()).map_err(memory_error)?;
    body.extend_from_slice(subfilter);
    if let Some(d) = date_str {
        admitted::reserve(limits, &mut body, b" /M ".len()).map_err(memory_error)?;
        body.extend_from_slice(b" /M ");
        write_literal_string(d, &mut body, limits)?;
    }
    admitted::reserve(limits, &mut body, b" /ByteRange [0 ".len()).map_err(memory_error)?;
    body.extend_from_slice(b" /ByteRange [0 ");
    let br_rel = body.len();
    for i in 0..3 {
        admitted::reserve(limits, &mut body, BYTERANGE_DIGITS).map_err(memory_error)?;
        body.extend_from_slice(b"00000000000000000000");
        if i < 2 {
            admitted::reserve(limits, &mut body, 1).map_err(memory_error)?;
            body.push(b' ');
        }
    }
    admitted::reserve(limits, &mut body, b"] /Contents <".len()).map_err(memory_error)?;
    body.extend_from_slice(b"] /Contents <");
    let lt_rel = body.len() - 1;
    admitted::reserve(limits, &mut body, hex_len).map_err(memory_error)?;
    body.extend(std::iter::repeat_n(b'0', hex_len));
    admitted::reserve(limits, &mut body, b"> >>".len()).map_err(memory_error)?;
    body.extend_from_slice(b"> >>");
    Ok((body, br_rel, lt_rel))
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

/// Admit one dictionary insertion's node share and key bytes before `set`.
fn admit_dict_insert(limits: &SealResourceLimits, key_len: usize) -> Result<(), SealError> {
    limits
        .memory
        .admit::<(Vec<u8>, Object)>(1)
        .map_err(memory_error)?;
    limits.memory.admit::<usize>(1).map_err(memory_error)?;
    limits.memory.admit::<u8>(key_len).map_err(memory_error)?;
    Ok(())
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
    limits: &SealResourceLimits,
) -> Result<(), SealError> {
    let seed: Option<lopdf::Dictionary> = match &state.acroform_dict {
        Some(dict) => {
            admitted::dictionary(limits, dict).map_err(memory_error)?;
            Some(dict.clone())
        }
        None => None,
    };
    match (state.acroform, seed) {
        (Some(af_id), Some(mut af)) => {
            admitted::objects(limits, &state.acroform_fields).map_err(memory_error)?;
            let mut fields = state.acroform_fields.clone();
            admitted::push(limits, &mut fields, Object::Reference((field_num, 0)))
                .map_err(memory_error)?;
            admit_dict_insert(limits, b"Fields".len())?;
            af.set(b"Fields", Object::Array(fields));
            admit_dict_insert(limits, b"SigFlags".len())?;
            af.set(b"SigFlags", Object::Integer(3));
            let mut body = Vec::new();
            write_object(&Object::Dictionary(af), &mut body, limits)?;
            admitted::push(limits, objs, (af_id.0, af_id.1, body)).map_err(memory_error)?;
        }
        (referenced, seed) => {
            let af_num = next_obj(next)?;
            // A dangling /AcroForm reference keeps no fields to preserve.
            let mut af = seed.unwrap_or_else(lopdf::Dictionary::new);
            let mut fields = if referenced.is_some() {
                Vec::new()
            } else {
                admitted::objects(limits, &state.acroform_fields).map_err(memory_error)?;
                state.acroform_fields.clone()
            };
            admitted::push(limits, &mut fields, Object::Reference((field_num, 0)))
                .map_err(memory_error)?;
            admit_dict_insert(limits, b"Fields".len())?;
            af.set(b"Fields", Object::Array(fields));
            admit_dict_insert(limits, b"SigFlags".len())?;
            af.set(b"SigFlags", Object::Integer(3));
            let mut af_body = Vec::new();
            write_object(&Object::Dictionary(af), &mut af_body, limits)?;
            admitted::push(limits, objs, (af_num, 0, af_body)).map_err(memory_error)?;
            admitted::dictionary(limits, &state.root_dict).map_err(memory_error)?;
            let mut catalog = state.root_dict.clone();
            admit_dict_insert(limits, b"AcroForm".len())?;
            catalog.set(b"AcroForm", Object::Reference((af_num, 0)));
            let mut body = Vec::new();
            write_object(&Object::Dictionary(catalog), &mut body, limits)?;
            admitted::push(limits, objs, (state.root.0, state.root.1, body))
                .map_err(memory_error)?;
        }
    }
    Ok(())
}

pub(super) fn build_objects(
    state: &RevisionState,
    kind: &RevisionKind,
    capacity: usize,
    limits: &SealResourceLimits,
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
            let (sig_body, br_rel, lt_rel) =
                sig_dict_body(false, Some(date_str), capacity, limits)?;
            let sig_num = next_obj(&mut next)?;
            let field_num = next_obj(&mut next)?;
            // Use one terminal field/widget object. Poppler 22.02 through 25.02 treat
            // a separate widget with /Parent as a child field and look for
            // /V on that widget, incorrectly reporting the parent unsigned.
            // A combined field is valid PDF and keeps /V, /FT and the widget
            // together for both AcroForm and page-annotation readers.
            let mut field = Vec::new();
            admitted::reserve(limits, &mut field, b"<< /FT /Sig /T ".len())
                .map_err(memory_error)?;
            field.extend_from_slice(b"<< /FT /Sig /T ");
            write_literal_string(field_name, &mut field, limits)?;
            let prefix: &[u8] = b" /V ";
            let middle: &[u8] = b" 0 R /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /F 4 /P ";
            let suffix: &[u8] = b" R >>";
            let len_sig = decimal_len_u64(u64::from(sig_num));
            let len_p0 = decimal_len_u64(u64::from(state.first_page.0));
            let len_p1 = decimal_len_u64(u64::from(state.first_page.1));
            admitted::reserve(
                limits,
                &mut field,
                prefix.len() + len_sig + middle.len() + len_p0 + 1 + len_p1 + suffix.len(),
            )
            .map_err(memory_error)?;
            field.extend_from_slice(prefix);
            push_decimal_u64(&mut field, u64::from(sig_num));
            field.extend_from_slice(middle);
            push_decimal_u64(&mut field, u64::from(state.first_page.0));
            field.push(b' ');
            push_decimal_u64(&mut field, u64::from(state.first_page.1));
            field.extend_from_slice(suffix);
            admitted::push(limits, &mut objs, (sig_num, 0, sig_body)).map_err(memory_error)?;
            admitted::push(limits, &mut objs, (field_num, 0, field)).map_err(memory_error)?;
            sig_info = Some((sig_num, br_rel, lt_rel));
            // The same terminal field/widget must be reachable from the
            // page /Annots as well as the AcroForm /Fields array.
            admitted::dictionary(limits, &state.first_page_dict).map_err(memory_error)?;
            let mut page = state.first_page_dict.clone();
            admitted::objects(limits, &state.first_page_annots).map_err(memory_error)?;
            let mut annots = state.first_page_annots.clone();
            admitted::push(limits, &mut annots, Object::Reference((field_num, 0)))
                .map_err(memory_error)?;
            admit_dict_insert(limits, b"Annots".len())?;
            page.set(b"Annots", Object::Array(annots));
            let mut page_body = Vec::new();
            write_object(&Object::Dictionary(page), &mut page_body, limits)?;
            admitted::push(
                limits,
                &mut objs,
                (state.first_page.0, state.first_page.1, page_body),
            )
            .map_err(memory_error)?;
            register_field(state, &mut objs, &mut next, field_num, limits)?;
        }
        RevisionKind::DocumentTimestamp => {
            let (sig_body, br_rel, lt_rel) = sig_dict_body(true, None, capacity, limits)?;
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
            let pre: &[u8] = b"<< /FT /Sig /T (Seal-DocTimeStamp-";
            let mid: &[u8] = b") /V ";
            let suf: &[u8] = b" 0 R >>";
            let len_field = decimal_len_u64(u64::from(field_num));
            let len_sig = decimal_len_u64(u64::from(sig_num));
            let mut field: Vec<u8> = admitted::vec(
                limits,
                pre.len() + len_field + mid.len() + len_sig + suf.len(),
            )
            .map_err(memory_error)?;
            field.extend_from_slice(pre);
            push_decimal_u64(&mut field, u64::from(field_num));
            field.extend_from_slice(mid);
            push_decimal_u64(&mut field, u64::from(sig_num));
            field.extend_from_slice(suf);
            admitted::push(limits, &mut objs, (sig_num, 0, sig_body)).map_err(memory_error)?;
            admitted::push(limits, &mut objs, (field_num, 0, field)).map_err(memory_error)?;
            sig_info = Some((sig_num, br_rel, lt_rel));
            register_field(state, &mut objs, &mut next, field_num, limits)?;
        }
        RevisionKind::Dss {
            material_objects,
            dss_obj,
        } => {
            for (num, body) in material_objects {
                let mut copy: Vec<u8> = admitted::vec(limits, body.len()).map_err(memory_error)?;
                copy.extend_from_slice(body);
                admitted::push(limits, &mut objs, (*num, 0, copy)).map_err(memory_error)?;
            }
            admitted::dictionary(limits, &state.root_dict).map_err(memory_error)?;
            let mut catalog = state.root_dict.clone();
            admit_dict_insert(limits, b"DSS".len())?;
            catalog.set(b"DSS", Object::Reference((*dss_obj, 0)));
            let mut body = Vec::new();
            write_object(&Object::Dictionary(catalog), &mut body, limits)?;
            admitted::push(limits, &mut objs, (state.root.0, state.root.1, body))
                .map_err(memory_error)?;
        }
    }
    Ok((objs, sig_info))
}
