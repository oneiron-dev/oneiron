//! The ordinary signature revision, written on the engine's side of the seal
//! (ARCH-0075 `#organ-host-design-seal-binding`). The engine appends the
//! invisible signature field and widget, the signature dictionary with its
//! zero `/Contents` hole, the page `/Annots` and AcroForm links, the xref and
//! the trailer, and patches the ByteRange. The seal organ builds only the CMS
//! that fills the hole, so it never chooses a PDF object of the revision the
//! key signs. One revision is written for each contents capacity. The layout
//! is the native seal writer's, so its verifier reads it as its own. The
//! objects it re-emits keep every value and type: a real is written as the
//! shortest decimal that reads back as the same real, never rounded.

use lopdf::{Dictionary, Document, LoadOptions, Object, ObjectId, StringFormat};
use sha2::{Digest, Sha256};

use super::render::PdfPreparationError;
use super::sealer::{EsignSealInput, EsignSignatureRevision};

#[cfg(test)]
#[path = "signature_revision_tests.rs"]
mod tests;

/// The contents ladder: the DER bytes each revision's hole holds.
pub const SEAL_CONTENTS_LADDER: [usize; 3] = [64 * 1024, 128 * 1024, 256 * 1024];
const BYTERANGE_DIGITS: usize = 20;

type Result<T> = std::result::Result<T, PdfPreparationError>;

impl EsignSealInput {
    /// Writes the signature revisions of a prepared PDF, one per rung of
    /// [`SEAL_CONTENTS_LADDER`]. `operation_id` names the signature field and
    /// `now_ms` dates it.
    ///
    /// # Errors
    /// [`PdfPreparationError::MalformedPdf`] for a PDF this writer cannot
    /// append to: it reads the classic xref table the preparation writes.
    pub fn new(pdf: Vec<u8>, operation_id: &str, now_ms: u64) -> Result<Self> {
        Ok(Self::measured(pdf, operation_id, now_ms)?.0)
    }

    /// [`Self::new`], with the bytes the prepared PDF's largest stream
    /// decoded to while it was read, for the `seal_prepared_stream_bytes`
    /// row.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub(crate) fn measured(pdf: Vec<u8>, operation_id: &str, now_ms: u64) -> Result<(Self, u64)> {
        let (base, stream_bytes) = Base::read(&pdf)?;
        let revisions = SEAL_CONTENTS_LADDER
            .iter()
            .map(|&capacity| base.revision(pdf.len(), operation_id, now_ms, capacity))
            .collect::<Result<_>>()?;
        Ok((Self { pdf, revisions }, stream_bytes))
    }
}

/// The bytes the largest stream lopdf decoded while it read `doc` came to:
/// an object stream's, which it leaves decoded in place, or a
/// cross-reference stream's, decoded again here to be measured. Every
/// stream decodes whole, however large (Rule 5): the size is measured
/// against the `seal_prepared_stream_bytes` row, never refused.
fn largest_decoded_stream(doc: &Document) -> u64 {
    doc.objects
        .values()
        .filter_map(|object| object.as_stream().ok())
        .filter_map(|stream| {
            let kind = stream
                .dict
                .get(b"Type")
                .ok()
                .and_then(|kind| kind.as_name().ok());
            match kind {
                Some(b"ObjStm") if !stream.is_compressed() => Some(stream.content.len()),
                Some(b"ObjStm" | b"XRef") => stream
                    .decompressed_content()
                    .ok()
                    .map(|content| content.len()),
                _ => None,
            }
        })
        .map(|len| len as u64)
        .max()
        .unwrap_or(0)
}

/// What appending one revision needs from the prepared PDF.
struct Base {
    pdf_ends_with_eol: bool,
    max_obj: u32,
    root: ObjectId,
    info: Option<ObjectId>,
    id: Option<Vec<Object>>,
    prev_startxref: u64,
    acroform: Option<ObjectId>,
    acroform_dict: Option<Dictionary>,
    acroform_fields: Vec<Object>,
    first_page: ObjectId,
    first_page_dict: Dictionary,
    first_page_annots: Vec<Object>,
    root_dict: Dictionary,
}

fn malformed<T>(_: T) -> PdfPreparationError {
    PdfPreparationError::MalformedPdf
}

fn reference(object: &Object) -> Option<ObjectId> {
    match object {
        Object::Reference(id) => Some(*id),
        _ => None,
    }
}

impl Base {
    /// The prepared PDF's base, and its largest decoded stream's bytes.
    fn read(pdf: &[u8]) -> Result<(Self, u64)> {
        let doc = Document::load_mem_with_options(
            pdf,
            LoadOptions {
                strict: true,
                ..LoadOptions::default()
            },
        )?;
        let stream_bytes = largest_decoded_stream(&doc);
        let prev_startxref = last_startxref(pdf)?;
        let at = usize::try_from(prev_startxref).map_err(malformed)?;
        if pdf.get(at..at.saturating_add(4)) != Some(b"xref".as_slice())
            || doc.trailer.has(b"XRefStm")
        {
            return Err(PdfPreparationError::MalformedPdf);
        }
        let trailer = &doc.trailer;
        let root = trailer
            .get(b"Root")
            .ok()
            .and_then(reference)
            .ok_or(PdfPreparationError::MalformedPdf)?;
        let info = trailer.get(b"Info").ok().and_then(reference);
        let id = match trailer.get(b"ID") {
            Ok(Object::Array(items)) => Some(items.clone()),
            _ => None,
        };
        let root_dict = doc.get_object(root)?.as_dict()?.clone();
        let (acroform, acroform_dict) = match root_dict.get(b"AcroForm") {
            Ok(Object::Reference(id)) => (
                Some(*id),
                doc.get_object(*id)
                    .ok()
                    .and_then(|object| object.as_dict().ok())
                    .cloned(),
            ),
            Ok(Object::Dictionary(dict)) => (None, Some(dict.clone())),
            _ => (None, None),
        };
        let acroform_fields = match acroform_dict.as_ref().and_then(|d| d.get(b"Fields").ok()) {
            Some(fields) => doc
                .dereference(fields)
                .ok()
                .and_then(|(_, object)| object.as_array().ok().cloned())
                .ok_or(PdfPreparationError::MalformedPdf)?,
            None => Vec::new(),
        };
        let first_page = *doc
            .get_pages()
            .values()
            .next()
            .ok_or(PdfPreparationError::MalformedPdf)?;
        let first_page_dict = doc.get_object(first_page)?.as_dict()?.clone();
        let first_page_annots = first_page_dict
            .get(b"Annots")
            .ok()
            .and_then(|annots| {
                doc.dereference(annots)
                    .ok()
                    .and_then(|(_, object)| object.as_array().ok().cloned())
            })
            .unwrap_or_default();
        let max_existing = doc.objects.keys().map(|(num, _)| *num).max().unwrap_or(0);
        let size_max = match trailer.get(b"Size") {
            Ok(size) => size
                .as_i64()
                .ok()
                .and_then(|size| u64::try_from(size).ok())
                .and_then(|size| size.checked_sub(1))
                .and_then(|size| u32::try_from(size).ok())
                .ok_or(PdfPreparationError::Limit)?,
            Err(_) => 0,
        };
        let base = Self {
            pdf_ends_with_eol: pdf.ends_with(b"\n"),
            max_obj: max_existing.max(size_max),
            root,
            info,
            id,
            prev_startxref,
            acroform,
            acroform_dict,
            acroform_fields,
            first_page,
            first_page_dict,
            first_page_annots,
            root_dict,
        };
        Ok((base, stream_bytes))
    }

    /// The suffix that appends one signature revision with a hole of
    /// `capacity` DER bytes, its ByteRange patched.
    fn revision(
        &self,
        base_len: usize,
        operation_id: &str,
        now_ms: u64,
        capacity: usize,
    ) -> Result<EsignSignatureRevision> {
        let mut next = self
            .max_obj
            .checked_add(1)
            .ok_or(PdfPreparationError::Limit)?;
        let sig_num = next_obj(&mut next)?;
        let field_num = next_obj(&mut next)?;
        let (sig_body, br_rel, lt_rel) = sig_dict_body(&pdf_date(now_ms), capacity);
        let mut field = b"<< /FT /Sig /T ".to_vec();
        write_literal_string(&field_name(operation_id), &mut field);
        field.extend_from_slice(
            format!(
                " /V {sig_num} 0 R /Type /Annot /Subtype /Widget \
                 /Rect [0 0 0 0] /F 4 /P {} {} R >>",
                self.first_page.0, self.first_page.1
            )
            .as_bytes(),
        );
        let mut objects = vec![(sig_num, 0, sig_body), (field_num, 0, field)];
        let mut page = self.first_page_dict.clone();
        let mut annots = self.first_page_annots.clone();
        annots.push(Object::Reference((field_num, 0)));
        page.set(b"Annots", Object::Array(annots));
        objects.push((
            self.first_page.0,
            self.first_page.1,
            dictionary_bytes(page)?,
        ));
        self.register_field(&mut objects, &mut next, field_num)?;

        let mut out = Vec::with_capacity(capacity * 2 + 4096);
        if !self.pdf_ends_with_eol {
            out.push(b'\n');
        }
        let mut written = Vec::with_capacity(objects.len());
        let mut patch = None;
        for (num, generation, body) in &objects {
            written.push((*num, *generation, (base_len + out.len()) as u64));
            out.extend_from_slice(format!("{num} {generation} obj\n").as_bytes());
            if *num == sig_num {
                patch = Some((out.len() + br_rel, base_len + out.len() + lt_rel));
            }
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        let (br_at, lt) = patch.ok_or(PdfPreparationError::Encoding)?;
        let max_used = written
            .iter()
            .map(|(num, _, _)| *num)
            .max()
            .unwrap_or(self.max_obj);
        let xref_offset = (base_len + out.len()) as u64;
        self.xref_table(&mut written, u64::from(max_used) + 1, &mut out);
        out.extend_from_slice(format!("startxref\n{xref_offset}\n%%EOF").as_bytes());
        let gt = lt + 1 + capacity * 2;
        let total = (base_len + out.len()) as u64;
        let byte_range = [0, lt as u64, gt as u64 + 1, total - (gt as u64 + 1)];
        for (i, value) in byte_range[1..].iter().enumerate() {
            let at = br_at + i * (BYTERANGE_DIGITS + 1);
            let digits = format!("{value:0BYTERANGE_DIGITS$}");
            if digits.len() != BYTERANGE_DIGITS {
                return Err(PdfPreparationError::Limit);
            }
            out[at..at + BYTERANGE_DIGITS].copy_from_slice(digits.as_bytes());
        }
        Ok(EsignSignatureRevision {
            suffix: out,
            byte_range,
        })
    }

    /// Lists the field in the AcroForm, creating it (and re-emitting the
    /// catalog) when it is absent, direct or dangling.
    fn register_field(
        &self,
        objects: &mut Vec<(u32, u16, Vec<u8>)>,
        next: &mut u32,
        field_num: u32,
    ) -> Result<()> {
        if let (Some(id), Some(dict)) = (self.acroform, self.acroform_dict.clone()) {
            let mut form = dict;
            let mut fields = self.acroform_fields.clone();
            fields.push(Object::Reference((field_num, 0)));
            form.set(b"Fields", Object::Array(fields));
            form.set(b"SigFlags", Object::Integer(3));
            objects.push((id.0, id.1, dictionary_bytes(form)?));
            return Ok(());
        }
        let form_num = next_obj(next)?;
        let mut form = self.acroform_dict.clone().unwrap_or_default();
        let mut fields = if self.acroform.is_some() {
            Vec::new()
        } else {
            self.acroform_fields.clone()
        };
        fields.push(Object::Reference((field_num, 0)));
        form.set(b"Fields", Object::Array(fields));
        form.set(b"SigFlags", Object::Integer(3));
        objects.push((form_num, 0, dictionary_bytes(form)?));
        let mut catalog = self.root_dict.clone();
        catalog.set(b"AcroForm", Object::Reference((form_num, 0)));
        objects.push((self.root.0, self.root.1, dictionary_bytes(catalog)?));
        Ok(())
    }

    fn xref_table(&self, written: &mut [(u32, u16, u64)], size: u64, out: &mut Vec<u8>) {
        out.extend_from_slice(b"xref\n");
        written.sort_by_key(|(num, _, _)| *num);
        for run in written.chunk_by(|a, b| b.0 == a.0 + 1) {
            out.extend_from_slice(format!("{} {}\n", run[0].0, run.len()).as_bytes());
            for (_, generation, offset) in run {
                out.extend_from_slice(format!("{offset:010} {generation:05} n\r\n").as_bytes());
            }
        }
        out.extend_from_slice(b"trailer\n<< ");
        out.extend_from_slice(format!("/Size {size} /Prev {} ", self.prev_startxref).as_bytes());
        out.extend_from_slice(format!("/Root {} {} R ", self.root.0, self.root.1).as_bytes());
        if let Some(info) = self.info {
            out.extend_from_slice(format!("/Info {} {} R ", info.0, info.1).as_bytes());
        }
        if let Some(id) = &self.id {
            out.extend_from_slice(b"/ID [");
            for item in id {
                if let Object::String(bytes, _) = item {
                    write_hex_string(bytes, out);
                    out.push(b' ');
                }
            }
            out.push(b']');
        }
        out.extend_from_slice(b">>\n");
    }
}

fn next_obj(next: &mut u32) -> Result<u32> {
    let num = *next;
    *next = num.checked_add(1).ok_or(PdfPreparationError::Limit)?;
    Ok(num)
}

/// The signature dictionary with a zero ByteRange and a `capacity`-byte
/// hole, and the offsets of the ByteRange digits and the hole's `<`.
fn sig_dict_body(date: &str, capacity: usize) -> (Vec<u8>, usize, usize) {
    let mut body = Vec::with_capacity(capacity * 2 + 256);
    body.extend_from_slice(b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached");
    body.extend_from_slice(b" /M ");
    write_literal_string(date, &mut body);
    body.extend_from_slice(b" /ByteRange [0 ");
    let br_rel = body.len();
    body.extend_from_slice(b"00000000000000000000 00000000000000000000 00000000000000000000");
    body.extend_from_slice(b"] /Contents <");
    let lt_rel = body.len() - 1;
    body.extend(std::iter::repeat_n(b'0', capacity * 2));
    body.extend_from_slice(b"> >>");
    (body, br_rel, lt_rel)
}

/// The field name the seal derives from its operation.
fn field_name(operation_id: &str) -> String {
    let digest = Sha256::digest(operation_id.as_bytes());
    let mut name = String::from("Seal-");
    for byte in &digest[..6] {
        name.push_str(&format!("{byte:02X}"));
    }
    name
}

/// `D:YYYYMMDDHHmmSSZ`.
fn pdf_date(unix_ms: u64) -> String {
    let secs = i64::try_from(unix_ms / 1000).unwrap_or(i64::MAX);
    let at = chrono::DateTime::from_timestamp(secs, 0).unwrap_or_default();
    format!("D:{}Z", at.format("%Y%m%d%H%M%S"))
}

fn last_startxref(pdf: &[u8]) -> Result<u64> {
    let at = pdf
        .windows(9)
        .rposition(|window| window == b"startxref")
        .ok_or(PdfPreparationError::MalformedPdf)?;
    let digits: Vec<u8> = pdf[at + 9..]
        .iter()
        .copied()
        .skip_while(|byte| matches!(byte, b' ' | b'\r' | b'\n' | b'\t'))
        .take_while(u8::is_ascii_digit)
        .collect();
    std::str::from_utf8(&digits)
        .ok()
        .and_then(|digits| digits.parse().ok())
        .ok_or(PdfPreparationError::MalformedPdf)
}

fn dictionary_bytes(dict: Dictionary) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_object(&Object::Dictionary(dict), &mut out)?;
    Ok(out)
}

/// The seal writer's serializer for the objects it re-emits. Streams are
/// never re-emitted; they stay reachable by reference.
fn write_object(object: &Object, out: &mut Vec<u8>) -> Result<()> {
    match object {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Object::Integer(value) => out.extend_from_slice(value.to_string().as_bytes()),
        Object::Real(value) => write_real(*value, out)?,
        Object::Name(name) => write_name(name, out),
        Object::String(bytes, StringFormat::Literal) => write_literal_bytes(bytes, out),
        Object::String(bytes, StringFormat::Hexadecimal) => write_hex_string(bytes, out),
        Object::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_object(item, out)?;
            }
            out.push(b']');
        }
        Object::Dictionary(dict) => {
            out.extend_from_slice(b"<< ");
            for (key, value) in dict {
                write_name(key, out);
                out.push(b' ');
                write_object(value, out)?;
                out.push(b' ');
            }
            out.extend_from_slice(b">>");
        }
        Object::Reference(id) => out.extend_from_slice(format!("{} {} R", id.0, id.1).as_bytes()),
        Object::Stream(_) => return Err(PdfPreparationError::UnsupportedPdf),
    }
    Ok(())
}

/// A real as the same real: the shortest decimal that reads back as the
/// same value, with a decimal point so it reads back as a real, not an
/// integer. Six places would turn 0.0000004 into 0, and `0` would turn 0.0
/// into an integer. An infinity, which lopdf reads from a decimal past f32,
/// is written as such a decimal again.
fn write_real(value: f32, out: &mut Vec<u8>) -> Result<()> {
    let text = if value.is_finite() {
        value.to_string()
    } else if value.is_infinite() {
        let sign = if value.is_sign_negative() { "-" } else { "" };
        format!("{sign}1{}", "0".repeat(39))
    } else {
        return Err(PdfPreparationError::MalformedPdf);
    };
    out.extend_from_slice(text.as_bytes());
    if !text.contains('.') {
        out.extend_from_slice(b".0");
    }
    Ok(())
}

/// A literal string as the same literal string: `(`, `)` and `\` escaped,
/// and every byte outside printable ASCII as a three-digit octal escape, so
/// no raw end of line is read back as another.
fn write_literal_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.push(b'(');
    for &byte in bytes {
        match byte {
            b'(' | b')' | b'\\' => out.extend_from_slice(&[b'\\', byte]),
            b' '..=b'~' => out.push(byte),
            _ => out.extend_from_slice(format!("\\{byte:03o}").as_bytes()),
        }
    }
    out.push(b')');
}

fn write_name(name: &[u8], out: &mut Vec<u8>) {
    out.push(b'/');
    for &byte in name {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+' | b'*') {
            out.push(byte);
        } else {
            out.extend_from_slice(format!("#{byte:02X}").as_bytes());
        }
    }
}

fn write_hex_string(bytes: &[u8], out: &mut Vec<u8>) {
    out.push(b'<');
    for byte in bytes {
        out.extend_from_slice(format!("{byte:02X}").as_bytes());
    }
    out.push(b'>');
}

fn write_literal_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'(');
    for &byte in text.as_bytes() {
        if matches!(byte, b'(' | b')' | b'\\') {
            out.push(b'\\');
        }
        out.push(byte);
    }
    out.push(b')');
}
