//! Core half of `blob_artifact::esign::signature_revision`: its store-layer items live in `oneiron_store::blob_artifact::esign::signature_revision` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::blob_artifact::esign::signature_revision::*;

use super::render::PdfPreparationError;
use super::sealer::{EsignSealInput, EsignSignatureRevision};
use crate::limit_ask::EngineLimit;
use lopdf::{
    DecodeAdmission, DecodeAdmissionError, Dictionary, Document, LoadOptions, Object, ObjectId,
    StringFormat,
};
use oneiron_docedit::resource::{Hold, ResourceRefusal, wide};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(test)]
#[path = "signature_revision_tests.rs"]
mod tests;

type Result<T> = std::result::Result<T, PdfPreparationError>;

impl EsignSealInput {
    /// Writes the signature revisions of a prepared PDF, one per rung of
    /// [`SEAL_CONTENTS_LADDER`]. `operation_id` names the signature field and
    /// `now_ms` dates it. Each stream decodes within the `[limits]
    /// esign_seal_stream_codec_bytes` row's default; a vault's seal reads
    /// the PDF under its configured row.
    ///
    /// # Errors
    /// [`PdfPreparationError::MalformedPdf`] for a PDF this writer cannot
    /// append to: it reads the classic xref table the preparation writes.
    pub fn new(pdf: Vec<u8>, operation_id: &str, now_ms: u64) -> Result<Self> {
        let codec_bytes = STREAM_CODEC_ROW.default_bound();
        Ok(Self::measured(pdf, operation_id, now_ms, codec_bytes)?.0)
    }

    /// [`Self::new`], each stream decoded within `codec_bytes` (the
    /// configured `[limits] esign_seal_stream_codec_bytes` row), with the
    /// bytes the prepared PDF's largest stream decoded to while it was read,
    /// for the `seal_prepared_stream_bytes` row.
    ///
    /// # Errors
    /// As [`Self::new`], and [`PdfPreparationError::StreamPastCodecBound`]
    /// for a stream past `codec_bytes`.
    pub(crate) fn measured(
        pdf: Vec<u8>,
        operation_id: &str,
        now_ms: u64,
        codec_bytes: u64,
    ) -> Result<(Self, u64)> {
        let codec = usize::try_from(codec_bytes).unwrap_or(usize::MAX);
        let (base, stream_bytes) = Base::read(&pdf, codec)?;
        let revisions = SEAL_CONTENTS_LADDER
            .iter()
            .map(|&capacity| base.revision(pdf.len(), operation_id, now_ms, capacity))
            .collect::<Result<_>>()?;
        Ok((Self { pdf, revisions }, stream_bytes))
    }
}

impl EsignSealInput {
    /// Replaces the revisions with one fresh revision whose hole holds at
    /// least `needed` DER bytes (FIX 6270): twice the largest written so far,
    /// or `needed` to the next power of two when that is more, so a fresh
    /// CMS a few bytes longer still fits. `false`, with nothing changed, when
    /// `needed` already fits the largest: no larger revision would help.
    ///
    /// # Errors
    /// As [`Self::measured`].
    pub(crate) fn rewrite_larger(
        &mut self,
        operation_id: &str,
        now_ms: u64,
        codec_bytes: u64,
        needed: u64,
    ) -> Result<bool> {
        let largest = self
            .revisions
            .iter()
            .filter_map(|revision| {
                let [_, open, close, _] = revision.byte_range;
                close
                    .checked_sub(open)?
                    .checked_sub(2)
                    .map(|digits| digits / 2)
            })
            .max()
            .unwrap_or(0);
        if needed <= largest {
            return Ok(false);
        }
        let doubled = largest.checked_mul(2).ok_or(PdfPreparationError::Limit)?;
        let next = needed
            .checked_next_power_of_two()
            .ok_or(PdfPreparationError::Limit)?;
        let capacity = doubled.max(next);
        if capacity > MAX_CLASSIC_XREF_OFFSET / 2 {
            return Err(PdfPreparationError::Limit);
        }
        let capacity = usize::try_from(capacity).map_err(|_| PdfPreparationError::Limit)?;
        let codec = usize::try_from(codec_bytes).unwrap_or(usize::MAX);
        let (base, _) = Base::read(&self.pdf, codec)?;
        self.revisions = vec![base.revision(self.pdf.len(), operation_id, now_ms, capacity)?];
        Ok(true)
    }
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

impl Base {
    /// The prepared PDF's base, and its largest decoded stream's bytes.
    fn read(pdf: &[u8], codec: usize) -> Result<(Self, u64)> {
        // Declared before `doc`: reverse drop order keeps the hold alive
        // while the tables, copies, and decodes it admitted live in `doc`.
        let admission = Arc::new(BaseAdmission::new(
            crate::entity_doc::document_resources::document_resources().hold(),
        ));
        let doc = Document::load_mem_with_options(
            pdf,
            LoadOptions {
                strict: true,
                max_decompressed_size: Some(codec), // KEPT: bound and admission compose
                decode_admission: Some(Arc::clone(&admission) as Arc<dyn DecodeAdmission>),
                ..LoadOptions::default()
            },
        )
        .map_err(|error| match error {
            lopdf::Error::DecodeAdmission(DecodeAdmissionError::MemoryFloor {
                needed,
                available,
            }) => PdfPreparationError::MemoryFloor { needed, available },
            // Deadline, plus Cancelled defensively: nothing on this path
            // cancels (no Cancelled source in the vendored load).
            lopdf::Error::DecodeAdmission(_) => PdfPreparationError::Deadline,
            other => match PdfPreparationError::from(other) {
                PdfPreparationError::Limit => {
                    PdfPreparationError::StreamPastCodecBound(STREAM_CODEC_ROW)
                }
                other => other,
            },
        })?;
        let stream_bytes = admission
            .max_decoded()
            .max(uncompressed_xref_bytes(&doc, codec));
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
        let hole_digits = capacity.checked_mul(2).ok_or(PdfPreparationError::Limit)?;
        let reserve = hole_digits
            .checked_add(4096)
            .ok_or(PdfPreparationError::Limit)?;
        if u64::try_from(reserve).unwrap_or(u64::MAX) > MAX_CLASSIC_XREF_OFFSET {
            return Err(PdfPreparationError::Limit);
        }
        let (sig_body, br_rel, lt_rel) = sig_dict_body(&pdf_date(now_ms), capacity)?;
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

        let mut out = Vec::new();
        out.try_reserve_exact(reserve)
            .map_err(|_| PdfPreparationError::Limit)?;
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
        let gt = lt
            .checked_add(1)
            .and_then(|value| value.checked_add(hole_digits))
            .ok_or(PdfPreparationError::Limit)?;
        let after_hole = gt.checked_add(1).ok_or(PdfPreparationError::Limit)?;
        let total = (base_len + out.len()) as u64;
        let byte_range = [
            0,
            lt as u64,
            after_hole as u64,
            total
                .checked_sub(after_hole as u64)
                .ok_or(PdfPreparationError::Limit)?,
        ];
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
fn sig_dict_body(date: &str, capacity: usize) -> Result<(Vec<u8>, usize, usize)> {
    let digits = capacity.checked_mul(2).ok_or(PdfPreparationError::Limit)?;
    let reserve = digits.checked_add(256).ok_or(PdfPreparationError::Limit)?;
    let mut body = Vec::new();
    body.try_reserve_exact(reserve)
        .map_err(|_| PdfPreparationError::Limit)?;
    body.extend_from_slice(b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached");
    body.extend_from_slice(b" /M ");
    write_literal_string(date, &mut body);
    body.extend_from_slice(b" /ByteRange [0 ");
    let br_rel = body.len();
    body.extend_from_slice(b"00000000000000000000 00000000000000000000 00000000000000000000");
    body.extend_from_slice(b"] /Contents <");
    let lt_rel = body.len() - 1;
    body.extend(std::iter::repeat_n(b'0', digits));
    body.extend_from_slice(b"> >>");
    Ok((body, br_rel, lt_rel))
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
