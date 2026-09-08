//! Byte-exact incremental append: xref table/stream emitters, EOF glue, ByteRange/Contents patch, hash and naming helpers.

use lopdf::Object;

use super::objects::{
    BYTERANGE_DIGITS, DraftRevision, ObjOut, RevisionKind, build_objects, write_hex_string,
};
use super::parse::{RevisionState, XrefStyle, fatal_pdf, input_invalid};
use crate::error::{FatalCode, InputInvalidCode, SealError, SealStage};

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
