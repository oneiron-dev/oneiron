//! Byte-exact incremental append: xref table/stream emitters, EOF glue, ByteRange/Contents patch, hash and naming helpers.

use lopdf::Object;

use super::admitted;
use super::objects::{
    BYTERANGE_DIGITS, DraftRevision, ObjOut, RevisionKind, build_objects, write_hex_string,
};
use super::parse::{RevisionState, XrefStyle, fatal_pdf, input_invalid};
use crate::api::SealResourceLimits;
use crate::error::{FatalCode, InputInvalidCode, SealError, SealStage};
use crate::memory::SealMemoryRefusal;

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

/// `format!("{:0width$}", value)` without any temporary allocation: leading
/// zeros to `width`, the full decimal when it runs longer. The caller admits
/// `decimal_len_u64(value).max(width)` first.
fn push_zero_padded_u64(out: &mut Vec<u8>, value: u64, width: usize) {
    let digits = decimal_len_u64(value);
    for _ in digits..width {
        out.push(b'0');
    }
    push_decimal_u64(out, value);
}

fn write_trailer_entries(
    state: &RevisionState,
    size: u64,
    out: &mut Vec<u8>,
    limits: &SealResourceLimits,
) -> Result<(), SealError> {
    let size_len = decimal_len_u64(size);
    let prev_len = decimal_len_u64(state.prev_startxref);
    admitted::reserve(
        limits,
        out,
        b"/Size ".len() + size_len + b" /Prev ".len() + prev_len + 1,
    )
    .map_err(memory_error)?;
    out.extend_from_slice(b"/Size ");
    push_decimal_u64(out, size);
    out.extend_from_slice(b" /Prev ");
    push_decimal_u64(out, state.prev_startxref);
    out.push(b' ');
    let root0_len = decimal_len_u64(u64::from(state.root.0));
    let root1_len = decimal_len_u64(u64::from(state.root.1));
    admitted::reserve(
        limits,
        out,
        b"/Root ".len() + root0_len + 1 + root1_len + b" R ".len(),
    )
    .map_err(memory_error)?;
    out.extend_from_slice(b"/Root ");
    push_decimal_u64(out, u64::from(state.root.0));
    out.push(b' ');
    push_decimal_u64(out, u64::from(state.root.1));
    out.extend_from_slice(b" R ");
    if let Some(info) = state.info {
        let info0_len = decimal_len_u64(u64::from(info.0));
        let info1_len = decimal_len_u64(u64::from(info.1));
        admitted::reserve(
            limits,
            out,
            b"/Info ".len() + info0_len + 1 + info1_len + b" R ".len(),
        )
        .map_err(memory_error)?;
        out.extend_from_slice(b"/Info ");
        push_decimal_u64(out, u64::from(info.0));
        out.push(b' ');
        push_decimal_u64(out, u64::from(info.1));
        out.extend_from_slice(b" R ");
    }
    if let Some(id) = &state.id {
        admitted::reserve(limits, out, b"/ID [".len()).map_err(memory_error)?;
        out.extend_from_slice(b"/ID [");
        for item in id {
            if let Object::String(s, _) = item {
                write_hex_string(s, out, limits)?;
                admitted::reserve(limits, out, 1).map_err(memory_error)?;
                out.push(b' ');
            }
        }
        admitted::reserve(limits, out, 1).map_err(memory_error)?;
        out.push(b']');
    }
    Ok(())
}

fn emit_xref_table(
    state: &RevisionState,
    objs: &[ObjOut],
    size: u64,
    out: &mut Vec<u8>,
    limits: &SealResourceLimits,
) -> Result<(), SealError> {
    admitted::reserve(limits, out, b"xref\n".len()).map_err(memory_error)?;
    out.extend_from_slice(b"xref\n");
    let mut sorted: Vec<&ObjOut> = admitted::vec(limits, objs.len()).map_err(memory_error)?;
    sorted.extend(objs.iter());
    sorted.sort_unstable_by_key(|o| o.num);
    let mut idx = 0;
    while idx < sorted.len() {
        let start = sorted[idx].num;
        let mut end = start;
        while idx + 1 < sorted.len() && sorted[idx + 1].num == end + 1 {
            idx += 1;
            end = sorted[idx].num;
        }
        let count = end - start + 1;
        let start_len = decimal_len_u64(u64::from(start));
        let count_len = decimal_len_u64(u64::from(count));
        admitted::reserve(limits, out, start_len + 1 + count_len + 1).map_err(memory_error)?;
        push_decimal_u64(out, u64::from(start));
        out.push(b' ');
        push_decimal_u64(out, u64::from(count));
        out.push(b'\n');
        for o in &sorted[idx + 1 - count as usize..=idx] {
            let off_len = decimal_len_u64(o.offset).max(10);
            let gen_len = decimal_len_u64(u64::from(o.generation)).max(5);
            admitted::reserve(limits, out, off_len + 1 + gen_len + b" n\r\n".len())
                .map_err(memory_error)?;
            push_zero_padded_u64(out, o.offset, 10);
            out.push(b' ');
            push_zero_padded_u64(out, u64::from(o.generation), 5);
            out.extend_from_slice(b" n\r\n");
        }
        idx += 1;
    }
    admitted::reserve(limits, out, b"trailer\n<< ".len()).map_err(memory_error)?;
    out.extend_from_slice(b"trailer\n<< ");
    write_trailer_entries(state, size, out, limits)?;
    admitted::reserve(limits, out, b">>\n".len()).map_err(memory_error)?;
    out.extend_from_slice(b">>\n");
    Ok(())
}

/// Xref-stream entry layout: /W [1 8 2] (type, 8-byte offset, 2-byte gen).
fn emit_xref_stream(
    state: &RevisionState,
    objs: &[ObjOut],
    xref_num: u32,
    xref_offset: u64,
    size: u64,
    out: &mut Vec<u8>,
    limits: &SealResourceLimits,
) -> Result<(), SealError> {
    let mut all: Vec<ObjOut> = admitted::vec(limits, objs.len()).map_err(memory_error)?;
    all.extend_from_slice(objs);
    admitted::push(
        limits,
        &mut all,
        ObjOut {
            num: xref_num,
            generation: 0,
            offset: xref_offset,
        },
    )
    .map_err(memory_error)?;
    all.sort_unstable_by_key(|o| o.num);
    let data_cap = all.len().checked_mul(11).ok_or_else(|| {
        memory_error(SealMemoryRefusal::Floor {
            needed: u64::MAX,
            available: 0,
        })
    })?;
    let mut data: Vec<u8> = admitted::vec(limits, data_cap).map_err(memory_error)?;
    let mut index: Vec<(u32, u32)> = Vec::new();
    let mut i = 0;
    while i < all.len() {
        let start = all[i].num;
        let mut count = 0u32;
        while i < all.len() && all[i].num == start + count {
            admitted::push(limits, &mut data, 1u8).map_err(memory_error)?;
            admitted::reserve(limits, &mut data, 8).map_err(memory_error)?;
            data.extend_from_slice(&all[i].offset.to_be_bytes());
            admitted::reserve(limits, &mut data, 2).map_err(memory_error)?;
            data.extend_from_slice(&all[i].generation.to_be_bytes());
            count += 1;
            i += 1;
        }
        admitted::push(limits, &mut index, (start, count)).map_err(memory_error)?;
    }
    let xref_len = decimal_len_u64(u64::from(xref_num));
    admitted::reserve(
        limits,
        out,
        xref_len + b" 0 obj\n<< /Type /XRef /W [1 8 2] ".len(),
    )
    .map_err(memory_error)?;
    push_decimal_u64(out, u64::from(xref_num));
    out.extend_from_slice(b" 0 obj\n<< /Type /XRef /W [1 8 2] ");
    admitted::reserve(limits, out, b"/Index [".len()).map_err(memory_error)?;
    out.extend_from_slice(b"/Index [");
    for (s, c) in &index {
        let s_len = decimal_len_u64(u64::from(*s));
        let c_len = decimal_len_u64(u64::from(*c));
        admitted::reserve(limits, out, s_len + 1 + c_len + 1).map_err(memory_error)?;
        push_decimal_u64(out, u64::from(*s));
        out.push(b' ');
        push_decimal_u64(out, u64::from(*c));
        out.push(b' ');
    }
    admitted::reserve(limits, out, b"] ".len()).map_err(memory_error)?;
    out.extend_from_slice(b"] ");
    write_trailer_entries(state, size, out, limits)?;
    let data_len = decimal_len_u64(data.len() as u64);
    admitted::reserve(
        limits,
        out,
        b"/Length ".len() + data_len + b" >>\nstream\n".len(),
    )
    .map_err(memory_error)?;
    out.extend_from_slice(b"/Length ");
    push_decimal_u64(out, data.len() as u64);
    out.extend_from_slice(b" >>\nstream\n");
    admitted::reserve(limits, out, data.len()).map_err(memory_error)?;
    out.extend_from_slice(&data);
    admitted::reserve(limits, out, b"\nendstream\nendobj\n".len()).map_err(memory_error)?;
    out.extend_from_slice(b"\nendstream\nendobj\n");
    Ok(())
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
    let limits = &state.limits;
    let (objs, sig_info) = build_objects(state, kind, capacity, limits)?;
    let mut out: Vec<u8> = admitted::vec(limits, input.len()).map_err(memory_error)?;
    out.extend_from_slice(input);
    // EOF glue: the first appended object header must start on its own
    // line even when the input's final %%EOF carries no trailing EOL
    // (a bare `%%EOF4 0 obj` line would corrupt both the marker and the
    // object). Emit exactly one EOL boundary: a missing newline is added;
    // a trailing '\r' is completed into CRLF.
    if !out.ends_with(b"\n") {
        admitted::reserve(limits, &mut out, 1).map_err(memory_error)?;
        out.push(b'\n');
    }
    let mut written: Vec<ObjOut> = admitted::vec(limits, objs.len()).map_err(memory_error)?;
    let mut contents_gap = None;
    let mut br_patch = None;
    for (num, generation, body) in &objs {
        let offset = out.len() as u64;
        let num_len = decimal_len_u64(u64::from(*num));
        let gen_len = decimal_len_u64(u64::from(*generation));
        admitted::reserve(limits, &mut out, num_len + 1 + gen_len + b" obj\n".len())
            .map_err(memory_error)?;
        push_decimal_u64(&mut out, u64::from(*num));
        out.push(b' ');
        push_decimal_u64(&mut out, u64::from(*generation));
        out.extend_from_slice(b" obj\n");
        if let Some((sig_num, br_rel, lt_rel)) = sig_info
            && sig_num == *num
        {
            let base = out.len();
            br_patch = Some(base + br_rel);
            contents_gap = Some((base + lt_rel, base + lt_rel + 1 + capacity * 2));
        }
        admitted::reserve(limits, &mut out, body.len()).map_err(memory_error)?;
        out.extend_from_slice(body);
        admitted::reserve(limits, &mut out, b"\nendobj\n".len()).map_err(memory_error)?;
        out.extend_from_slice(b"\nendobj\n");
        admitted::push(
            limits,
            &mut written,
            ObjOut {
                num: *num,
                generation: *generation,
                offset,
            },
        )
        .map_err(memory_error)?;
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
        None => emit_xref_table(state, &written, size, &mut out, limits)?,
        Some(n) => emit_xref_stream(state, &written, n, xref_offset, size, &mut out, limits)?,
    }
    let xref_off_len = decimal_len_u64(xref_offset);
    admitted::reserve(
        limits,
        &mut out,
        b"startxref\n".len() + xref_off_len + b"\n%%EOF".len(),
    )
    .map_err(memory_error)?;
    out.extend_from_slice(b"startxref\n");
    push_decimal_u64(&mut out, xref_offset);
    out.extend_from_slice(b"\n%%EOF");
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
        let at = pos
            .checked_add(
                i.checked_mul(BYTERANGE_DIGITS + 1)
                    .ok_or_else(|| fatal_pdf(FatalCode::PdfInvariantFailed))?,
            )
            .ok_or_else(|| fatal_pdf(FatalCode::PdfInvariantFailed))?;
        if at
            .checked_add(BYTERANGE_DIGITS)
            .is_none_or(|end| end > out.len())
        {
            return Err(fatal_pdf(FatalCode::PdfInvariantFailed));
        }
        let mut field = [b'0'; BYTERANGE_DIGITS];
        let mut tmp = *v;
        for slot in field.iter_mut().rev() {
            *slot = b'0' + (tmp % 10) as u8;
            tmp /= 10;
        }
        if tmp != 0 {
            return Err(fatal_pdf(FatalCode::PdfInvariantFailed));
        }
        out[at..at + BYTERANGE_DIGITS].copy_from_slice(&field);
    }
    Ok(())
}

/// Write the DER CMS into the `/Contents` hex gap, zero-padding the rest.
/// Returns `Err(ContentsCapacityExceeded)` when the DER does not fit; the
/// caller discards this candidate and rebuilds at the next capacity.
pub(crate) fn patch_contents(
    draft: &mut DraftRevision,
    der: &[u8],
    _limits: &SealResourceLimits,
) -> Result<(), SealError> {
    let (lt, gt) = draft
        .contents_gap
        .ok_or_else(|| fatal_pdf(FatalCode::PdfInvariantFailed))?;
    let gap = gt
        .checked_sub(lt)
        .and_then(|span| span.checked_sub(1))
        .ok_or_else(|| fatal_pdf(FatalCode::PdfInvariantFailed))?;
    if der.len().checked_mul(2).is_none_or(|need| need > gap) {
        return Err(SealError::Fatal {
            stage: SealStage::PdfIncrementalUpdate,
            code: FatalCode::ContentsCapacityExceeded,
        });
    }
    // The draft already owns this gap's allocation.
    let slot = &mut draft.bytes[lt + 1..gt];
    for (i, &b) in der.iter().enumerate() {
        slot[2 * i] = HEX_UPPER[(b >> 4) as usize];
        slot[2 * i + 1] = HEX_UPPER[(b & 0xF) as usize];
    }
    slot[der.len() * 2..].fill(b'0');
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
pub(crate) fn field_name_for(
    operation_id: &str,
    limits: &SealResourceLimits,
) -> Result<String, SealError> {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(operation_id.as_bytes());
    let mut name = admitted::vec(limits, 17).map_err(memory_error)?;
    name.extend_from_slice(b"Seal-");
    for &b in &digest[..6] {
        name.push(HEX_UPPER[(b >> 4) as usize]);
        name.push(HEX_UPPER[(b & 0xF) as usize]);
    }
    String::from_utf8(name).map_err(|_| fatal_pdf(FatalCode::PdfInvariantFailed))
}

/// PDF date representation of a unix-time-ms clock value.
pub(crate) fn pdf_date(unix_ms: u64, limits: &SealResourceLimits) -> Result<String, SealError> {
    use time::format_description::well_known::Rfc3339;
    let secs = i64::try_from(unix_ms / 1000).unwrap_or(i64::MAX);
    let dt =
        time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    limits.memory.admit::<u8>(64).map_err(memory_error)?;
    // D:YYYYMMDDHHmmSSZ
    let rfc = dt.format(&Rfc3339).unwrap_or_default();
    let mut out = admitted::vec(limits, 17).map_err(memory_error)?;
    out.extend_from_slice(b"D:");
    out.extend(rfc.bytes().filter(u8::is_ascii_digit).take(14));
    out.push(b'Z');
    String::from_utf8(out).map_err(|_| fatal_pdf(FatalCode::PdfInvariantFailed))
}
