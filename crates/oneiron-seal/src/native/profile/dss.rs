//! DSS serialization: stream objects, global Certs/OCSPs/CRLs arrays, DSS revision append.

use std::io::Write;

use crate::api::SealResourceLimits;
use crate::error::{InputInvalidCode, SealError, SealStage};
use crate::memory::{SealMemoryRefusal, SharedBytes};

use super::super::pdf;
use super::assembly::SealContext;

/// DSS revision material: global `/Certs`, `/OCSPs`, `/CRLs` arrays; `/VRI`
/// is not emitted in v1 (§7.5 step 5).
pub(crate) struct DssMaterial {
    pub certs_der: Vec<Vec<u8>>,
    /// OCSP responses keep the fetch's own admitted bytes until DSS serialization.
    pub ocsps_der: Vec<SharedBytes>,
    /// Each CRL is its fetch's own admitted bytes, held with their
    /// reservation until the DSS is written, and read in place (FIX 7655).
    pub crls_der: Vec<SharedBytes>,
}

/// Serialized DSS objects plus the DSS dictionary's own object number.
type DssObjects = (Vec<(u32, Vec<u8>)>, u32);

fn memory_error(refusal: SealMemoryRefusal) -> SealError {
    refusal.seal_error(SealStage::PdfIncrementalUpdate)
}

fn object_reference(num: u32, limits: &SealResourceLimits) -> Result<String, SealError> {
    let len = num
        .checked_ilog10()
        .map_or(1, |digits| digits as usize + 1)
        .saturating_add(b" 0 R".len());
    limits.memory.admit::<u8>(len).map_err(memory_error)?;
    Ok(format!("{num} 0 R"))
}

fn admit_reference_array(
    limits: &SealResourceLimits,
    output: &mut Vec<u8>,
    references: &[String],
    open_len: usize,
) -> Result<(), SealError> {
    let joined = references
        .iter()
        .fold(0usize, |len, reference| len.saturating_add(reference.len()))
        .saturating_add(references.len().saturating_sub(1));
    let formatted = open_len.saturating_add(joined).saturating_add(b"] ".len());
    // The joined and formatted strings coexist during the output extend.
    limits
        .memory
        .admit::<u8>(joined.saturating_add(formatted))
        .map_err(memory_error)?;
    pdf::admitted::reserve(limits, output, formatted).map_err(memory_error)
}

/// Serialize DSS stream objects and the DSS dictionary (which is included in
/// the returned object list). Returns `(objects, dss_dict_obj_num)` with
/// object numbers starting at `first_num`. Object numbers are allocated with
/// checked arithmetic: a crafted trailer `/Size` near `u32::MAX` must yield
/// a clean `ObjectLimitExceeded`, never a wrap or panic.
pub(crate) fn build_dss_objects(
    material: &DssMaterial,
    first_num: u32,
    limits: &SealResourceLimits,
) -> Result<DssObjects, SealError> {
    let total = material
        .certs_der
        .len()
        .saturating_add(material.ocsps_der.len())
        .saturating_add(material.crls_der.len())
        .saturating_add(1);
    let mut objs: Vec<(u32, Vec<u8>)> = pdf::admitted::vec(limits, total).map_err(memory_error)?;
    let mut next = first_num;
    let mut alloc = || {
        let n = next;
        next = n.checked_add(1).ok_or(SealError::InputInvalid {
            code: InputInvalidCode::ObjectLimitExceeded,
        })?;
        Ok(n)
    };
    let mut cert_refs =
        pdf::admitted::vec(limits, material.certs_der.len()).map_err(memory_error)?;
    let mut ocsp_refs =
        pdf::admitted::vec(limits, material.ocsps_der.len()).map_err(memory_error)?;
    let mut crl_refs = pdf::admitted::vec(limits, material.crls_der.len()).map_err(memory_error)?;
    for cert in &material.certs_der {
        let num = alloc()?;
        objs.push((num, stream_obj(cert, limits)?));
        cert_refs.push(object_reference(num, limits)?);
    }
    for ocsp in &material.ocsps_der {
        let num = alloc()?;
        objs.push((num, stream_obj(ocsp, limits)?));
        ocsp_refs.push(object_reference(num, limits)?);
    }
    for crl in &material.crls_der {
        let num = alloc()?;
        objs.push((num, stream_obj(crl, limits)?));
        crl_refs.push(object_reference(num, limits)?);
    }
    let dss_num = alloc()?;
    let mut dss = pdf::admitted::vec(limits, b"<< /Type /DSS ".len()).map_err(memory_error)?;
    dss.extend_from_slice(b"<< /Type /DSS ");
    if !cert_refs.is_empty() {
        admit_reference_array(limits, &mut dss, &cert_refs, b"/Certs [".len())?;
        dss.extend_from_slice(format!("/Certs [{}] ", cert_refs.join(" ")).as_bytes());
    }
    if !ocsp_refs.is_empty() {
        admit_reference_array(limits, &mut dss, &ocsp_refs, b"/OCSPs [".len())?;
        dss.extend_from_slice(format!("/OCSPs [{}] ", ocsp_refs.join(" ")).as_bytes());
    }
    if !crl_refs.is_empty() {
        admit_reference_array(limits, &mut dss, &crl_refs, b"/CRLs [".len())?;
        dss.extend_from_slice(format!("/CRLs [{}] ", crl_refs.join(" ")).as_bytes());
    }
    pdf::admitted::reserve(limits, &mut dss, b">>".len()).map_err(memory_error)?;
    dss.extend_from_slice(b">>");
    objs.push((dss_num, dss));
    Ok((objs, dss_num))
}

fn stream_obj(data: &[u8], limits: &SealResourceLimits) -> Result<Vec<u8>, SealError> {
    let digits = data
        .len()
        .checked_ilog10()
        .map_or(1, |digits| digits as usize + 1);
    let len = b"<< /Length "
        .len()
        .saturating_add(digits)
        .saturating_add(b" >>\nstream\n".len())
        .saturating_add(data.len())
        .saturating_add(b"\nendstream".len());
    let mut body = pdf::admitted::vec(limits, len).map_err(memory_error)?;
    write!(&mut body, "<< /Length {} >>\nstream\n", data.len())
        .expect("writing to a Vec cannot fail");
    body.extend_from_slice(data);
    body.extend_from_slice(b"\nendstream");
    Ok(body)
}

/// Append the DSS revision for B-LT. Returns updated bytes.
pub(super) fn append_dss(
    bytes: &[u8],
    ctx: &SealContext<'_>,
    material: &DssMaterial,
) -> Result<Vec<u8>, SealError> {
    let state = pdf::reparse_revision(bytes, ctx.limits)?;
    // A crafted trailer /Size pushing allocation past the object-number
    // space is invalid INPUT, not an internal invariant breach.
    let first_num = state
        .max_obj
        .checked_add(1)
        .ok_or(SealError::InputInvalid {
            code: InputInvalidCode::ObjectLimitExceeded,
        })?;
    let (objs, dss_num) = build_dss_objects(material, first_num, ctx.limits)?;
    let kind = pdf::RevisionKind::Dss {
        material_objects: objs,
        dss_obj: dss_num,
    };
    let draft = pdf::append_revision(bytes, &state, &kind, 0)?;
    Ok(draft.bytes)
}
