//! DSS serialization: stream objects, global Certs/OCSPs/CRLs arrays, DSS revision append.

use crate::error::{InputInvalidCode, SealError};

use super::super::pdf;
use super::assembly::SealContext;

/// DSS revision material: global `/Certs`, `/OCSPs`, `/CRLs` arrays; `/VRI`
/// is not emitted in v1 (§7.5 step 5).
pub(crate) struct DssMaterial {
    pub certs_der: Vec<Vec<u8>>,
    pub ocsps_der: Vec<Vec<u8>>,
    pub crls_der: Vec<Vec<u8>>,
}

/// Serialized DSS objects plus the DSS dictionary's own object number.
type DssObjects = (Vec<(u32, Vec<u8>)>, u32);

/// Serialize DSS stream objects and the DSS dictionary (which is included in
/// the returned object list). Returns `(objects, dss_dict_obj_num)` with
/// object numbers starting at `first_num`. Object numbers are allocated with
/// checked arithmetic: a crafted trailer `/Size` near `u32::MAX` must yield
/// a clean `ObjectLimitExceeded`, never a wrap or panic.
pub(crate) fn build_dss_objects(
    material: &DssMaterial,
    first_num: u32,
) -> Result<DssObjects, SealError> {
    let mut objs: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut next = first_num;
    let mut alloc = || {
        let n = next;
        next = n.checked_add(1).ok_or(SealError::InputInvalid {
            code: InputInvalidCode::ObjectLimitExceeded,
        })?;
        Ok(n)
    };
    let mut cert_refs = Vec::new();
    let mut ocsp_refs = Vec::new();
    let mut crl_refs = Vec::new();
    for cert in &material.certs_der {
        let num = alloc()?;
        objs.push((num, stream_obj(cert)));
        cert_refs.push(format!("{num} 0 R"));
    }
    for ocsp in &material.ocsps_der {
        let num = alloc()?;
        objs.push((num, stream_obj(ocsp)));
        ocsp_refs.push(format!("{num} 0 R"));
    }
    for crl in &material.crls_der {
        let num = alloc()?;
        objs.push((num, stream_obj(crl)));
        crl_refs.push(format!("{num} 0 R"));
    }
    let dss_num = alloc()?;
    let mut dss = b"<< /Type /DSS ".to_vec();
    if !cert_refs.is_empty() {
        dss.extend_from_slice(format!("/Certs [{}] ", cert_refs.join(" ")).as_bytes());
    }
    if !ocsp_refs.is_empty() {
        dss.extend_from_slice(format!("/OCSPs [{}] ", ocsp_refs.join(" ")).as_bytes());
    }
    if !crl_refs.is_empty() {
        dss.extend_from_slice(format!("/CRLs [{}] ", crl_refs.join(" ")).as_bytes());
    }
    dss.extend_from_slice(b">>");
    objs.push((dss_num, dss));
    Ok((objs, dss_num))
}

fn stream_obj(data: &[u8]) -> Vec<u8> {
    let mut body = format!("<< /Length {} >>\nstream\n", data.len()).into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(b"\nendstream");
    body
}

/// Append the DSS revision for B-LT. Returns updated bytes.
pub(super) fn append_dss(
    bytes: &[u8],
    ctx: &SealContext<'_>,
    material: &DssMaterial,
) -> Result<Vec<u8>, SealError> {
    let state = pdf::reparse_revision(bytes, &ctx.config.resource_limits)?;
    // A crafted trailer /Size pushing allocation past the object-number
    // space is invalid INPUT, not an internal invariant breach.
    let first_num = state
        .max_obj
        .checked_add(1)
        .ok_or(SealError::InputInvalid {
            code: InputInvalidCode::ObjectLimitExceeded,
        })?;
    let (objs, dss_num) = build_dss_objects(material, first_num)?;
    let kind = pdf::RevisionKind::Dss {
        material_objects: objs,
        dss_obj: dss_num,
    };
    let draft = pdf::append_revision(bytes, &state, &kind, 0)?;
    Ok(draft.bytes)
}
