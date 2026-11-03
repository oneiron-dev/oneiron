//! DSS serialization: stream objects, global Certs/OCSPs/CRLs arrays, DSS revision append.

use crate::error::{InputInvalidCode, SealError, SealStage};
use crate::memory::{MemoryLedger, SharedBytes};

use super::super::pdf;
use super::assembly::SealContext;

/// DSS revision material: global `/Certs`, `/OCSPs`, `/CRLs` arrays; `/VRI`
/// is not emitted in v1 (§7.5 step 5).
pub(crate) struct DssMaterial {
    pub certs_der: Vec<Vec<u8>>,
    pub ocsps_der: Vec<Vec<u8>>,
    /// Each CRL is its fetch's own admitted bytes, held with their
    /// reservation until the DSS is written, and read in place (FIX 7655).
    pub crls_der: Vec<SharedBytes>,
}

/// Serialized DSS objects plus the DSS dictionary's own object number.
type DssObjects = (Vec<(u32, Vec<u8>)>, u32);

/// Serialize DSS stream objects and the DSS dictionary (which is included in
/// the returned object list). Returns `(objects, dss_dict_obj_num)` with
/// object numbers starting at `first_num`. Object numbers are allocated with
/// checked arithmetic: a crafted trailer `/Size` near `u32::MAX` must yield
/// a clean `ObjectLimitExceeded`, never a wrap or panic. Every stream body,
/// reference string, and the dictionary draft is admitted on `memory` before
/// it is built; fetched CRL bytes stay under their own leases and are read in
/// place, never re-charged.
pub(crate) fn build_dss_objects(
    material: &DssMaterial,
    first_num: u32,
    memory: &MemoryLedger,
) -> Result<DssObjects, SealError> {
    let admit = |bytes: usize| {
        memory
            .admit_len::<u8>(bytes)
            .map_err(|refusal| refusal.seal_error(SealStage::Dss))
    };
    let entries = material
        .certs_der
        .len()
        .saturating_add(material.ocsps_der.len())
        .saturating_add(material.crls_der.len());
    memory
        .admit_len::<(u32, Vec<u8>)>(entries.saturating_add(1))
        .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
    memory
        .admit_len::<String>(material.certs_der.len())
        .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
    memory
        .admit_len::<String>(material.ocsps_der.len())
        .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
    memory
        .admit_len::<String>(material.crls_der.len())
        .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
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
    // A `stream_obj` body is its input plus a `<< /Length N >>\nstream\n`
    // header (at most 32 bytes for a 64-bit length) and a 10-byte trailer;
    // a `{num} 0 R` reference is at most 15 bytes for a u32 number.
    let stream_admit = |data_len: usize| admit(data_len.saturating_add(48));
    for cert in &material.certs_der {
        let num = alloc()?;
        stream_admit(cert.len())?;
        admit(16)?;
        objs.push((num, stream_obj(cert)));
        cert_refs.push(format!("{num} 0 R"));
    }
    for ocsp in &material.ocsps_der {
        let num = alloc()?;
        stream_admit(ocsp.len())?;
        admit(16)?;
        objs.push((num, stream_obj(ocsp)));
        ocsp_refs.push(format!("{num} 0 R"));
    }
    for crl in &material.crls_der {
        let num = alloc()?;
        stream_admit(crl.len())?;
        admit(16)?;
        objs.push((num, stream_obj(crl)));
        crl_refs.push(format!("{num} 0 R"));
    }
    let dss_num = alloc()?;
    // The dictionary draft: its fixed head and tail plus one `/Certs [...]`
    // style section per non-empty array, each admitted before its `format!`
    // and `join` temporaries are built.
    let refs_len = |refs: &[String]| {
        refs.iter()
            .map(String::len)
            .sum::<usize>()
            .saturating_add(refs.len())
    };
    admit(15usize.saturating_add(2))?;
    if !cert_refs.is_empty() {
        admit(refs_len(&cert_refs).saturating_add(32))?;
    }
    if !ocsp_refs.is_empty() {
        admit(refs_len(&ocsp_refs).saturating_add(32))?;
    }
    if !crl_refs.is_empty() {
        admit(refs_len(&crl_refs).saturating_add(32))?;
    }
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
    let state = pdf::reparse_revision(bytes, ctx.limits)?;
    // A crafted trailer /Size pushing allocation past the object-number
    // space is invalid INPUT, not an internal invariant breach.
    let first_num = state
        .max_obj
        .checked_add(1)
        .ok_or(SealError::InputInvalid {
            code: InputInvalidCode::ObjectLimitExceeded,
        })?;
    let memory = ctx
        .limits
        .memory
        .ledger()
        .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
    let (objs, dss_num) = build_dss_objects(material, first_num, &memory)?;
    let kind = pdf::RevisionKind::Dss {
        material_objects: objs,
        dss_obj: dss_num,
    };
    let draft = pdf::append_revision(bytes, &state, &kind, 0)?;
    Ok(draft.bytes)
}
