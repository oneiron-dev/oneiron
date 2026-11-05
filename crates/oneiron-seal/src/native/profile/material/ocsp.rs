//! OCSP fallback for a certificate not covered by a working CRL.

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::{AnyRef, OctetString};
use der::{Decode, Encode, Reader, SliceReader, Tag, TagNumber, Tagged};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_ocsp::{CertId, OcspRequest, Request, TbsRequest};

use crate::api::{FetchError, FetchMethod, FetchPurpose, FetchRequest};
use crate::error::{SealError, SealStage};
use crate::memory::{LedgerHold, MemoryLedger, SealMemoryRefusal, SharedBytes};
use crate::native::verify;

use super::super::assembly::SealContext;

const OID_AD_OCSP: &[u8] = b"\x2b\x06\x01\x05\x05\x07\x30\x01";
const REQUEST_CONTENT_TYPE: &str = "application/ocsp-request";

/// Read AIA descriptions in place. Decoding the optional discovery extension
/// does not copy its names or build an owned list beside the admitted cert.
fn ocsp_uris(cert: &Certificate) -> impl Iterator<Item = &str> {
    cert.tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|ext| ext.extn_id == x509_cert::ext::pkix::AuthorityInfoAccessSyntax::OID)
        .filter_map(|ext| {
            let sequence = AnyRef::from_der(ext.extn_value.as_bytes()).ok()?;
            (sequence.tag() == Tag::Sequence).then_some(sequence.value())
        })
        .flat_map(|descriptions| {
            let mut reader = SliceReader::new(descriptions).ok();
            std::iter::from_fn(move || {
                loop {
                    let reader = reader.as_mut()?;
                    if reader.is_finished() || reader.is_failed() {
                        return None;
                    }
                    let description = reader.decode::<AnyRef<'_>>().ok()?;
                    let uri = description
                        .sequence(|fields| {
                            let method = fields.decode::<ObjectIdentifier>()?;
                            let location = fields.decode::<AnyRef<'_>>()?;
                            if method.as_bytes() != OID_AD_OCSP
                                || location.tag()
                                    != (Tag::ContextSpecific {
                                        constructed: false,
                                        number: TagNumber::N6,
                                    })
                                || !location.value().is_ascii()
                            {
                                return Ok(None);
                            }
                            Ok(std::str::from_utf8(location.value()).ok())
                        })
                        .ok()
                        .flatten();
                    if let Some(uri) = uri {
                        return Some(uri);
                    }
                }
            })
        })
}

/// One unsigned, nonce-free request. Its exact encoded body keeps its hold
/// through the fetch; the name DER and owned CertID fields are temporary.
fn request_body(
    cert: &Certificate,
    issuer: &Certificate,
    memory: &MemoryLedger,
) -> Result<Option<(Vec<u8>, LedgerHold)>, SealMemoryRefusal> {
    let subject = &issuer.tbs_certificate.subject;
    let Some(subject_len) = subject
        .encoded_len()
        .ok()
        .and_then(|n| usize::try_from(n).ok())
    else {
        return Ok(None);
    };
    let subject_hold = memory.hold(subject_len)?;
    let mut subject_der = vec![0; subject_len];
    if subject.encode_to_slice(&mut subject_der).is_err() {
        return Ok(None);
    }
    // Two SHA-256 output buffers, the cloned serial, and one request-list
    // slot. vec![Request] below allocates exactly that one slot.
    let request_hold = memory.hold(
        <Sha256 as Digest>::output_size()
            .saturating_mul(2)
            .saturating_add(cert.tbs_certificate.serial_number.as_bytes().len())
            .saturating_add(std::mem::size_of::<Request>()),
    )?;
    let id = (|| -> der::Result<CertId> {
        Ok(CertId {
            hash_algorithm: spki::AlgorithmIdentifierOwned {
                oid: Sha256::OID,
                parameters: Some(der::asn1::Null.into()),
            },
            issuer_name_hash: OctetString::new(Sha256::digest(&subject_der).to_vec())?,
            issuer_key_hash: OctetString::new(
                Sha256::digest(
                    issuer
                        .tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .raw_bytes(),
                )
                .to_vec(),
            )?,
            serial_number: cert.tbs_certificate.serial_number.clone(),
        })
    })();
    let Ok(id) = id else {
        return Ok(None);
    };
    drop(subject_der);
    drop(subject_hold);
    let request = OcspRequest {
        tbs_request: TbsRequest {
            request_list: vec![Request {
                req_cert: id,
                single_request_extensions: None,
            }],
            ..TbsRequest::default()
        },
        optional_signature: None,
    };
    let Some(len) = request
        .encoded_len()
        .ok()
        .and_then(|n| usize::try_from(n).ok())
    else {
        return Ok(None);
    };
    let body_hold = memory.hold(len)?;
    let mut body = vec![0; len];
    if request.encode_to_slice(&mut body).is_err() {
        return Ok(None);
    }
    drop(request);
    drop(request_hold);
    Ok(Some((body, body_hold)))
}

pub(super) async fn fetch_valid_ocsp(
    ctx: &SealContext<'_>,
    cert_der: &[u8],
    issuer_der: &[u8],
    memory: &MemoryLedger,
) -> Result<Option<SharedBytes>, SealError> {
    let resource_error = |refusal: SealMemoryRefusal| refusal.seal_error(SealStage::Revocation);
    let Some(cert) = verify::EmbeddedCert::admitted(cert_der, memory).map_err(resource_error)?
    else {
        return Ok(None);
    };
    let Some(issuer) =
        verify::EmbeddedCert::admitted(issuer_der, memory).map_err(resource_error)?
    else {
        return Ok(None);
    };
    let embedded = [cert, issuer];
    for uri in ocsp_uris(embedded[0].certificate()) {
        // The discovery string is borrowed; reserve its URL storage before
        // handing it to the existing URL parser.
        let _url_hold = memory.hold(uri.len()).map_err(resource_error)?;
        let Ok(url) = url::Url::parse(uri) else {
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") {
            continue;
        }
        let Some((body, body_hold)) =
            request_body(embedded[0].certificate(), embedded[1].certificate(), memory)
                .map_err(resource_error)?
        else {
            return Ok(None);
        };
        // The content type and the organ fetch ask's URL/purpose strings
        // remain held while the request is sent. The DER body is moved.
        let _metadata_hold = memory
            .hold(
                url.as_str()
                    .len()
                    .saturating_add(REQUEST_CONTENT_TYPE.len())
                    .saturating_add("ocsp".len()),
            )
            .map_err(resource_error)?;
        let response = ctx
            .fetcher
            .fetch(FetchRequest {
                purpose: FetchPurpose::Ocsp,
                url,
                method: FetchMethod::Post,
                request_body: body,
                content_type: Some(REQUEST_CONTENT_TYPE.to_owned()),
            })
            .await;
        drop(body_hold);
        let response = match response {
            Ok(response) => response,
            Err(FetchError::Memory(refusal)) => return Err(resource_error(refusal)),
            Err(_) => continue,
        };
        // The key-bound issuer is already present. The existing validator
        // also admits and checks any delegated responder in the response.
        let targets =
            verify::ocsp_entry_valid(&response.body, &embedded, &[], ctx.clock_ms / 1000, memory)
                .map_err(resource_error)?;
        if targets.is_some_and(|targets| targets.contains(&cert_der)) {
            return Ok(Some(response.body));
        }
    }
    Ok(None)
}
