//! The trusted side's own proof of a seal's evidence (ARCH-0075
//! `#organ-host-design-seal-residual`, L4-13): the fresh verifier is the same
//! installed binary, a second opinion, so whatever the achieved profile
//! claims the host checks itself, from the bytes it holds, with general
//! crates (cms, x509-tsp, pkix-chain, lopdf at the engine's pins), never
//! the organ's code (ARCH-0064a §4, the profile table):
//! - B-T and above: the bound signature carries one signature timestamp, a
//!   valid RFC 3161 token over SHA-256 of its signature value, from an
//!   authority that chains to the seal's anchors with a critical, sole
//!   id-kp-timeStamping EKU. A token present below B-T is checked the same.
//! - B-LT and above: the DSS the archival suffix adds (the catalog's `/DSS`,
//!   written after the bound revision; read with lopdf, nothing else of the
//!   PDF) holds every non-anchor certificate of the signer chain and of each
//!   timestamp's authority chain, and for each certificate on those paths a
//!   CRL or OCSP response its issuer signed, fresh at the material's time,
//!   that does not list it. Every CRL and OCSP response in it must vouch for
//!   one of them: a DSS carries only evidence the engine can vouch for.
//! - B-LTA: a document timestamp after that DSS, covering every byte to the
//!   end of the file but its own hole, passes the same RFC 3161 checks over
//!   its two ranges; its time is the material's. Every document timestamp
//!   the classification names is checked, at any profile.
//!
//! The material's time follows the organ's own rule: the archival document
//! timestamp's genTime when there is one, else now. Anything an honest
//! organ never writes (a suffix below B-LT, a document timestamp below
//! B-LTA) fails the same way. A failed proof leaves the seal retryable
//! (ARCH-0064a SGN-04), never a nominally complete document.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString};
use der::referenced::OwnedToRef;
use der::{Decode, Encode, Reader, SliceReader};
use oneiron::blob_artifact::esign::{EsignSealerError, SealProfile};
use oneiron_organ_protocol::seal::{SealRevisionClassification, SealSignatureKind};
use pkix_chain::pkix_revocation::{self, RevocationChecker};
use pkix_chain::{
    CrlChecker, DefaultVerifier, NoAiaFetcher, NoRevocation, OcspChecker, SignatureVerifier,
    TrustAnchor, ValidationPolicy,
};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::binding::{AdmittedRevision, unhex};
use crate::resource_memory::{FloorLease, FloorRefusal, MachineFloor};

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_CERT_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const ID_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const ID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// deltaCRLIndicator and issuingDistributionPoint (RFC 5280 §5.2.4, §5.2.5):
/// a CRL with either is not complete evidence for its issuer.
const ID_DELTA_CRL_INDICATOR: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.27");
const ID_ISSUING_DISTRIBUTION_POINT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.28");
/// How far a genTime may run ahead of the engine's clock: the organ's own
/// bound (its `TS_GEN_TIME_MAX_SKEW_SECS`).
const GEN_TIME_SKEW_SECS: u64 = 300;
/// The keys a DSS the engine vouches for may hold (ARCH-0064a: `/Certs`,
/// `/OCSPs`, `/CRLs`; the seal writes no `/VRI`).
const DSS_KEYS: [&[u8]; 4] = [b"Type", b"Certs", b"CRLs", b"OCSPs"];

/// What a seal's evidence is proven against.
pub(super) struct EvidenceTrust<'a> {
    /// DER trust anchors, the seal's own (`SealSettings::trust_anchors`).
    pub(super) anchors: &'a [Vec<u8>],
    /// The policies a token may name; empty allows any.
    pub(super) policies: Vec<ObjectIdentifier>,
    pub(super) now_ms: u64,
    /// The machine floor the DSS read's decodes lease from, and until when.
    pub(super) floor: Option<Arc<dyn MachineFloor>>,
    pub(super) deadline: Instant,
}

/// Proves `sealed`'s evidence for `achieved`, as the module says.
///
/// # Errors
/// [`EsignSealerError::Retryable`] at stage `evidence`, with the code of
/// the first claim the host could not prove: `signature_timestamp_unproven`,
/// `validation_data_unproven` or `document_timestamp_unproven`;
/// `evidence_memory` when the DSS read found no memory before the deadline.
pub(super) fn prove_evidence(
    sealed: &[u8],
    witness: &AdmittedRevision,
    classification: &SealRevisionClassification,
    achieved: SealProfile,
    trust: &EvidenceTrust<'_>,
) -> Result<(), EsignSealerError> {
    let now = trust.now_ms / 1000;
    let anchors: Vec<TrustAnchor> = trust
        .anchors
        .iter()
        .map(|der| Certificate::from_der(der).map(TrustAnchor::from_cert))
        .collect::<Result<_, _>>()
        .map_err(|_| unproven(SIGNATURE_TIMESTAMP))?;
    let anchored = |der: &[u8]| trust.anchors.iter().any(|anchor| anchor.as_slice() == der);
    let signature_timestamp = match signature_timestamp(sealed, witness) {
        Bound::Token(token, imprint) => Some(
            prove_token(&token, &imprint, &anchors, &trust.policies, now)
                .ok_or_else(|| unproven(SIGNATURE_TIMESTAMP))?,
        ),
        Bound::None if achieved < SealProfile::BaselineT => None,
        Bound::None | Bound::Malformed => return Err(unproven(SIGNATURE_TIMESTAMP)),
    };
    let suffix = sealed.len() as u64 > witness.byte_end;
    if achieved < SealProfile::BaselineLt {
        // An honest organ appends nothing below B-LT.
        return if suffix {
            Err(unproven(VALIDATION_DATA))
        } else {
            Ok(())
        };
    }
    let Some(signature_timestamp) = signature_timestamp.filter(|_| suffix) else {
        return Err(unproven(VALIDATION_DATA));
    };
    let dss = match read_dss(sealed, witness.byte_end, trust) {
        Ok(Some(dss)) => dss,
        Ok(None) => return Err(unproven(VALIDATION_DATA)),
        Err(()) => {
            return Err(EsignSealerError::Retryable {
                stage: STAGE.to_owned(),
                code: "evidence_memory".to_owned(),
                retry_after_ms: None,
            });
        }
    };
    let mut documents = Vec::new();
    for signature in &classification.signatures {
        if signature.kind == SealSignatureKind::DocumentTimestamp {
            documents.push(
                document_timestamp(sealed, signature.byte_range.values, &anchors, trust, now)
                    .ok_or_else(|| unproven(DOCUMENT_TIMESTAMP))?,
            );
        }
    }
    if achieved < SealProfile::BaselineLta && !documents.is_empty() {
        return Err(unproven(DOCUMENT_TIMESTAMP));
    }
    let archival = documents
        .iter()
        .filter(|document| document.start >= dss.end && document.covers_to == sealed.len())
        .map(|document| document.proof.gen_time)
        .min();
    let at = match archival {
        Some(gen_time) => gen_time,
        None if achieved == SealProfile::BaselineLta => {
            return Err(unproven(DOCUMENT_TIMESTAMP));
        }
        None => now,
    };
    let mut chains = vec![witness.signer_chain.clone()];
    for proof in std::iter::once(&signature_timestamp).chain(documents.iter().map(|d| &d.proof)) {
        chains.push(proof.chain.clone());
    }
    let revocation = DssRevocation::new(&dss, at);
    let policy = ValidationPolicy::new(at);
    for chain in &chains {
        let unanchored: Vec<&Vec<u8>> = chain
            .iter()
            .filter(|der| !anchored(der.as_slice()))
            .collect();
        if unanchored.is_empty() {
            continue;
        }
        if !unanchored.iter().all(|der| dss.certs.contains(*der)) {
            return Err(unproven(VALIDATION_DATA));
        }
        let path: Vec<Certificate> = unanchored
            .iter()
            .map(|der| Certificate::from_der(der))
            .collect::<Result<_, _>>()
            .map_err(|_| unproven(VALIDATION_DATA))?;
        pkix_chain::verify_chain(
            &path,
            &anchors,
            &policy,
            &DefaultVerifier,
            &revocation,
            &NoAiaFetcher,
        )
        .map_err(|_| unproven(VALIDATION_DATA))?;
    }
    let vouched =
        |der: &Vec<u8>| anchored(der.as_slice()) || chains.iter().any(|chain| chain.contains(der));
    if !revocation.all_used() || !dss.certs.iter().all(vouched) {
        return Err(unproven(VALIDATION_DATA));
    }
    Ok(())
}

const STAGE: &str = "evidence";
const SIGNATURE_TIMESTAMP: &str = "signature_timestamp_unproven";
const VALIDATION_DATA: &str = "validation_data_unproven";
const DOCUMENT_TIMESTAMP: &str = "document_timestamp_unproven";

fn unproven(code: &str) -> EsignSealerError {
    EsignSealerError::Retryable {
        stage: STAGE.to_owned(),
        code: code.to_owned(),
        retry_after_ms: None,
    }
}

/// The bound signature's timestamp, as its CMS carries it.
enum Bound {
    None,
    /// The token's DER, and the imprint it must carry: SHA-256 of the
    /// signature value (RFC 3161 Appendix A).
    Token(Vec<u8>, [u8; 32]),
    /// Not one attribute with one value, or a CMS the host cannot read.
    Malformed,
}

fn signature_timestamp(sealed: &[u8], witness: &AdmittedRevision) -> Bound {
    let [_, open, close, _] = witness.byte_range;
    let Some(der) = usize::try_from(open)
        .ok()
        .zip(usize::try_from(close).ok())
        .and_then(|(open, close)| hole_der(sealed, open, close))
    else {
        return Bound::Malformed;
    };
    let Some(signer) = ContentInfo::from_der(&der)
        .ok()
        .and_then(|info| info.content.decode_as::<SignedData>().ok())
        .and_then(|signed| match signed.signer_infos.0.as_slice() {
            [signer] => Some(signer.clone()),
            _ => None,
        })
    else {
        return Bound::Malformed;
    };
    let tokens: Vec<_> = signer
        .unsigned_attrs
        .iter()
        .flat_map(|attributes| attributes.iter())
        .filter(|attribute| attribute.oid == ID_SIGNATURE_TIME_STAMP_TOKEN)
        .collect();
    match tokens.as_slice() {
        [] => Bound::None,
        [attribute] => match attribute.values.as_slice() {
            [token] => token.to_der().map_or(Bound::Malformed, |token| {
                Bound::Token(token, Sha256::digest(signer.signature.as_bytes()).into())
            }),
            _ => Bound::Malformed,
        },
        _ => Bound::Malformed,
    }
}

/// The DER in the hole `[open, close)` of `sealed`: `<`, the hex of one
/// canonical CMS ContentInfo, zero padding, `>`. The ContentInfo's bytes.
fn hole_der(sealed: &[u8], open: usize, close: usize) -> Option<Vec<u8>> {
    let hole = sealed.get(open..close)?;
    let (&b'<', rest) = hole.split_first()? else {
        return None;
    };
    let (&b'>', hex) = rest.split_last()? else {
        return None;
    };
    let der = unhex(hex)?;
    let mut reader = SliceReader::new(&der).ok()?;
    let info = ContentInfo::decode(&mut reader).ok()?;
    let used = usize::try_from(reader.position()).ok()?;
    let canonical = info.to_der().ok()? == der[..used];
    (canonical && der[used..].iter().all(|byte| *byte == 0)).then(|| der[..used].to_vec())
}

/// A token the host proved: its genTime, and its authority's chain as the
/// token carries it, the authority first, DER.
struct TimestampProof {
    gen_time: u64,
    chain: Vec<Vec<u8>>,
}

/// RFC 3161 and ARCH-0064a §4 (line 104): one SignedData of a TSTInfo v1
/// over `imprint` (SHA-256), in an allowed policy, under one SHA-256 digest
/// algorithm; one SignerInfo whose signed attributes hold the content type
/// id-ct-TSTInfo and the TSTInfo's messageDigest once each and a
/// signingCertificateV2 naming a certificate the token carries, whose key
/// signed them; a genTime no later than the skew allows; that certificate's
/// chain to an anchor at the genTime, with the critical, sole timestamping
/// EKU. Its imprint is never enough on its own.
fn prove_token(
    token: &[u8],
    imprint: &[u8; 32],
    anchors: &[TrustAnchor],
    policies: &[ObjectIdentifier],
    now: u64,
) -> Option<TimestampProof> {
    let info = ContentInfo::from_der(token).ok()?;
    if info.content_type != ID_SIGNED_DATA || info.to_der().ok()? != token {
        return None;
    }
    let signed: SignedData = info.content.decode_as().ok()?;
    if signed.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return None;
    }
    let content = signed
        .encap_content_info
        .econtent
        .as_ref()?
        .decode_as::<OctetString>()
        .ok()?;
    let tst = x509_tsp::TstInfo::from_der(content.as_bytes()).ok()?;
    let [digest] = signed.digest_algorithms.as_slice() else {
        return None;
    };
    let [signer] = signed.signer_infos.0.as_slice() else {
        return None;
    };
    if tst.version != x509_tsp::TspVersion::V1
        || tst.message_imprint.hash_algorithm.oid != ID_SHA256
        || tst.message_imprint.hashed_message.as_bytes() != imprint
        || !(policies.is_empty() || policies.contains(&tst.policy))
        || digest.oid != ID_SHA256
        || signer.digest_alg.oid != ID_SHA256
    {
        return None;
    }
    let certificates: Vec<&Certificate> = signed
        .certificates
        .as_ref()?
        .0
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => Some(cert),
            CertificateChoices::Other(_) => None,
        })
        .collect();
    let content_digest: [u8; 32] = Sha256::digest(content.as_bytes()).into();
    let authority = token_signer(signer, &certificates, &content_digest)?;
    let gen_time = tst.gen_time.to_unix_duration().as_secs();
    if gen_time > now.saturating_add(GEN_TIME_SKEW_SECS) {
        return None;
    }
    let chain: Vec<Certificate> = std::iter::once(authority)
        .chain(certificates.iter().copied().filter(|cert| *cert != authority))
        .cloned()
        .collect();
    pkix_chain::verify_time_stamper(
        &chain,
        anchors,
        &TimestampProfile,
        gen_time,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .ok()?;
    Some(TimestampProof {
        gen_time,
        chain: chain
            .iter()
            .map(Encode::to_der)
            .collect::<Result<_, _>>()
            .ok()?,
    })
}

/// The certificate whose key signed `signer`'s attributes, which must be
/// exactly once each the content type id-ct-TSTInfo, the messageDigest
/// `content_digest`, and a signingCertificateV2 whose first ESSCertIDv2 is
/// SHA-256 of that certificate.
fn token_signer<'c>(
    signer: &SignerInfo,
    certificates: &[&'c Certificate],
    content_digest: &[u8; 32],
) -> Option<&'c Certificate> {
    let attributes = signer.signed_attrs.as_ref()?;
    let one = |oid: ObjectIdentifier| -> Option<&Any> {
        let mut found = attributes.iter().filter(|attribute| attribute.oid == oid);
        let attribute = found.next()?;
        match (found.next(), attribute.values.as_slice()) {
            (None, [value]) => Some(value),
            _ => None,
        }
    };
    let content_type: ObjectIdentifier = one(ID_CONTENT_TYPE)?.decode_as().ok()?;
    let message_digest: OctetString = one(ID_MESSAGE_DIGEST)?.decode_as().ok()?;
    let signing_certificate = one(ID_SIGNING_CERT_V2)?.to_der().ok()?;
    let cert_hash = ess_cert_hash(&signing_certificate)?;
    if content_type != ID_CT_TST_INFO || message_digest.as_bytes() != content_digest {
        return None;
    }
    let authority = certificates.iter().copied().find(|cert| {
        cert.to_der()
            .is_ok_and(|der| Sha256::digest(&der).as_slice() == cert_hash)
    })?;
    let message = attributes.to_der().ok()?;
    // CMS signers often name rsaEncryption beside a SHA-256 digest
    // (RFC 5754 §3.2): that is sha256WithRSAEncryption.
    let algorithm = if signer.signature_algorithm.oid == ID_RSA_ENCRYPTION {
        AlgorithmIdentifierOwned {
            oid: ID_SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        }
    } else {
        signer.signature_algorithm.clone()
    };
    DefaultVerifier
        .verify_signature(
            algorithm.owned_to_ref(),
            authority
                .tbs_certificate
                .subject_public_key_info
                .owned_to_ref(),
            &message,
            signer.signature.as_bytes(),
        )
        .ok()?;
    Some(authority)
}

/// SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, .. };
/// ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash, .. }.
/// The first certHash, when its algorithm is SHA-256.
fn ess_cert_hash(value: &[u8]) -> Option<&[u8]> {
    let (0x30, signing_certificate, _) = tlv_at(value)? else {
        return None;
    };
    let (0x30, certs, _) = tlv_at(signing_certificate)? else {
        return None;
    };
    let (0x30, first, _) = tlv_at(certs)? else {
        return None;
    };
    let (tag, content, rest) = tlv_at(first)?;
    let (tag, content) = if tag == 0x30 {
        let (0x06, oid, _) = tlv_at(content)? else {
            return None;
        };
        if oid != ID_SHA256.as_bytes() {
            return None;
        }
        let (tag, content, _) = tlv_at(rest)?;
        (tag, content)
    } else {
        (tag, content)
    };
    (tag == 0x04).then_some(content)
}

/// One DER TLV with a one-byte tag at the start of `input`: its tag, its
/// content and what follows it.
fn tlv_at(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |len, byte| (len << 8) | usize::from(*byte));
        (len, &rest[count..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// The profile pkix-chain checks a timestamp authority under: RFC 5280 path
/// validation at the token's genTime, no policy OIDs.
struct TimestampProfile;

impl pkix_chain::Profile for TimestampProfile {
    fn id(&self) -> &'static str {
        "oneiron.organ-host.seal-evidence"
    }

    fn version(&self) -> &'static str {
        "v1"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        ValidationPolicy::new(now_unix)
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

/// A document timestamp the host proved: where its hole starts, where its
/// second range ends, and its token.
struct DocumentTimestamp {
    start: usize,
    covers_to: usize,
    proof: TimestampProof,
}

/// A document timestamp at ByteRange `[0, a, b, c]`: its hole `[a, b)`
/// holds one token, proven over SHA-256 of `[0, a)` and `[b, b + c)`.
fn document_timestamp(
    sealed: &[u8],
    values: [u64; 4],
    anchors: &[TrustAnchor],
    trust: &EvidenceTrust<'_>,
    now: u64,
) -> Option<DocumentTimestamp> {
    let [start, open, close, rest] = values.map(|value| usize::try_from(value).ok());
    let (open, close, rest) = (open?, close?, rest?);
    let end = close.checked_add(rest)?;
    if start != Some(0) || open >= close || end > sealed.len() {
        return None;
    }
    let token = hole_der(sealed, open, close)?;
    let imprint: [u8; 32] = Sha256::new()
        .chain_update(&sealed[..open])
        .chain_update(&sealed[close..end])
        .finalize()
        .into();
    Some(DocumentTimestamp {
        start: open,
        covers_to: end,
        proof: prove_token(&token, &imprint, anchors, &trust.policies, now)?,
    })
}

/// The DSS the archival suffix wrote: its certificates, CRLs and OCSP
/// responses, DER, and the end of the revision that holds it.
struct Dss {
    certs: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    ocsps: Vec<Vec<u8>>,
    end: usize,
}

/// The catalog's `/DSS`, read with lopdf from the whole file: an indirect
/// dictionary of only [`DSS_KEYS`] at an offset past `byte_end`, whose
/// arrays name unfiltered streams written after `byte_end` and before it.
/// `Ok(None)` when it is missing or not that; `Err` when its decodes found
/// no memory before the deadline.
fn read_dss(
    sealed: &[u8],
    byte_end: u64,
    trust: &EvidenceTrust<'_>,
) -> Result<Option<Dss>, ()> {
    let admission = trust.floor.as_ref().map(|floor| {
        Arc::new(FloorAdmission {
            floor: Arc::clone(floor),
            deadline: trust.deadline,
            lease: Mutex::new(None),
        }) as Arc<dyn lopdf::DecodeAdmission>
    });
    let options = lopdf::LoadOptions {
        decode_admission: admission,
        ..lopdf::LoadOptions::default()
    };
    let document = match lopdf::Document::load_mem_with_options(sealed, options) {
        Ok(document) => document,
        Err(lopdf::Error::DecodeAdmission(_)) => return Err(()),
        Err(_) => return Ok(None),
    };
    Ok(dss_of(&document, sealed, byte_end))
}

fn dss_of(document: &lopdf::Document, sealed: &[u8], byte_end: u64) -> Option<Dss> {
    use lopdf::xref::XrefEntry;
    // lopdf reads offsets from the header on (its own rule).
    let header = sealed
        .windows(b"%PDF-".len())
        .position(|window| window == b"%PDF-")
        .unwrap_or(0);
    let byte_end = usize::try_from(byte_end).ok()?;
    let offset = |id: lopdf::ObjectId| match document.reference_table.get(id.0)? {
        XrefEntry::Normal { offset, generation } if *generation == id.1 => {
            header.checked_add(usize::try_from(*offset).ok()?)
        }
        _ => None,
    };
    let root = document.trailer.get(b"Root").ok()?.as_reference().ok()?;
    let catalog = document.get_object(root).ok()?.as_dict().ok()?;
    let dss_id = catalog.get(b"DSS").ok()?.as_reference().ok()?;
    let dss_at = offset(dss_id).filter(|at| *at >= byte_end)?;
    let dss = document.get_object(dss_id).ok()?.as_dict().ok()?;
    if !dss.iter().all(|(key, _)| DSS_KEYS.contains(&key.as_slice()))
        || dss
            .get(b"Type")
            .is_ok_and(|kind| kind.as_name().ok() != Some(b"DSS".as_slice()))
    {
        return None;
    }
    let streams = |key: &[u8]| -> Option<Vec<Vec<u8>>> {
        let Ok(items) = dss.get(key) else {
            return Some(Vec::new());
        };
        items
            .as_array()
            .ok()?
            .iter()
            .map(|item| {
                let id = item.as_reference().ok()?;
                offset(id).filter(|at| (byte_end..dss_at).contains(at))?;
                let stream = document.get_object(id).ok()?.as_stream().ok()?;
                (!stream.dict.has(b"Filter")).then(|| stream.content.clone())
            })
            .collect()
    };
    let end = sealed
        .get(dss_at..)?
        .windows(b"%%EOF".len())
        .position(|window| window == b"%%EOF")?;
    Some(Dss {
        certs: streams(b"Certs")?,
        crls: streams(b"CRLs")?,
        ocsps: streams(b"OCSPs")?,
        end: dss_at + end + b"%%EOF".len(),
    })
}

/// Revocation answered only from the DSS, at the material's time: a
/// certificate is covered when one CRL or OCSP response its issuer (or the
/// anchor) signed, fresh then, says it is not revoked; a revocation from
/// such an item fails it. It records which items vouched for anything.
struct DssRevocation {
    crls: Vec<Option<CrlChecker<DefaultVerifier>>>,
    ocsps: Vec<Option<OcspChecker<DefaultVerifier>>>,
    used: Mutex<Vec<bool>>,
}

impl DssRevocation {
    fn new(dss: &Dss, at: u64) -> Self {
        let crls = dss
            .crls
            .iter()
            .map(|der| {
                let crl = x509_cert::crl::CertificateList::from_der(der).ok()?;
                let list = &crl.tbs_cert_list;
                let scoped = list.crl_extensions.as_ref().is_some_and(|extensions| {
                    extensions.iter().any(|extension| {
                        extension.extn_id == ID_DELTA_CRL_INDICATOR
                            || extension.extn_id == ID_ISSUING_DISTRIBUTION_POINT
                    })
                });
                let issued = match list.this_update {
                    x509_cert::time::Time::UtcTime(time) => time.to_unix_duration(),
                    x509_cert::time::Time::GeneralTime(time) => time.to_unix_duration(),
                };
                if scoped || issued.as_secs() > at {
                    return None;
                }
                CrlChecker::new(der, at, DefaultVerifier).ok()
            })
            .collect();
        let ocsps = dss
            .ocsps
            .iter()
            .map(|der| OcspChecker::new(der, at, DefaultVerifier).ok())
            .collect();
        Self {
            used: Mutex::new(vec![false; dss.crls.len() + dss.ocsps.len()]),
            crls,
            ocsps,
        }
    }

    fn all_used(&self) -> bool {
        lock(&self.used).iter().all(|used| *used)
    }

    /// Asks every item; `check` is one item's answer for the certificate.
    fn answer(
        &self,
        check: impl Fn(&dyn RevocationChecker) -> pkix_revocation::Result<()>,
    ) -> pkix_revocation::Result<()> {
        let items = self
            .crls
            .iter()
            .map(|item| item.as_ref().map(|item| item as &dyn RevocationChecker))
            .chain(
                self.ocsps
                    .iter()
                    .map(|item| item.as_ref().map(|item| item as &dyn RevocationChecker)),
            );
        let mut covered = false;
        for (index, item) in items.enumerate() {
            let Some(item) = item else {
                continue;
            };
            match check(item) {
                Ok(()) => {
                    covered = true;
                    if let Some(used) = lock(&self.used).get_mut(index) {
                        *used = true;
                    }
                }
                Err(revoked @ pkix_revocation::Error::Revoked { .. }) => return Err(revoked),
                Err(_) => {}
            }
        }
        if covered {
            Ok(())
        } else {
            Err(pkix_revocation::Error::OcspStatusUnknown)
        }
    }
}

impl RevocationChecker for DssRevocation {
    fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> pkix_revocation::Result<()> {
        self.answer(|item| item.check_revocation(cert, issuer))
    }

    fn check_revocation_against_anchor(
        &self,
        cert: &Certificate,
        anchor: &TrustAnchor,
    ) -> pkix_revocation::Result<()> {
        self.answer(|item| item.check_revocation_against_anchor(cert, anchor))
    }
}

/// The DSS read's decodes, leased from the machine floor before they
/// allocate (FIX 7654), held until the read ends.
struct FloorAdmission {
    floor: Arc<dyn MachineFloor>,
    deadline: Instant,
    lease: Mutex<Option<Box<dyn FloorLease>>>,
}

impl lopdf::DecodeAdmission for FloorAdmission {
    fn admit(&self, bytes: usize) -> Result<(), lopdf::DecodeAdmissionError> {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let mut lease = lock(&self.lease);
        let leased = match lease.as_mut() {
            Some(lease) => lease.grow(bytes, self.deadline, &|| false),
            None => self
                .floor
                .lease(bytes, self.deadline, &|| false)
                .map(|granted| *lease = Some(granted)),
        };
        leased.map_err(|refusal| match refusal {
            FloorRefusal::Floor { needed, available } => {
                lopdf::DecodeAdmissionError::MemoryFloor { needed, available }
            }
            FloorRefusal::Deadline => lopdf::DecodeAdmissionError::Deadline,
        })
    }

    fn release(&self, bytes: usize) {
        if let Some(lease) = lock(&self.lease).as_mut() {
            lease.shrink(u64::try_from(bytes).unwrap_or(u64::MAX));
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
