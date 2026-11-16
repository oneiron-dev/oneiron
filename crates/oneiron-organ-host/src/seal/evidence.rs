//! The trusted side's own proof of a seal's evidence (ARCH-0075
//! `#organ-host-design-seal-residual`, L4-13): the fresh verifier is the same
//! installed binary, a second opinion, so whatever the achieved profile
//! claims the host checks itself, from the bytes it holds, with general
//! crates (cms, x509-tsp, pkix-chain, lopdf at the engine's pins), never
//! the organ's code (ARCH-0064a §4, the profile table):
//! - B-T and above: the bound signature carries one signature timestamp, a
//!   valid RFC 3161 token over SHA-256 of its signature value, from an
//!   authority whose path to the seal's anchors pkix builds from the
//!   token's certificates and finds valid at the token's genTime, with a
//!   critical, sole id-kp-timeStamping EKU. A token present below B-T is
//!   checked the same.
//! - B-LT and above: the DSS the archival suffix adds (the catalog's `/DSS`,
//!   written after the bound revision; read with lopdf) holds every
//!   non-anchor certificate of the signer's path (valid at the signature
//!   timestamp's genTime) and of each authority's path (valid at its
//!   token's), and for each certificate on those paths a CRL or OCSP
//!   response its issuer (or a responder it delegated to, whose KeyUsage
//!   lets it sign) signed, fresh at the material's time, that does not list
//!   it; an OCSP response may be produced up to the organ's 300 s after
//!   that time. A CRL or OCSP response without nextUpdate proves nothing.
//!   Any other certificate it holds (the organ keeps the chain of an
//!   authority whose archival token it replaced) must be on a path of its
//!   own through the DSS to an anchor, valid and not revoked at the
//!   material's time; every CRL and OCSP response must vouch for some
//!   certificate: a DSS carries only evidence the engine can vouch for.
//! - B-LTA: a document timestamp after that DSS, covering every byte to the
//!   end of the file but its own hole, passes the same RFC 3161 checks over
//!   its two ranges; its time is the material's. Every document timestamp
//!   the classification names is checked, at any profile, and must be a
//!   PDF document timestamp: the `/DocTimeStamp` value of a signature field
//!   of the catalog's `/AcroForm`, whose `/ByteRange` and `/Contents` are
//!   the ones checked. A token the classification alone names is none.
//!
//! The material's time follows the organ's own rule: the archival document
//! timestamp's genTime when there is one, else now. Anything an honest
//! organ never writes (a suffix below B-LT, a document timestamp below
//! B-LTA) fails the same way. A failed proof leaves the seal retryable
//! (ARCH-0064a SGN-04), never a nominally complete document.

use std::collections::HashSet;
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
use pkix_chain::pkix_path_builder::{self, CertPool};
use pkix_chain::pkix_revocation::{self, RevocationChecker};
use pkix_chain::{
    CrlChecker, DefaultVerifier, NoAiaFetcher, NoRevocation, OcspChecker, SignatureVerifier,
    TrustAnchor, ValidationPolicy,
};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::ext::pkix::KeyUsage;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_ocsp::{BasicOcspResponse, OcspResponse};

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
const ID_CE_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
/// deltaCRLIndicator and issuingDistributionPoint (RFC 5280 §5.2.4, §5.2.5):
/// a CRL with either is not complete evidence for its issuer.
const ID_DELTA_CRL_INDICATOR: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.27");
const ID_ISSUING_DISTRIBUTION_POINT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.28");
/// How far a genTime may run ahead of the engine's clock: the organ's own
/// bound (its `TS_GEN_TIME_MAX_SKEW_SECS`).
const GEN_TIME_SKEW_SECS: u64 = 300;
/// How far a responder's clock may run ahead of the material's time when it
/// stamps an OCSP response's producedAt: the organ's own bound (its
/// `OCSP_PRODUCED_AT_MAX_SKEW_SECS`).
const OCSP_SKEW_SECS: u64 = 300;
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
    let anchor_certificates: Vec<Certificate> = trust
        .anchors
        .iter()
        .map(|der| Certificate::from_der(der))
        .collect::<Result<_, _>>()
        .map_err(|_| unproven(SIGNATURE_TIMESTAMP))?;
    let anchors: Vec<TrustAnchor> = anchor_certificates
        .iter()
        .cloned()
        .map(TrustAnchor::from_cert)
        .collect();
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
    let pdf = match read_pdf(sealed, trust) {
        Ok(Some(pdf)) => pdf,
        Ok(None) => return Err(unproven(VALIDATION_DATA)),
        Err(()) => {
            return Err(EsignSealerError::Retryable {
                stage: STAGE.to_owned(),
                code: "evidence_memory".to_owned(),
                retry_after_ms: None,
            });
        }
    };
    let dss = pdf
        .dss(witness.byte_end)
        .ok_or_else(|| unproven(VALIDATION_DATA))?;
    let mut documents = Vec::new();
    for signature in &classification.signatures {
        if signature.kind == SealSignatureKind::DocumentTimestamp {
            documents.push(
                document_timestamp(
                    &pdf,
                    signature.byte_range.values,
                    &anchors,
                    &trust.policies,
                    now,
                )
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
    // The signer's path, valid when its signature timestamp says it signed,
    // and each authority's, valid at its token's genTime (the organ's rule);
    // their revocation, fresh at the material's time.
    let mut paths = Vec::new();
    if !witness
        .signer_chain
        .first()
        .is_some_and(|leaf| anchored(leaf))
    {
        let signer: Vec<Certificate> = witness
            .signer_chain
            .iter()
            .map(|der| Certificate::from_der(der))
            .collect::<Result<_, _>>()
            .map_err(|_| unproven(VALIDATION_DATA))?;
        let path = signer
            .first()
            .and_then(|leaf| built_path(leaf, &signer, &anchors, signature_timestamp.gen_time))
            .ok_or_else(|| unproven(VALIDATION_DATA))?;
        paths.push((path, signature_timestamp.gen_time));
    }
    for proof in std::iter::once(&signature_timestamp).chain(documents.iter().map(|d| &d.proof)) {
        paths.push((proof.path.clone(), proof.gen_time));
    }
    let revocation = DssRevocation::new(&dss, &anchor_certificates, at);
    let mut vouched: Vec<Vec<u8>> = Vec::new();
    for (path, valid_at) in paths {
        let mut proven = Vec::with_capacity(path.len());
        for certificate in path {
            let der = certificate
                .to_der()
                .map_err(|_| unproven(VALIDATION_DATA))?;
            if anchored(&der) {
                continue;
            }
            if !dss.certs.contains(&der) {
                return Err(unproven(VALIDATION_DATA));
            }
            vouched.push(der);
            proven.push(certificate);
        }
        if !proven.is_empty() && !proves_path(&proven, &anchors, valid_at, &revocation) {
            return Err(unproven(VALIDATION_DATA));
        }
    }
    // Material beyond those paths: each certificate on a path of its own
    // through the DSS to an anchor, valid and not revoked at the material's
    // time. Only what pkix validated is vouched for.
    let pool: Vec<Certificate> = dss
        .certs
        .iter()
        .map(|der| Certificate::from_der(der))
        .collect::<Result<_, _>>()
        .map_err(|_| unproven(VALIDATION_DATA))?;
    for (der, certificate) in dss.certs.iter().zip(&pool) {
        if anchored(der) || vouched.contains(der) {
            continue;
        }
        let proven = built_path(certificate, &pool, &anchors, at)
            .is_some_and(|path| proves_path(&path, &anchors, at, &revocation));
        if !proven {
            return Err(unproven(VALIDATION_DATA));
        }
    }
    if !revocation.all_used() {
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

/// A path from `leaf` to an anchor that pkix finds valid at `valid_at`,
/// leaf first: `leaf` and then the rest of `pool` in its order, when pkix
/// validates all of it (the organ's first try: pkix-chain's positional
/// path), else the one pkix builds through `pool`, the anchor left out.
/// Only the certificates on it are vouched for, never the rest of what a
/// token or a chain carried.
fn built_path<'a>(
    leaf: &Certificate,
    pool: impl IntoIterator<Item = &'a Certificate>,
    anchors: &[TrustAnchor],
    valid_at: u64,
) -> Option<Vec<Certificate>> {
    let pool: Vec<Certificate> = pool.into_iter().cloned().collect();
    let policy = ValidationPolicy::new(valid_at);
    let supplied: Vec<Certificate> = std::iter::once(leaf.clone())
        .chain(
            pool.iter()
                .filter(|certificate| *certificate != leaf)
                .cloned(),
        )
        .collect();
    if pkix_chain::pkix_path::validate_path(&supplied, anchors, &policy, &DefaultVerifier).is_ok() {
        return Some(supplied);
    }
    let pool: CertPool = pool.into_iter().collect();
    let path =
        pkix_path_builder::build_first_valid_path(leaf, &pool, anchors, &policy, &DefaultVerifier)
            .ok()?;
    let from_leaf = path.first() == Some(leaf);
    from_leaf.then_some(path)
}

/// Whether `path` (leaf first, no anchor) is valid to an anchor at
/// `valid_at`, every certificate on it, each covered by `revocation`.
fn proves_path(
    path: &[Certificate],
    anchors: &[TrustAnchor],
    valid_at: u64,
    revocation: &DssRevocation,
) -> bool {
    pkix_chain::verify_chain(
        path,
        anchors,
        &ValidationPolicy::new(valid_at),
        &DefaultVerifier,
        revocation,
        &NoAiaFetcher,
    )
    .is_ok_and(|validated| validated.depth + 1 == path.len())
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
        .and_then(|(open, close)| hole_bytes(sealed, open, close))
        .and_then(|bytes| content_info_der(&bytes).map(<[u8]>::to_vec))
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

/// What the hole `[open, close)` of `sealed` holds: `<`, hex digits, `>`;
/// the bytes the digits spell.
fn hole_bytes(sealed: &[u8], open: usize, close: usize) -> Option<Vec<u8>> {
    let hole = sealed.get(open..close)?;
    let (&b'<', rest) = hole.split_first()? else {
        return None;
    };
    let (&b'>', hex) = rest.split_last()? else {
        return None;
    };
    unhex(hex)
}

/// The one canonical CMS ContentInfo at the start of `bytes`, which only
/// zero padding may follow: its DER.
fn content_info_der(bytes: &[u8]) -> Option<&[u8]> {
    let mut reader = SliceReader::new(bytes).ok()?;
    let info = ContentInfo::decode(&mut reader).ok()?;
    let used = usize::try_from(reader.position()).ok()?;
    let (der, padding) = (bytes.get(..used)?, bytes.get(used..)?);
    (info.to_der().ok()? == der && padding.iter().all(|byte| *byte == 0)).then_some(der)
}

/// A token the host proved: its genTime, and its authority's path as pkix
/// built and validated it, the authority first.
struct TimestampProof {
    gen_time: u64,
    path: Vec<Certificate>,
}

/// RFC 3161 and ARCH-0064a §4 (line 104): one SignedData of a TSTInfo v1
/// over `imprint` (SHA-256), in an allowed policy, under one SHA-256 digest
/// algorithm; one SignerInfo whose signed attributes hold the content type
/// id-ct-TSTInfo and the TSTInfo's messageDigest once each and a
/// signingCertificateV2 naming a certificate the token carries, whose key
/// signed them; a genTime no later than the skew allows; a path from that
/// certificate through the token's certificates to an anchor, valid at the
/// genTime, with the critical, sole timestamping EKU. Its imprint is never
/// enough on its own.
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
    let path = built_path(authority, certificates.iter().copied(), anchors, gen_time)?;
    pkix_chain::verify_time_stamper(
        &path,
        anchors,
        &TimestampProfile,
        gen_time,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .ok()?;
    Some(TimestampProof { gen_time, path })
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

/// A document timestamp at ByteRange `[0, a, b, c]`: a `/DocTimeStamp` the
/// PDF names with that ByteRange, whose hole `[a, b)` holds one token,
/// proven over SHA-256 of `[0, a)` and `[b, b + c)`.
fn document_timestamp(
    pdf: &Pdf<'_>,
    values: [u64; 4],
    anchors: &[TrustAnchor],
    policies: &[ObjectIdentifier],
    now: u64,
) -> Option<DocumentTimestamp> {
    let sealed = pdf.sealed;
    let [start, open, close, rest] = values.map(|value| usize::try_from(value).ok());
    let (open, close, rest) = (open?, close?, rest?);
    let end = close.checked_add(rest)?;
    if start != Some(0) || open >= close || end > sealed.len() {
        return None;
    }
    let contents = hole_bytes(sealed, open, close)?;
    if !pdf.names_document_timestamp(values, open, &contents) {
        return None;
    }
    let token = content_info_der(&contents)?;
    let imprint: [u8; 32] = Sha256::new()
        .chain_update(&sealed[..open])
        .chain_update(&sealed[close..end])
        .finalize()
        .into();
    Some(DocumentTimestamp {
        start: open,
        covers_to: end,
        proof: prove_token(token, &imprint, anchors, policies, now)?,
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

/// The sealed PDF as lopdf read it from the whole file.
struct Pdf<'a> {
    document: lopdf::Document,
    sealed: &'a [u8],
    /// Where `%PDF-` starts: lopdf reads offsets from there on (its own rule).
    header: usize,
}

/// Reads `sealed` with lopdf, its stream decodes leasing from the machine
/// floor. `Ok(None)` when lopdf cannot read it; `Err` when its decodes
/// found no memory before the deadline.
fn read_pdf<'a>(sealed: &'a [u8], trust: &EvidenceTrust<'_>) -> Result<Option<Pdf<'a>>, ()> {
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
    let header = sealed
        .windows(b"%PDF-".len())
        .position(|window| window == b"%PDF-")
        .unwrap_or(0);
    Ok(Some(Pdf {
        document,
        sealed,
        header,
    }))
}

impl Pdf<'_> {
    /// Where object `id` starts in the file, when the cross-reference
    /// names it as a plain object of that generation.
    fn offset(&self, id: lopdf::ObjectId) -> Option<usize> {
        match self.document.reference_table.get(id.0)? {
            lopdf::xref::XrefEntry::Normal { offset, generation } if *generation == id.1 => {
                self.header.checked_add(usize::try_from(*offset).ok()?)
            }
            _ => None,
        }
    }

    /// The catalog's `/DSS`: an indirect dictionary of only [`DSS_KEYS`] at
    /// an offset past `byte_end`, whose arrays name unfiltered streams
    /// written after `byte_end` and before it. `None` when it is missing or
    /// not that.
    fn dss(&self, byte_end: u64) -> Option<Dss> {
        let document = &self.document;
        let byte_end = usize::try_from(byte_end).ok()?;
        let root = document.trailer.get(b"Root").ok()?.as_reference().ok()?;
        let catalog = document.get_object(root).ok()?.as_dict().ok()?;
        let dss_id = catalog.get(b"DSS").ok()?.as_reference().ok()?;
        let dss_at = self.offset(dss_id).filter(|at| *at >= byte_end)?;
        let dss = document.get_object(dss_id).ok()?.as_dict().ok()?;
        if !dss
            .iter()
            .all(|(key, _)| DSS_KEYS.contains(&key.as_slice()))
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
                    self.offset(id)
                        .filter(|at| (byte_end..dss_at).contains(at))?;
                    let stream = document.get_object(id).ok()?.as_stream().ok()?;
                    (!stream.dict.has(b"Filter")).then(|| stream.content.clone())
                })
                .collect()
        };
        let end = self
            .sealed
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

    /// Whether a signature field of the catalog's `/AcroForm` (its `/FT`
    /// `/Sig`, its own or inherited) has for its `/V` a `/DocTimeStamp`
    /// dictionary of `/SubFilter /ETSI.RFC3161`, written before the hole at
    /// `open`, with ByteRange `values` and `/Contents` `contents` (ISO
    /// 32000-2 §12.8, ETSI EN 319 142-1 §5.4). A token cannot cover its own
    /// bytes, so those `/Contents` are the hole's.
    fn names_document_timestamp(&self, values: [u64; 4], open: usize, contents: &[u8]) -> bool {
        let document = &self.document;
        let fields = document
            .trailer
            .get(b"Root")
            .and_then(|root| document.dereference(root))
            .and_then(|(_, catalog)| catalog.as_dict())
            .and_then(|catalog| catalog.get(b"AcroForm"))
            .and_then(|form| document.dereference(form))
            .and_then(|(_, form)| form.as_dict())
            .and_then(|form| form.get(b"Fields"))
            .and_then(|fields| document.dereference(fields))
            .and_then(|(_, fields)| fields.as_array());
        let Ok(fields) = fields else {
            return false;
        };
        // Each field, with whether its parent's field type is /Sig.
        let mut pending: Vec<(&lopdf::Object, bool)> =
            fields.iter().map(|field| (field, false)).collect();
        let mut seen = HashSet::new();
        while let Some((node, inherited)) = pending.pop() {
            let Ok((id, node)) = document.dereference(node) else {
                continue;
            };
            if id.is_some_and(|id| !seen.insert(id)) {
                continue;
            }
            let Ok(field) = node.as_dict() else {
                continue;
            };
            // Only a field with no /FT of its own inherits; one it has,
            // direct or by reference, decides, and one that names no
            // type is no signature field.
            let signature = match field.get(b"FT") {
                Ok(kind) => document
                    .dereference(kind)
                    .and_then(|(_, kind)| kind.as_name())
                    .is_ok_and(|kind| kind == b"Sig".as_slice()),
                Err(_) => inherited,
            };
            if signature
                && field
                    .get(b"V")
                    .and_then(lopdf::Object::as_reference)
                    .is_ok_and(|value| self.is_document_timestamp(value, values, open, contents))
            {
                return true;
            }
            if let Ok(kids) = field
                .get(b"Kids")
                .and_then(|kids| document.dereference(kids))
                .and_then(|(_, kids)| kids.as_array())
            {
                pending.extend(kids.iter().map(|kid| (kid, signature)));
            }
        }
        false
    }

    fn is_document_timestamp(
        &self,
        id: lopdf::ObjectId,
        values: [u64; 4],
        open: usize,
        contents: &[u8],
    ) -> bool {
        let Some(dictionary) = self
            .offset(id)
            .filter(|at| *at < open)
            .and_then(|_| self.document.get_object(id).ok())
            .and_then(|object| object.as_dict().ok())
        else {
            return false;
        };
        let named = |key: &[u8], name: &[u8]| {
            dictionary
                .get(key)
                .and_then(lopdf::Object::as_name)
                .is_ok_and(|found| found == name)
        };
        named(b"Type", b"DocTimeStamp")
            && named(b"SubFilter", b"ETSI.RFC3161")
            && dictionary
                .get(b"ByteRange")
                .and_then(lopdf::Object::as_array)
                .is_ok_and(|range| {
                    range.len() == values.len()
                        && range.iter().zip(values).all(|(item, value)| {
                            item.as_i64().ok().and_then(|item| u64::try_from(item).ok())
                                == Some(value)
                        })
                })
            && dictionary
                .get(b"Contents")
                .and_then(lopdf::Object::as_str)
                .is_ok_and(|found| found == contents)
    }
}

/// Revocation answered only from the DSS, at the material's time: a
/// certificate is covered when one CRL or OCSP response its issuer (or a
/// responder the issuer delegated to) signed, fresh then, says it is not
/// revoked; a revocation from such an item fails it. It records which items
/// vouched for anything.
struct DssRevocation {
    /// The anchors as certificates: evidence for a certificate an anchor
    /// issued is checked against the anchor's certificate, its KeyUsage
    /// included (a CRL's signer must hold cRLSign, RFC 5280 §6.3.3).
    anchors: Vec<Certificate>,
    crls: Vec<Option<CrlChecker<DefaultVerifier>>>,
    ocsps: Vec<Option<MaterialOcsp>>,
    used: Mutex<Vec<bool>>,
}

impl DssRevocation {
    fn new(dss: &Dss, anchors: &[Certificate], at: u64) -> Self {
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
                let issued = match &list.this_update {
                    x509_cert::time::Time::UtcTime(time) => time.to_unix_duration(),
                    x509_cert::time::Time::GeneralTime(time) => time.to_unix_duration(),
                };
                if scoped || issued.as_secs() > at {
                    return None;
                }
                CrlChecker::new(der, at, DefaultVerifier).ok()
            })
            .collect();
        let responders: Vec<Certificate> = dss
            .certs
            .iter()
            .filter_map(|der| Certificate::from_der(der).ok())
            .chain(anchors.iter().cloned())
            .collect();
        let ocsps = dss
            .ocsps
            .iter()
            .map(|der| MaterialOcsp::new(der, &responders, at))
            .collect();
        Self {
            anchors: anchors.to_vec(),
            used: Mutex::new(vec![false; dss.crls.len() + dss.ocsps.len()]),
            crls,
            ocsps,
        }
    }

    fn all_used(&self) -> bool {
        lock(&self.used).iter().all(|used| *used)
    }

    /// Asks every item about `cert`, which `issuer` issued.
    fn answer(&self, cert: &Certificate, issuer: &Certificate) -> pkix_revocation::Result<()> {
        let answers = self
            .crls
            .iter()
            .map(|crl| crl.as_ref().map(|crl| crl.check_revocation(cert, issuer)))
            .chain(
                self.ocsps
                    .iter()
                    .map(|ocsp| ocsp.as_ref().map(|ocsp| ocsp.check(cert, issuer))),
            );
        let mut covered = false;
        for (index, answer) in answers.enumerate() {
            match answer {
                Some(Ok(())) => {
                    covered = true;
                    if let Some(used) = lock(&self.used).get_mut(index) {
                        *used = true;
                    }
                }
                Some(Err(revoked @ pkix_revocation::Error::Revoked { .. })) => {
                    return Err(revoked);
                }
                Some(Err(_)) | None => {}
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
        self.answer(cert, issuer)
    }

    fn check_revocation_against_anchor(
        &self,
        cert: &Certificate,
        anchor: &TrustAnchor,
    ) -> pkix_revocation::Result<()> {
        // Every configured certificate of the anchor's name and key: one
        // whose KeyUsage lets the key sign CRLs authorises it (the organ's
        // rule for an authenticated holder), whichever comes first.
        let mut verdict = Err(pkix_revocation::Error::OcspStatusUnknown);
        for issuer in self.anchors.iter().filter(|candidate| {
            candidate.tbs_certificate.subject == anchor.subject
                && candidate.tbs_certificate.subject_public_key_info
                    == anchor.subject_public_key_info
        }) {
            verdict = self.answer(cert, issuer);
            if matches!(
                verdict,
                Ok(()) | Err(pkix_revocation::Error::Revoked { .. })
            ) {
                break;
            }
        }
        verdict
    }
}

/// One DSS OCSP response as the organ weighs it: produced at most
/// [`OCSP_SKEW_SECS`] after the material's time (a responder's clock may
/// run that far ahead), with a status for the certificate fresh at the
/// material's time itself. pkix checks the rest (signature, responder,
/// CertID, status, and a nextUpdate no earlier than producedAt) at the
/// later of that time and producedAt.
///
/// Its own `certs` (which its signature does not cover) are the
/// response's, then the DSS certificates, then the anchors: pkix looks for
/// a delegated responder only there, the organ also in the DSS and the
/// anchors (its `OcspContext`), so in this order the host finds the one
/// the organ found. Any whose KeyUsage forbids signing is left out (the
/// organ's rule); pkix still requires the one it picks to carry
/// id-kp-OCSPSigning and to be signed by the certificate's issuer.
struct MaterialOcsp {
    checker: OcspChecker<DefaultVerifier>,
    /// Each status's serial, thisUpdate and nextUpdate, in order.
    windows: Vec<(SerialNumber, u64, Option<u64>)>,
    at: u64,
}

impl MaterialOcsp {
    /// `None` for an unsuccessful response, one the host cannot read, or
    /// one produced too late: it vouches for nothing.
    fn new(der: &[u8], responders: &[Certificate], at: u64) -> Option<Self> {
        let mut response = OcspResponse::from_der(der).ok()?;
        let bytes = response.response_bytes.as_mut()?;
        let mut basic = BasicOcspResponse::from_der(bytes.response.as_bytes()).ok()?;
        let data = &basic.tbs_response_data;
        let produced = data.produced_at.0.to_unix_duration().as_secs();
        if produced > at.saturating_add(OCSP_SKEW_SECS) {
            return None;
        }
        let windows = data
            .responses
            .iter()
            .map(|single| {
                (
                    single.cert_id.serial_number.clone(),
                    single.this_update.0.to_unix_duration().as_secs(),
                    single
                        .next_update
                        .as_ref()
                        .map(|next| next.0.to_unix_duration().as_secs()),
                )
            })
            .collect();
        let own = basic.certs.take().unwrap_or_default();
        basic.certs = Some(
            own.into_iter()
                .chain(responders.iter().cloned())
                .filter(may_sign)
                .collect(),
        );
        bytes.response = OctetString::new(basic.to_der().ok()?).ok()?;
        Some(Self {
            checker: OcspChecker::new(response.to_der().ok()?, at.max(produced), DefaultVerifier)
                .ok()?,
            windows,
            at,
        })
    }

    fn check(&self, cert: &Certificate, issuer: &Certificate) -> pkix_revocation::Result<()> {
        // The status pkix weighs: the first for the certificate's serial.
        let fresh = self
            .windows
            .iter()
            .find(|(serial, ..)| *serial == cert.tbs_certificate.serial_number)
            .is_some_and(|(_, this_update, next_update)| {
                *this_update <= self.at && next_update.is_some_and(|next| self.at <= next)
            });
        if !fresh {
            return Err(pkix_revocation::Error::OcspExpired);
        }
        self.checker.check_revocation(cert, issuer)
    }
}

/// Whether `cert`'s KeyUsage lets its key sign: absent, or present once,
/// readable, with digitalSignature (RFC 5280 §4.2.1.3).
fn may_sign(cert: &Certificate) -> bool {
    let mut usages = cert
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|extension| extension.extn_id == ID_CE_KEY_USAGE);
    match (usages.next(), usages.next()) {
        (None, _) => true,
        (Some(usage), None) => KeyUsage::from_der(usage.extn_value.as_bytes())
            .is_ok_and(|usage| usage.digital_signature()),
        (Some(_), Some(_)) => false,
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
