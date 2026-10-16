//! The seal's binding (ARCH-0075 `#organ-host-design-seal-binding`). The key
//! signs only the signed attributes of a revision the engine wrote, whose
//! messageDigest the host computed itself over that revision's ByteRange.
//! A sealed PDF is admitted only when it begins with one of those revisions,
//! byte for byte outside its hole, and the hole holds the CMS of a signature
//! this call issued for it. Byte and DER checks only: no PDF is parsed here.

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use cms::cert::CertificateChoices;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{SignedAttributes, SignedData, SignerIdentifier};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString};
use der::{Decode, Encode, Reader, SliceReader};
use oneiron::blob_artifact::esign::{EsignSealInput, EsignSealerError, SEAL_CONTENTS_LADDER};
use oneiron_organ_protocol::{AskCode, AskRefusal, ByteBuf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::{SealAlgorithm, SealIdentity, SealKeyError, SealKeys, SealLimits};
use crate::handlers::AskRequest;
use crate::receipt::SignedReceipt;

const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_CERT_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const ID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// One seal call's binding: the engine's revisions, the identity the key
/// gave, and every signature the key issued in this call.
pub(super) struct SealCall<'a> {
    keys: &'a dyn SealKeys,
    /// The call's operation and a colon: every signature's operation
    /// starts with it.
    operation: String,
    input: &'a EsignSealInput,
    signer: Mutex<Option<Signer>>,
    issued: Mutex<Vec<Issued>>,
}

/// The identity the key gave this call, and its certificate's issuer and
/// serial, DER.
#[derive(Clone)]
struct Signer {
    identity: SealIdentity,
    issuer: Vec<u8>,
    serial: Vec<u8>,
}

/// A signature the key issued, and what it signed.
struct Issued {
    revision: usize,
    /// The signed attributes, under the universal `SET OF` tag.
    attributes: Vec<u8>,
    signature: Vec<u8>,
}

/// One revision as the call's args describe it: its suffix in the second
/// input, and its ByteRange.
#[derive(Serialize)]
pub(super) struct RevisionArgs {
    id: u32,
    suffix_offset: u64,
    suffix_len: u64,
    byte_range: [u64; 4],
}

/// `seal.sign`'s value. No digest: the host computes every hash it signs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignAsk {
    operation_id: String,
    revision_id: u32,
    byte_range: [u64; 4],
    /// The `[0] IMPLICIT` signed attributes, as the CMS carries them.
    signed_attributes_der: ByteBuf,
}

impl<'a> SealCall<'a> {
    /// Checks the engine's revisions before any organ sees them: one per
    /// rung of the contents ladder, each a hole of ASCII zeros after the
    /// prepared PDF, which its ByteRange leaves out and nothing else.
    pub(super) fn new(
        keys: &'a dyn SealKeys,
        operation_id: &str,
        input: &'a EsignSealInput,
    ) -> Result<Self, EsignSealerError> {
        if input.revisions.len() != SEAL_CONTENTS_LADDER.len()
            || (0..input.revisions.len()).any(|index| hole(input, index).is_none())
        {
            return Err(EsignSealerError::Fatal {
                stage: "input_validation".to_owned(),
                code: "invalid_revision".to_owned(),
            });
        }
        Ok(Self {
            keys,
            operation: format!("{operation_id}:"),
            input,
            signer: Mutex::new(None),
            issued: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn revision_args(&self) -> Vec<RevisionArgs> {
        let mut offset = 0;
        let mut args = Vec::new();
        for (id, revision) in (0u32..).zip(&self.input.revisions) {
            let len = revision.suffix.len() as u64;
            args.push(RevisionArgs {
                id,
                suffix_offset: offset,
                suffix_len: len,
                byte_range: revision.byte_range,
            });
            offset += len;
        }
        args
    }

    /// The suffixes, one after another: the call's second input.
    pub(super) fn suffixes(&self) -> Vec<u8> {
        self.input
            .revisions
            .iter()
            .flat_map(|revision| revision.suffix.iter().copied())
            .collect()
    }

    /// `seal.identity`: the key's identity, asked of the key once a call.
    pub(super) fn identity(&self, deadline: Instant) -> Result<SealIdentity, AskRefusal> {
        let mut held = lock(&self.signer);
        if let Some(signer) = held.as_ref() {
            return Ok(signer.identity.clone());
        }
        let identity = self.keys.identity(deadline).map_err(key_refusal)?;
        let unreadable = || AskRefusal::new(AskCode::Failed, "the key's certificate is not DER");
        let cert = x509_cert::Certificate::from_der(&identity.signer_certificate)
            .map_err(|_| unreadable())?;
        let signer = Signer {
            issuer: cert
                .tbs_certificate
                .issuer
                .to_der()
                .map_err(|_| unreadable())?,
            serial: cert
                .tbs_certificate
                .serial_number
                .to_der()
                .map_err(|_| unreadable())?,
            identity,
        };
        *held = Some(signer.clone());
        Ok(signer.identity)
    }

    /// `seal.sign`: one signature over the signed attributes of one of the
    /// engine's revisions, once each. The host hashes the revision's
    /// ByteRange itself, requires the attributes to be exactly the three a
    /// seal signs with that messageDigest and the key's certificate, and
    /// signs SHA-256 of their `SET OF` encoding. It never signs a hash the
    /// organ sent.
    pub(super) fn sign(&self, ask: &AskRequest<'_>) -> Result<Vec<u8>, AskRefusal> {
        let request: SignAsk = decode(ask.value).ok_or_else(|| {
            bad("a signature ask is {operation_id, revision_id, byte_range, signed_attributes_der}")
        })?;
        if !request.operation_id.starts_with(&self.operation) {
            return Err(bad("the operation is not this call's"));
        }
        let signer = lock(&self.signer)
            .clone()
            .ok_or_else(|| bad("ask seal.identity first"))?;
        let index = usize::try_from(request.revision_id).unwrap_or(usize::MAX);
        let (revision, (open, close)) = self
            .input
            .revisions
            .get(index)
            .zip(hole(self.input, index))
            .ok_or_else(|| bad("no such revision"))?;
        if request.byte_range != revision.byte_range {
            return Err(bad("not the revision's ByteRange"));
        }
        if lock(&self.issued)
            .iter()
            .any(|issued| issued.revision == index)
        {
            return Err(bad("the revision is signed already"));
        }
        let base = self.input.pdf.len();
        let content: [u8; 32] = Sha256::new()
            .chain_update(&self.input.pdf)
            .chain_update(&revision.suffix[..open - base])
            .chain_update(&revision.suffix[close - base..])
            .finalize()
            .into();
        let attributes = signed_attributes(&request.signed_attributes_der, &content, &signer)?;
        let prehash: [u8; 32] = Sha256::digest(&attributes).into();
        // On record before the key runs: a key may sign and still fail.
        let mut signed = SignedReceipt {
            operation_id: request.operation_id,
            prehash,
            content_sha256: content,
            revision: Some(request.revision_id),
            signature_sha256: None,
        };
        ask.record_signing(signed.clone());
        let signature = self
            .keys
            .sign_prehash(&signed.operation_id, &prehash, ask.deadline)
            .map_err(key_refusal)?;
        lock(&self.issued).push(Issued {
            revision: index,
            attributes,
            signature: signature.clone(),
        });
        signed.signature_sha256 = Some(Sha256::digest(&signature).into());
        ask.record_signing(signed);
        Ok(signature)
    }

    /// Admits a sealed PDF only when it begins with one of this call's
    /// revisions, unchanged but for the inside of its hole, and that hole
    /// holds one CMS SignedData whose one SignerInfo carries the signature
    /// the key issued for that revision, over the same attributes. Later
    /// revisions (validation data, a document timestamp) may follow only
    /// when `suffix` allows them; their meaning is the verifier's to judge.
    pub(super) fn admit(
        &self,
        output: &[u8],
        suffix: bool,
        limits: &SealLimits,
    ) -> Result<(), EsignSealerError> {
        let unbound = || EsignSealerError::Fatal {
            stage: "binding".to_owned(),
            code: "unbound_output".to_owned(),
        };
        let len = output.len() as u64;
        let base = self.input.pdf.len() as u64;
        if len > base.saturating_add(limits.max_output_growth_bytes) || len > limits.max_input_bytes
        {
            return Err(unbound());
        }
        let signer = lock(&self.signer).clone().ok_or_else(unbound)?;
        let issued = lock(&self.issued);
        if issued
            .iter()
            .any(|issued| self.carries(output, issued, &signer, suffix))
        {
            Ok(())
        } else {
            Err(unbound())
        }
    }

    fn carries(&self, output: &[u8], issued: &Issued, signer: &Signer, suffix: bool) -> bool {
        let pdf = &self.input.pdf;
        let base = pdf.len();
        let Some(((open, close), revision)) =
            hole(self.input, issued.revision).zip(self.input.revisions.get(issued.revision))
        else {
            return false;
        };
        let end = base + revision.suffix.len();
        if output.len() < end || (!suffix && output.len() != end) {
            return false;
        }
        output[..base] == pdf[..]
            && output[base..=open] == revision.suffix[..=open - base]
            && output[close - 1..end] == revision.suffix[close - 1 - base..]
            && holds_issued(&output[open + 1..close - 1], issued, signer)
    }
}

/// The hole of revision `index`: the offsets of its `<` and one past its
/// `>`, in the whole revision. `None` unless the ByteRange leaves out
/// exactly the hole, the hole lies after the prepared PDF, holds this
/// rung's capacity, and is all ASCII zeros.
fn hole(input: &EsignSealInput, index: usize) -> Option<(usize, usize)> {
    let revision = input.revisions.get(index)?;
    let capacity = *SEAL_CONTENTS_LADDER.get(index)?;
    let base = input.pdf.len();
    let len = base.checked_add(revision.suffix.len())?;
    let [start, open, close, rest] = revision.byte_range.map(|at| usize::try_from(at).ok());
    let (open, close, rest) = (open?, close?, rest?);
    if start != Some(0)
        || open < base
        || close.checked_sub(open)? != capacity.checked_mul(2)?.checked_add(2)?
        || close.checked_add(rest)? != len
    {
        return None;
    }
    let hole = &revision.suffix[open - base..close - base];
    let zeros = &hole[1..hole.len() - 1];
    (hole[0] == b'<' && hole[hole.len() - 1] == b'>' && zeros.iter().all(|b| *b == b'0'))
        .then_some((open, close))
}

/// The organ's `[0] IMPLICIT` signed attributes, checked as strict DER and
/// as exactly the three a seal signs: content type id-data, this
/// revision's messageDigest, and signingCertificateV2 for the key's
/// certificate. Returns their `SET OF` encoding, the bytes the key signs.
fn signed_attributes(
    wire: &[u8],
    content: &[u8; 32],
    signer: &Signer,
) -> Result<Vec<u8>, AskRefusal> {
    if wire.first() != Some(&0xA0) {
        return Err(bad("the signed attributes are not [0] IMPLICIT"));
    }
    let mut set = wire.to_vec();
    set[0] = 0x31;
    let parsed =
        SignedAttributes::from_der(&set).map_err(|_| bad("the signed attributes are not DER"))?;
    // Decoding sorts a SET OF: only the same bytes back make it canonical.
    if parsed.to_der().ok().as_deref() != Some(set.as_slice()) {
        return Err(bad("the signed attributes are not canonical DER"));
    }
    let digests: Vec<_> = parsed
        .iter()
        .filter(|attribute| attribute.oid == ID_MESSAGE_DIGEST)
        .collect();
    let digest = match digests.as_slice() {
        [one] if one.values.len() == 1 => one
            .values
            .get(0)
            .and_then(|value| value.decode_as::<OctetString>().ok()),
        _ => None,
    };
    if digest.as_ref().map(OctetString::as_bytes) != Some(content.as_slice()) {
        return Err(bad("the messageDigest is not the revision's"));
    }
    if set != expected_attributes(content, signer) {
        return Err(bad("the signed attributes are not the three a seal signs"));
    }
    Ok(set)
}

/// The three signed attributes a seal signs, as the seal's own assembler
/// writes them, sorted, under the `SET OF` tag.
fn expected_attributes(content: &[u8; 32], signer: &Signer) -> Vec<u8> {
    let attribute = |oid: ObjectIdentifier, value: &[u8]| {
        tlv(
            0x30,
            &[tlv(0x06, oid.as_bytes()), tlv(0x31, value)].concat(),
        )
    };
    let cert_hash = tlv(0x04, &Sha256::digest(&signer.identity.signer_certificate));
    // IssuerSerial: GeneralNames with one directoryName, then the serial.
    let issuer_serial = tlv(
        0x30,
        &[tlv(0x30, &tlv(0xA4, &signer.issuer)), signer.serial.clone()].concat(),
    );
    // SigningCertificateV2 { certs: [ESSCertIDv2 { certHash, issuerSerial }] }
    let signing_certificate = tlv(
        0x30,
        &tlv(0x30, &tlv(0x30, &[cert_hash, issuer_serial].concat())),
    );
    let mut attributes = [
        attribute(ID_CONTENT_TYPE, &tlv(0x06, ID_DATA.as_bytes())),
        attribute(ID_MESSAGE_DIGEST, &tlv(0x04, content)),
        attribute(ID_SIGNING_CERT_V2, &signing_certificate),
    ];
    attributes.sort();
    tlv(0x31, &attributes.concat())
}

/// Whether a hole's hex holds one canonical CMS ContentInfo, then zero
/// padding, in the one shape the native assembler emits: SignedData v1,
/// detached id-data under SHA-256, exactly the X.509 certificates the key
/// handed over (its leaf and chain, once each), no revocation set, and one
/// SignerInfo v1: that certificate's
/// issuer and serial, the issued signature, over the issued attributes.
/// Each algorithm is checked with its parameters (RFC 5754). The DER types
/// accept any version, choice and parameter, so the shape is checked here
/// (Astra and Sol on #1379). The signature is read where CMS puts it, never
/// searched for.
fn holds_issued(hex: &[u8], issued: &Issued, signer: &Signer) -> bool {
    let Some(der) = unhex(hex) else {
        return false;
    };
    let Ok(mut reader) = SliceReader::new(&der) else {
        return false;
    };
    let Ok(info) = ContentInfo::decode(&mut reader) else {
        return false;
    };
    let Ok(used) = usize::try_from(reader.position()) else {
        return false;
    };
    if der[used..].iter().any(|byte| *byte != 0)
        || info.to_der().ok().as_deref() != Some(&der[..used])
        || info.content_type != ID_SIGNED_DATA
    {
        return false;
    }
    let Ok(signed) = info.content.decode_as::<SignedData>() else {
        return false;
    };
    let [signer_info] = signed.signer_infos.0.as_slice() else {
        return false;
    };
    // RFC 5754 §3: ECDSA takes no parameters; RSA PKCS#1 v1.5 absent or NULL.
    let (algorithm, null_parameters) = match signer.identity.algorithm {
        SealAlgorithm::EcdsaP256Sha256 => (ID_ECDSA_SHA256, false),
        SealAlgorithm::RsaPkcs1v15Sha256 => (ID_SHA256_WITH_RSA, true),
    };
    let same_signer = match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(id) => {
            id.issuer.to_der().ok().as_deref() == Some(signer.issuer.as_slice())
                && id.serial_number.to_der().ok().as_deref() == Some(signer.serial.as_slice())
        }
        SignerIdentifier::SubjectKeyIdentifier(_) => false,
    };
    // signingCertificateV2 names the leaf, and a verifier builds its path
    // from the chain the key gave. The set is exactly those, as the
    // assembler writes them (sorted, each once): a missing one breaks the
    // path, and an added one can poison it.
    let carries_identity = signed.certificates.as_ref().is_some_and(|set| {
        let held: Option<Vec<Vec<u8>>> = set
            .0
            .iter()
            .map(|choice| match choice {
                CertificateChoices::Certificate(cert) => cert.to_der().ok(),
                CertificateChoices::Other(_) => None,
            })
            .collect();
        let issued: BTreeSet<&[u8]> = std::iter::once(&signer.identity.signer_certificate)
            .chain(&signer.identity.chain)
            .map(Vec::as_slice)
            .collect();
        held.is_some_and(|held| {
            let distinct: BTreeSet<&[u8]> = held.iter().map(Vec::as_slice).collect();
            distinct.len() == held.len() && distinct == issued
        })
    });
    matches!((signed.to_der(), info.content.to_der()), (Ok(ours), Ok(theirs)) if ours == theirs)
        && signed.version == CmsVersion::V1
        && signer_info.version == CmsVersion::V1
        && signed.crls.is_none()
        && signed.encap_content_info.econtent_type == ID_DATA
        && signed.encap_content_info.econtent.is_none()
        && signed.digest_algorithms.len() == 1
        && signed
            .digest_algorithms
            .iter()
            .all(|alg| is_algorithm(alg, ID_SHA256, true))
        && is_algorithm(&signer_info.digest_alg, ID_SHA256, true)
        && is_algorithm(&signer_info.signature_algorithm, algorithm, null_parameters)
        && same_signer
        && carries_identity
        && signer_info
            .signed_attrs
            .as_ref()
            .and_then(|attributes| attributes.to_der().ok())
            .as_deref()
            == Some(issued.attributes.as_slice())
        && signer_info.signature.as_bytes() == issued.signature.as_slice()
}

/// Whether `id` names `oid` with no parameters, or NULL ones where
/// `null_allowed`; any other value is refused.
fn is_algorithm(id: &AlgorithmIdentifierOwned, oid: ObjectIdentifier, null_allowed: bool) -> bool {
    id.oid == oid
        && match &id.parameters {
            None => true,
            Some(parameters) => null_allowed && *parameters == Any::null(),
        }
}

fn unhex(hex: &[u8]) -> Option<Vec<u8>> {
    let nibble = |byte: u8| char::from(byte).to_digit(16);
    hex.chunks(2)
        .map(|pair| match pair {
            [high, low] => Some((nibble(*high)? * 16 + nibble(*low)?) as u8),
            _ => None,
        })
        .collect()
}

/// A DER TLV with a one-byte tag.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let significant = &bytes[bytes.iter().take_while(|byte| **byte == 0).count()..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

fn decode<T: serde::de::DeserializeOwned>(value: &rmpv::Value) -> Option<T> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).ok()?;
    rmp_serde::from_slice(&bytes).ok()
}

fn bad(detail: &str) -> AskRefusal {
    AskRefusal::new(AskCode::BadRequest, detail)
}

fn key_refusal(err: SealKeyError) -> AskRefusal {
    let refusal = AskRefusal::new(AskCode::Failed, err.detail);
    if err.retryable {
        refusal.retryable()
    } else {
        refusal
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
