//! A seal key held in secret custody (FIX 1297): its PKCS#8 private key is
//! a custody record's value, named by the record's handle, and its PEM
//! certificate chain is a file, as a file-backed key's is. The chain is read
//! once, at load, and names the signing identity. Each signature is one use
//! of the record ([`Vault::use_seal_secret_with`]): the custody door lends the
//! key to it under the record's binding and door policy, and records the
//! use. The key is parsed inside the lend, signs once and is dropped there,
//! zeroized; it never crosses the organ socket and is never stored here.

use std::path::Path;
use std::time::Instant;

use base64::Engine as _;
use der::Decode as _;
use oneiron::Vault;
use p256::elliptic_curve::zeroize::Zeroizing;
use rsa::pkcs1::{DecodeRsaPublicKey as _, EncodeRsaPublicKey as _};
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::signature::SignatureEncoding as _;
use rsa::signature::hazmat::PrehashSigner as _;

use super::{SealAlgorithm, SealIdentity, SealKeyError, SealKeys, pem_certificates};

/// A seal key in secret custody, by its handle, beside its chain.
pub struct CustodySealKeys<'a> {
    vault: &'a Vault,
    /// The custody record's handle, such as `sc12`.
    handle: String,
    identity: SealIdentity,
    /// The signer certificate's public key, as it certifies it: the key the
    /// custody value must be.
    certified: Vec<u8>,
}

impl std::fmt::Debug for CustodySealKeys<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustodySealKeys")
            .field("handle", &self.handle)
            .field("algorithm", &self.identity.algorithm)
            .finish_non_exhaustive()
    }
}

fn refused(detail: impl Into<String>) -> SealKeyError {
    SealKeyError {
        detail: detail.into(),
        retryable: false,
    }
}

impl<'a> CustodySealKeys<'a> {
    /// The key `handle` names in `vault`'s secret custody, and the chain
    /// (PEM certificates, the signer's first, then each issuer nearest
    /// first) read from `chain`.
    ///
    /// # Errors
    /// A chain file that cannot be read, or as [`Self::from_chain`].
    pub fn load(
        vault: &'a Vault,
        handle: impl Into<String>,
        chain: &Path,
    ) -> Result<Self, SealKeyError> {
        let pem = std::fs::read(chain)
            .map_err(|err| refused(format!("seal chain file {}: {err}", chain.display())))?;
        Self::from_chain(vault, handle, &pem)
    }

    /// [`Self::load`], over the chain file's bytes. The algorithm is the
    /// signer certificate's key's: RSA, or P-256. The key itself is read only
    /// when it signs.
    ///
    /// # Errors
    /// A chain with no certificate, a signer certificate that does not parse,
    /// or one that certifies neither an RSA key nor a P-256 one.
    pub fn from_chain(
        vault: &'a Vault,
        handle: impl Into<String>,
        chain: &[u8],
    ) -> Result<Self, SealKeyError> {
        let mut certificates = pem_certificates(chain)?.into_iter();
        let signer = certificates
            .next()
            .ok_or_else(|| refused("the chain file holds no certificate"))?;
        let chain: Vec<Vec<u8>> = certificates.collect();
        let leaf = x509_cert::Certificate::from_der(&signer)
            .map_err(|_| refused("the signer certificate does not parse"))?;
        let certified = leaf
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        let algorithm = if rsa::RsaPublicKey::from_pkcs1_der(&certified).is_ok() {
            SealAlgorithm::RsaPkcs1v15Sha256
        } else if p256::ecdsa::VerifyingKey::from_sec1_bytes(&certified).is_ok() {
            SealAlgorithm::EcdsaP256Sha256
        } else {
            return Err(refused(
                "the signer certificate certifies neither an RSA key nor a P-256 one",
            ));
        };
        Ok(Self {
            vault,
            handle: handle.into(),
            identity: SealIdentity {
                algorithm,
                signer_certificate: signer,
                chain,
            },
            certified,
        })
    }
}

/// The PKCS#8 DER of a custody value, PEM or DER, in a buffer zeroized on
/// drop.
fn key_der(value: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealKeyError> {
    let value = value.trim_ascii();
    if !value.starts_with(b"-----BEGIN") {
        return Ok(Zeroizing::new(value.to_vec()));
    }
    let text = std::str::from_utf8(value).map_err(|_| refused("the key PEM is not text"))?;
    let mut label = None;
    let mut body = Zeroizing::new(String::with_capacity(text.len()));
    for line in text.lines().map(str::trim) {
        if let Some(begun) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
        {
            if label.is_some() {
                break;
            }
            label = Some(begun);
        } else if line.starts_with("-----END ") {
            break;
        } else if label.is_some() {
            body.push_str(line);
        }
    }
    let label = label.ok_or_else(|| refused("the key holds no PEM block"))?;
    if label != "PRIVATE KEY" {
        return Err(refused(format!(
            "the seal key is a {label}; convert it to PKCS#8 (PRIVATE KEY)"
        )));
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| refused("the key PEM is not base64"))
}

/// Signs `digest` with the key `value` holds, after checking it is the key
/// `certified` names. The parsed key is dropped, zeroized, before this
/// returns.
fn sign_with(
    algorithm: SealAlgorithm,
    certified: &[u8],
    value: &[u8],
    digest: &[u8; 32],
) -> Result<Vec<u8>, SealKeyError> {
    let der = key_der(value)?;
    let failed = |err: rsa::signature::Error| SealKeyError {
        detail: format!("the seal key did not sign: {err}"),
        retryable: true,
    };
    let another = || refused("the signer certificate certifies another key");
    match algorithm {
        SealAlgorithm::RsaPkcs1v15Sha256 => {
            let private = rsa::RsaPrivateKey::from_pkcs8_der(&der)
                .map_err(|_| refused("the seal key in custody is not a PKCS#8 RSA key"))?;
            let public = private
                .to_public_key()
                .to_pkcs1_der()
                .map_err(|_| refused("the RSA public key does not encode"))?;
            if public.as_bytes() != certified {
                return Err(another());
            }
            let key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private);
            let signature: rsa::pkcs1v15::Signature = key.sign_prehash(digest).map_err(failed)?;
            Ok(signature.to_vec())
        }
        SealAlgorithm::EcdsaP256Sha256 => {
            let key = p256::ecdsa::SigningKey::from_pkcs8_der(&der)
                .map_err(|_| refused("the seal key in custody is not a PKCS#8 P-256 key"))?;
            if key.verifying_key().to_encoded_point(false).as_bytes() != certified {
                return Err(another());
            }
            let signature: p256::ecdsa::Signature = key.sign_prehash(digest).map_err(failed)?;
            Ok(signature.to_der().as_bytes().to_vec())
        }
    }
}

impl SealKeys for CustodySealKeys<'_> {
    fn identity(&self, _deadline: Instant) -> Result<SealIdentity, SealKeyError> {
        Ok(self.identity.clone())
    }

    fn sign_prehash(
        &self,
        _operation_id: &str,
        digest: &[u8; 32],
        _deadline: Instant,
    ) -> Result<Vec<u8>, SealKeyError> {
        let algorithm = self.identity.algorithm;
        let mut signature = None;
        let mut retryable = false;
        // The key is lent here, inside the custody door, and dropped here.
        let mut sign = |value: &[u8]| match sign_with(algorithm, &self.certified, value, digest) {
            Ok(signed) => {
                signature = Some(signed);
                Ok(())
            }
            Err(err) => {
                retryable = err.retryable;
                Err(err.detail)
            }
        };
        let used = self
            .vault
            .use_seal_secret_with(&self.handle, &mut sign)
            .map_err(|err| SealKeyError {
                detail: format!("the seal key's custody: {err}"),
                // The handle, its record, its binding or the door refused:
                // the owner's act changes that, not a retry.
                retryable: !matches!(err, oneiron::Error::Secret(_) | oneiron::Error::Gate(_)),
            })?;
        if let Some(detail) = used.failure {
            return Err(SealKeyError { detail, retryable });
        }
        signature.ok_or_else(|| SealKeyError {
            detail: "the seal key's custody lent no key".to_owned(),
            retryable: true,
        })
    }
}
