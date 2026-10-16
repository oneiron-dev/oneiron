//! A seal key held in files (OF-415): a PKCS#8 private key and its PEM
//! certificate chain, named by the host's configuration. The key signs here
//! and never crosses the organ socket. Its algorithm comes from the key:
//! RSA signs PKCS#1 v1.5 over SHA-256, a P-256 key signs ECDSA in DER.

use std::path::Path;
use std::time::Instant;

use base64::Engine as _;
use der::Decode as _;
use rsa::pkcs1::EncodeRsaPublicKey as _;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::signature::SignatureEncoding as _;
use rsa::signature::hazmat::PrehashSigner as _;

use super::{SealAlgorithm, SealIdentity, SealKeyError, SealKeys};

enum Key {
    Rsa(Box<rsa::pkcs1v15::SigningKey<sha2::Sha256>>),
    P256(p256::ecdsa::SigningKey),
}

/// A seal key read from files once, at load.
pub struct FileSealKeys {
    key: Key,
    identity: SealIdentity,
}

impl std::fmt::Debug for FileSealKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSealKeys")
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

/// Every PEM block in `text`: its label and its DER.
fn pem_blocks(text: &str) -> Result<Vec<(String, Vec<u8>)>, SealKeyError> {
    let mut blocks = Vec::new();
    let mut open: Option<(String, String)> = None;
    for line in text.lines().map(str::trim) {
        if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
        {
            open = Some((label.to_owned(), String::new()));
        } else if let Some(label) = line
            .strip_prefix("-----END ")
            .and_then(|rest| rest.strip_suffix("-----"))
        {
            let (began, body) = open
                .take()
                .ok_or_else(|| refused("a PEM block ends before it begins"))?;
            if began != label {
                return Err(refused("a PEM block ends under another label"));
            }
            let der = base64::engine::general_purpose::STANDARD
                .decode(body.as_bytes())
                .map_err(|_| refused("a PEM block is not base64"))?;
            blocks.push((began, der));
        } else if let Some((_, body)) = open.as_mut() {
            body.push_str(line);
        }
    }
    if open.is_some() {
        return Err(refused("a PEM block never ends"));
    }
    Ok(blocks)
}

/// The certificates (DER) in a PEM file, in order: trust anchors, or a
/// chain.
///
/// # Errors
/// Text that is not PEM, or no certificate in it.
pub fn pem_certificates(pem: &[u8]) -> Result<Vec<Vec<u8>>, SealKeyError> {
    let text = std::str::from_utf8(pem).map_err(|_| refused("the PEM file is not text"))?;
    let certificates: Vec<Vec<u8>> = pem_blocks(text)?
        .into_iter()
        .filter(|(label, _)| label == "CERTIFICATE")
        .map(|(_, der)| der)
        .collect();
    if certificates.is_empty() {
        return Err(refused("the PEM file holds no certificate"));
    }
    Ok(certificates)
}

impl FileSealKeys {
    /// Reads the key (PKCS#8, PEM or DER) and the chain (PEM certificates,
    /// the signer's first, then each issuer nearest first).
    ///
    /// # Errors
    /// A file that cannot be read, a key that is not PKCS#8 RSA or P-256, a
    /// chain with no certificate, or a signer certificate for another key.
    pub fn load(key: &Path, chain: &Path) -> Result<Self, SealKeyError> {
        let read = |path: &Path| {
            std::fs::read(path)
                .map_err(|err| refused(format!("seal key file {}: {err}", path.display())))
        };
        Self::from_files(&read(key)?, &read(chain)?)
    }

    /// [`Self::load`], over the files' bytes.
    ///
    /// # Errors
    /// As [`Self::load`].
    pub fn from_files(key: &[u8], chain: &[u8]) -> Result<Self, SealKeyError> {
        let key_der = if key.starts_with(b"-----BEGIN") {
            let text = std::str::from_utf8(key).map_err(|_| refused("the key PEM is not text"))?;
            let (label, der) = pem_blocks(text)?
                .into_iter()
                .next()
                .ok_or_else(|| refused("the key file holds no PEM block"))?;
            if label != "PRIVATE KEY" {
                return Err(refused(format!(
                    "the seal key is a {label}; convert it to PKCS#8 (PRIVATE KEY)"
                )));
            }
            der
        } else {
            key.to_vec()
        };
        let text = std::str::from_utf8(chain).map_err(|_| refused("the chain PEM is not text"))?;
        let mut certificates = pem_blocks(text)?
            .into_iter()
            .filter(|(label, _)| label == "CERTIFICATE")
            .map(|(_, der)| der);
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
        let (key, algorithm, public) = if let Ok(private) = rsa::RsaPrivateKey::from_pkcs8_der(&key_der)
        {
            let public = private
                .to_public_key()
                .to_pkcs1_der()
                .map_err(|_| refused("the RSA public key does not encode"))?
                .as_bytes()
                .to_vec();
            let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private);
            (
                Key::Rsa(Box::new(signing)),
                SealAlgorithm::RsaPkcs1v15Sha256,
                public,
            )
        } else if let Ok(signing) = p256::ecdsa::SigningKey::from_pkcs8_der(&key_der) {
            let public = signing
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            (Key::P256(signing), SealAlgorithm::EcdsaP256Sha256, public)
        } else {
            return Err(refused(
                "the seal key is neither a PKCS#8 RSA key nor a P-256 one",
            ));
        };
        if public != certified {
            return Err(refused("the signer certificate certifies another key"));
        }
        Ok(Self {
            key,
            identity: SealIdentity {
                algorithm,
                signer_certificate: signer,
                chain,
            },
        })
    }
}

impl SealKeys for FileSealKeys {
    fn identity(&self, _deadline: Instant) -> Result<SealIdentity, SealKeyError> {
        Ok(self.identity.clone())
    }

    fn sign_prehash(
        &self,
        _operation_id: &str,
        digest: &[u8; 32],
        _deadline: Instant,
    ) -> Result<Vec<u8>, SealKeyError> {
        let failed = |err: rsa::signature::Error| SealKeyError {
            detail: format!("the seal key did not sign: {err}"),
            retryable: true,
        };
        match &self.key {
            Key::Rsa(key) => {
                let signature: rsa::pkcs1v15::Signature = key.sign_prehash(digest).map_err(failed)?;
                Ok(signature.to_vec())
            }
            Key::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign_prehash(digest).map_err(failed)?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
        }
    }
}
