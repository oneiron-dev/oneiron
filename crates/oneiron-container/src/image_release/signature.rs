//! The detached signature envelope and the ONE verifier seam.
//!
//! The signature covers the exact bytes of `image-release.json`; the envelope
//! is a separate file, `image-release.sig.json`, so signing never rewrites
//! the payload and no canonical JSON form is needed. The envelope is shaped
//! after a Sigstore bundle's verification material
//! (<https://docs.sigstore.dev/about/bundle/>; the formal schema is
//! `sigstore_bundle.proto` in sigstore/protobuf-specs, media type
//! `application/vnd.dev.sigstore.bundle.v0.3+json`), as `cosign sign-blob
//! --bundle` writes it for a blob. Three providers fill the same fields
//! without any caller changing:
//!
//! - `kms_hsm`: a release key held in a KMS or HSM after its ceremony.
//!   `key_or_identity_ref` names the enrolled key; `signature` is its
//!   signature over the manifest bytes.
//! - `sigstore_keyless`: cosign keyless with an OIDC identity. The short-lived
//!   Fulcio certificate and the Rekor entry travel in `certificate_or_bundle`
//!   (the whole v0.3 bundle); `key_or_identity_ref` names the expected issuer
//!   and subject.
//! - `owner_hardware_key`: a hardware key the owner holds, shaped as `kms_hsm`.
//!
//! A key reference or an embedded certificate is a lookup hint, never trust:
//! the verifier adapter decides from roots and identities it holds itself.
//! No adapter ships here. [`NoVerifierConfigured`] is the only implementation
//! until one does.

use serde::{Deserialize, Serialize};

/// Who made a signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureProvider {
    KmsHsm,
    SigstoreKeyless,
    OwnerHardwareKey,
}

/// `image-release.sig.json`: a signature over the exact manifest file bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub provider: SignatureProvider,
    /// The signature algorithm label, e.g. `ecdsa-p256-sha256`. The adapter
    /// owns the list it accepts.
    pub algorithm: String,
    /// The enrolled key's id, or the keyless identity (issuer and subject).
    pub key_or_identity_ref: String,
    /// The signature, standard base64.
    pub signature: String,
    /// A PEM certificate chain or a whole Sigstore bundle, when the provider
    /// has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_or_bundle: Option<String>,
}

impl SignatureEnvelope {
    /// Decodes the closed envelope. A malformed one is an invalid signature,
    /// never an absent one.
    pub fn parse(bytes: &[u8]) -> Result<Self, SignatureRefusal> {
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|_| SignatureRefusal::MalformedEnvelope)?;
        let label = |text: &str| {
            !text.is_empty()
                && text.len() <= 64
                && text
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        };
        if !label(&envelope.algorithm)
            || envelope.key_or_identity_ref.trim().is_empty()
            || envelope.signature.trim().is_empty()
        {
            return Err(SignatureRefusal::MalformedEnvelope);
        }
        Ok(envelope)
    }
}

/// The identity a verifier established, from roots it trusts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerIdentity {
    pub provider: SignatureProvider,
    /// A trusted key id, or the verified issuer and subject.
    pub identity: String,
}

/// Why a present signature did not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum SignatureRefusal {
    #[error("no release-signature verifier is configured")]
    NoVerifierConfigured,
    #[error("the configured verifier does not handle this provider or algorithm")]
    UnsupportedProvider,
    #[error("the signature envelope is not the closed envelope shape")]
    MalformedEnvelope,
    #[error("the signature does not verify over the manifest bytes")]
    BadSignature,
    #[error("the signer is not a trusted release identity")]
    UntrustedSigner,
    #[error("the signing key or certificate is outside its validity")]
    Expired,
    #[error("the signing key or identity is revoked")]
    Revoked,
}

impl SignatureRefusal {
    /// True when the refusal says nothing about the signature, only that
    /// nothing here could check it.
    #[must_use]
    pub const fn is_unverifiable(self) -> bool {
        matches!(self, Self::NoVerifierConfigured | Self::UnsupportedProvider)
    }
}

/// The ONE signer seam. An adapter verifies `envelope` over `payload`, the
/// exact manifest bytes, against trust it holds itself. KMS/HSM, Sigstore
/// keyless and owner hardware keys are adapters of this trait; callers never
/// name a provider.
pub trait ReleaseSignatureVerifier {
    fn verify(
        &self,
        payload: &[u8],
        envelope: &SignatureEnvelope,
    ) -> Result<SignerIdentity, SignatureRefusal>;
}

/// The shipped verifier: no signing key exists, so nothing is trusted and
/// every present signature is unverifiable.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoVerifierConfigured;

impl ReleaseSignatureVerifier for NoVerifierConfigured {
    fn verify(
        &self,
        _payload: &[u8],
        _envelope: &SignatureEnvelope,
    ) -> Result<SignerIdentity, SignatureRefusal> {
        Err(SignatureRefusal::NoVerifierConfigured)
    }
}

/// What the signature slot says. An unsigned image is `Unavailable`, never a
/// pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SignatureOutcome {
    Verified {
        signer: SignerIdentity,
    },
    /// No envelope: `image_signature_unavailable`.
    Unavailable,
    /// An envelope is present but nothing here can check it.
    Unverifiable {
        provider: SignatureProvider,
        refusal: SignatureRefusal,
    },
    Invalid {
        refusal: SignatureRefusal,
    },
}

/// Reads the envelope, if any, and asks the verifier.
pub(super) fn signature_outcome(
    payload: &[u8],
    envelope: Option<&[u8]>,
    verifier: &dyn ReleaseSignatureVerifier,
) -> SignatureOutcome {
    let Some(bytes) = envelope else {
        return SignatureOutcome::Unavailable;
    };
    let envelope = match SignatureEnvelope::parse(bytes) {
        Ok(envelope) => envelope,
        Err(refusal) => return SignatureOutcome::Invalid { refusal },
    };
    match verifier.verify(payload, &envelope) {
        Ok(signer) => SignatureOutcome::Verified { signer },
        Err(refusal) if refusal.is_unverifiable() => SignatureOutcome::Unverifiable {
            provider: envelope.provider,
            refusal,
        },
        Err(refusal) => SignatureOutcome::Invalid { refusal },
    }
}
