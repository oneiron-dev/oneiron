//! Signed guest-image releases (FIX 8253, OS-IMAGE phase 1c): the release
//! manifest, ONE signature-verifier seam, the verification an installer or a
//! launch door runs before it uses an image, and the observe-only policy that
//! maps the result.
//!
//! No signing key exists. An image without a signature is reported as the
//! typed fact `image_signature_unavailable`, never as a pass. Under
//! [`IMAGE_SIGNATURE_POLICY`] (`ObserveOnly`) nothing here refuses a launch
//! or an install: every existing pin, fence and image-match check stays where
//! it is and decides exactly as before. The wire format and the call shapes
//! are in `crates/oneiron-container/images/manifest.md`.
//!
//! This module reads no file and hashes no artifact. The caller opens the
//! host-owned release documents and supplies the digests it measured.

mod manifest;
mod signature;
mod verify;

pub use manifest::{
    BinaryHash, Blake3Digest, ContractRevisions, DigestError, DocumentRef, EngineRelease,
    FileArtifact, GuestBinaries, HostRequirements, IMAGE_RELEASE_KIND, IMAGE_RELEASE_SCHEMA,
    ImageArch, ImageReleaseManifest, ImageVariant, KernelRef, KernelVersion, ManifestError,
    ManifestFact, OciArtifacts, ReleaseArtifacts, Sha256Digest, SnapshotCompatibility, SourcePin,
    StorageAbi, UnversionedContracts, VaultContractRevisions,
};
pub use signature::{
    NoVerifierConfigured, ReleaseSignatureVerifier, SignatureEnvelope, SignatureOutcome,
    SignatureProvider, SignatureRefusal, SignerIdentity,
};
pub use verify::{
    ArtifactCheck, ArtifactRole, CheckOutcome, HostCapabilities, HostCheck, HostOutcome,
    HostRequirement, ObservedArtifacts, ReleaseVerification, verify_release,
};

use serde::{Deserialize, Serialize};

/// The manifest's file name beside its artifacts.
pub const IMAGE_RELEASE_FILE: &str = "image-release.json";
/// The detached signature envelope's file name beside the manifest.
pub const IMAGE_RELEASE_ENVELOPE_FILE: &str = "image-release.sig.json";

/// No release manifest is bound to the image.
pub const IMAGE_RELEASE_MANIFEST_ABSENT: &str = "image_release_manifest_absent";
/// The manifest bytes are not the closed schema.
pub const IMAGE_RELEASE_MANIFEST_MALFORMED: &str = "image_release_manifest_malformed";
/// An observed variant or architecture differs from the manifest's.
pub const IMAGE_IDENTITY_MISMATCH: &str = "image_identity_mismatch";
/// An observed digest differs from the manifest's.
pub const IMAGE_ARTIFACT_MISMATCH: &str = "image_artifact_mismatch";
/// No observed digest matched: the manifest is not bound to the bytes in use.
pub const IMAGE_ARTIFACTS_UNBOUND: &str = "image_artifacts_unbound";
/// The manifest lists no BLAKE3, so the Firecracker pins cannot bind to it.
pub const IMAGE_BLAKE3_UNMEASURED: &str = "image_blake3_unmeasured";
/// The host lacks a capability the image needs.
pub const IMAGE_HOST_CAPABILITY_MISSING: &str = "image_host_capability_missing";
/// The caller did not observe a capability the image needs.
pub const IMAGE_HOST_CAPABILITY_UNOBSERVED: &str = "image_host_capability_unobserved";
/// The image's engine writes an older storage ABI than the data it would open.
pub const IMAGE_STORAGE_ABI_OLDER_THAN_HOST: &str = "image_storage_abi_older_than_host";
/// No signature envelope exists. Today every image is unsigned.
pub const IMAGE_SIGNATURE_UNAVAILABLE: &str = "image_signature_unavailable";
/// An envelope is present, but no configured verifier can check it.
pub const IMAGE_SIGNATURE_UNVERIFIABLE: &str = "image_signature_unverifiable";
/// An envelope is present and did not verify.
pub const IMAGE_SIGNATURE_INVALID: &str = "image_signature_invalid";

/// One typed fact about an image release, on the wire as its code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageReleaseFact {
    ImageReleaseManifestAbsent,
    ImageReleaseManifestMalformed,
    ImageIdentityMismatch,
    ImageArtifactMismatch,
    ImageArtifactsUnbound,
    ImageBlake3Unmeasured,
    ImageHostCapabilityMissing,
    ImageHostCapabilityUnobserved,
    ImageStorageAbiOlderThanHost,
    ImageSignatureUnavailable,
    ImageSignatureUnverifiable,
    ImageSignatureInvalid,
}

impl ImageReleaseFact {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImageReleaseManifestAbsent => IMAGE_RELEASE_MANIFEST_ABSENT,
            Self::ImageReleaseManifestMalformed => IMAGE_RELEASE_MANIFEST_MALFORMED,
            Self::ImageIdentityMismatch => IMAGE_IDENTITY_MISMATCH,
            Self::ImageArtifactMismatch => IMAGE_ARTIFACT_MISMATCH,
            Self::ImageArtifactsUnbound => IMAGE_ARTIFACTS_UNBOUND,
            Self::ImageBlake3Unmeasured => IMAGE_BLAKE3_UNMEASURED,
            Self::ImageHostCapabilityMissing => IMAGE_HOST_CAPABILITY_MISSING,
            Self::ImageHostCapabilityUnobserved => IMAGE_HOST_CAPABILITY_UNOBSERVED,
            Self::ImageStorageAbiOlderThanHost => IMAGE_STORAGE_ABI_OLDER_THAN_HOST,
            Self::ImageSignatureUnavailable => IMAGE_SIGNATURE_UNAVAILABLE,
            Self::ImageSignatureUnverifiable => IMAGE_SIGNATURE_UNVERIFIABLE,
            Self::ImageSignatureInvalid => IMAGE_SIGNATURE_INVALID,
        }
    }
}

/// How a verification result decides an install or a launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSignaturePolicy {
    /// Record every fact and admit exactly what the existing checks admit.
    ObserveOnly,
    /// Admit only a verified signature over a manifest bound to the observed
    /// bytes, with no fact left. Nothing selects it: it narrows what runs,
    /// so it waits for an owner ruling, enrolled trust and a rollout.
    RequireVerified,
}

/// The ONE policy switch every installer and launch door maps through.
pub const IMAGE_SIGNATURE_POLICY: ImageSignaturePolicy = ImageSignaturePolicy::ObserveOnly;

/// A policy's answer, with the facts it saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseAdmission {
    Admit { facts: Vec<ImageReleaseFact> },
    Refuse { facts: Vec<ImageReleaseFact> },
}

impl ReleaseAdmission {
    #[must_use]
    pub const fn admitted(&self) -> bool {
        matches!(self, Self::Admit { .. })
    }

    #[must_use]
    pub fn facts(&self) -> &[ImageReleaseFact] {
        match self {
            Self::Admit { facts } | Self::Refuse { facts } => facts,
        }
    }
}

/// Maps a verification under `policy`. `ObserveOnly` always admits and
/// returns the facts.
#[must_use]
pub fn release_admission(
    verification: &ReleaseVerification,
    policy: ImageSignaturePolicy,
) -> ReleaseAdmission {
    let facts = verification.facts.clone();
    match policy {
        ImageSignaturePolicy::ObserveOnly => ReleaseAdmission::Admit { facts },
        ImageSignaturePolicy::RequireVerified => {
            if matches!(verification.signature, SignatureOutcome::Verified { .. })
                && verification.manifest.is_ok()
                && facts.is_empty()
            {
                ReleaseAdmission::Admit { facts }
            } else {
                ReleaseAdmission::Refuse { facts }
            }
        }
    }
}

/// The host-owned release documents bound to the selected image.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseDocuments<'a> {
    /// The exact `image-release.json` bytes.
    pub manifest: &'a [u8],
    /// The exact `image-release.sig.json` bytes, when one exists.
    pub envelope: Option<&'a [u8]>,
}

/// Which manifest an install or a launch saw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ManifestObservation {
    Absent,
    Parsed {
        digest: Blake3Digest,
        variant: ImageVariant,
        arch: ImageArch,
        generation: String,
    },
    Malformed {
        digest: Blake3Digest,
        reason: String,
    },
}

/// The fact record a launch or an install attaches to its evidence (the
/// session manifest, an install record). Evidence only: it never decides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageReleaseObservation {
    pub manifest: ManifestObservation,
    pub signature: SignatureOutcome,
    pub facts: Vec<ImageReleaseFact>,
    pub policy: ImageSignaturePolicy,
    /// What `policy` answered. Under `ObserveOnly` always true.
    pub admitted: bool,
}

impl ImageReleaseObservation {
    /// Today's state at every launch door: no release manifest is bound, so
    /// no signature either.
    #[must_use]
    pub fn manifest_absent(policy: ImageSignaturePolicy) -> Self {
        Self {
            manifest: ManifestObservation::Absent,
            signature: SignatureOutcome::Unavailable,
            facts: vec![
                ImageReleaseFact::ImageReleaseManifestAbsent,
                ImageReleaseFact::ImageSignatureUnavailable,
            ],
            policy,
            admitted: policy == ImageSignaturePolicy::ObserveOnly,
        }
    }

    #[must_use]
    pub fn from_verification(
        verification: &ReleaseVerification,
        policy: ImageSignaturePolicy,
    ) -> Self {
        let manifest = match &verification.manifest {
            Ok(manifest) => ManifestObservation::Parsed {
                digest: verification.manifest_digest.clone(),
                variant: manifest.variant,
                arch: manifest.arch,
                generation: manifest.generation.clone(),
            },
            Err(error) => ManifestObservation::Malformed {
                digest: verification.manifest_digest.clone(),
                reason: error.to_string(),
            },
        };
        Self {
            manifest,
            signature: verification.signature.clone(),
            facts: verification.facts.clone(),
            policy,
            admitted: release_admission(verification, policy).admitted(),
        }
    }
}

/// A session record that predates the observation saw no manifest either.
impl Default for ImageReleaseObservation {
    fn default() -> Self {
        Self::manifest_absent(IMAGE_SIGNATURE_POLICY)
    }
}

/// The ONE observe path every launch door and installer calls, before it
/// starts or imports the image. `release` is the host-owned documents bound
/// to the selected image; no such binding exists yet, so launch doors pass
/// `None` and record `image_release_manifest_absent` and
/// `image_signature_unavailable`. Infallible: nothing is refused here.
#[must_use]
pub fn observe_release(
    release: Option<ReleaseDocuments<'_>>,
    observed: &ObservedArtifacts,
    host: &HostCapabilities,
    verifier: &dyn ReleaseSignatureVerifier,
) -> ImageReleaseObservation {
    match release {
        None => ImageReleaseObservation::manifest_absent(IMAGE_SIGNATURE_POLICY),
        Some(documents) => ImageReleaseObservation::from_verification(
            &verify_release(
                documents.manifest,
                documents.envelope,
                observed,
                host,
                verifier,
            ),
            IMAGE_SIGNATURE_POLICY,
        ),
    }
}
