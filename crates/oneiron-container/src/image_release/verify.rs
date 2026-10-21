//! `verify_release`: parse, bind to the observed bytes, check the host, read
//! the signature. It reads no file and hashes no artifact: the caller opens
//! the host-owned documents and supplies the digests it measured itself.

use super::ImageReleaseFact;
use super::manifest::{
    BinaryHash, Blake3Digest, ImageArch, ImageReleaseManifest, ImageVariant, KernelVersion,
    ManifestError, ManifestFact, Sha256Digest,
};
use super::signature::{ReleaseSignatureVerifier, SignatureOutcome, signature_outcome};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Digests and identity the caller measured or the runtime addresses. Each
/// `Some` is compared with the manifest; a manifest's own value is never
/// taken as an observation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservedArtifacts {
    pub variant: Option<ImageVariant>,
    pub arch: Option<ImageArch>,
    /// A digest the runtime addresses the image by: a local image id or the
    /// digest of a `name@sha256:<hex>` reference. Docker's classic store
    /// names the config digest, a containerd store the manifest digest, and
    /// a registry reference may name the index, so it matches any of the
    /// three; the manifest lists all of them.
    pub oci_image_digest: Option<Sha256Digest>,
    /// The OCI config digest, for a caller that read the config itself.
    pub oci_config_digest: Option<Sha256Digest>,
    pub oci_archive_sha256: Option<Sha256Digest>,
    pub rootfs_ext4_sha256: Option<Sha256Digest>,
    pub rootfs_ext4_blake3: Option<Blake3Digest>,
    pub kernel_sha256: Option<Sha256Digest>,
    pub kernel_blake3: Option<Blake3Digest>,
    pub guest_sha256: Option<Sha256Digest>,
    pub fence_sha256: Option<Sha256Digest>,
    pub relay_sha256: Option<Sha256Digest>,
}

impl ObservedArtifacts {
    /// What a pinned image reference names.
    #[must_use]
    pub fn from_image_ref(image: &crate::ImageRef) -> Self {
        Self::default().with_image_ref(image)
    }

    /// Adds the digest a pinned image reference names, `name@sha256:<hex>`
    /// or a local image id `sha256:<hex>`.
    #[must_use]
    pub fn with_image_ref(self, image: &crate::ImageRef) -> Self {
        let reference = image.as_str();
        let digest = reference
            .split_once('@')
            .map_or(reference, |(_, digest)| digest);
        Self {
            oci_image_digest: Sha256Digest::parse(digest).ok(),
            ..self
        }
    }

    /// The Firecracker host pins: BLAKE3 over the kernel and the rootfs,
    /// verified against the files about to boot.
    #[must_use]
    pub fn from_firecracker_pins(kernel: [u8; 32], rootfs: [u8; 32]) -> Self {
        Self {
            kernel_blake3: Some(Blake3Digest::from_bytes(kernel)),
            rootfs_ext4_blake3: Some(Blake3Digest::from_bytes(rootfs)),
            ..Self::default()
        }
    }
}

/// What the host observed about itself. `None` is unobserved, never assumed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostCapabilities {
    pub arch: Option<ImageArch>,
    pub kvm: Option<bool>,
    pub kernel: Option<KernelVersion>,
    pub landlock_abi: Option<u32>,
    pub seccomp_user_notify: Option<bool>,
    /// The storage ABI of the vault data the image's engine would open.
    pub storage_abi: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    Variant,
    Arch,
    OciImage,
    OciConfig,
    OciArchive,
    RootfsExt4Sha256,
    RootfsExt4Blake3,
    KernelSha256,
    KernelBlake3,
    Guest,
    Fence,
    Relay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Matched,
    Mismatched,
    /// Observed, but the manifest lists no value for it.
    NotInManifest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCheck {
    pub role: ArtifactRole,
    pub outcome: CheckOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostRequirement {
    Arch,
    Kvm,
    KernelFloor,
    LandlockAbi,
    SeccompUserNotify,
    StorageAbi,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostOutcome {
    Met,
    Missing,
    Unobserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCheck {
    pub requirement: HostRequirement,
    pub outcome: HostOutcome,
}

/// Everything one verification found. It is never a bare success: the
/// signature slot and the facts say what was and was not established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseVerification {
    /// BLAKE3 of the exact manifest bytes the signature covers.
    pub manifest_digest: Blake3Digest,
    pub manifest: Result<ImageReleaseManifest, ManifestError>,
    pub artifacts: Vec<ArtifactCheck>,
    pub host: Vec<HostCheck>,
    pub signature: SignatureOutcome,
    /// Every fact, once each, in declaration order.
    pub facts: Vec<ImageReleaseFact>,
}

/// Parses `manifest_bytes`, compares each observed digest with it, checks
/// the host against its needs and reads the signature over the same bytes.
/// An image without an envelope is [`SignatureOutcome::Unavailable`] with the
/// fact `image_signature_unavailable`, never a pass. Nothing here refuses:
/// [`super::release_admission`] maps the result under a policy.
#[must_use]
pub fn verify_release(
    manifest_bytes: &[u8],
    envelope: Option<&[u8]>,
    observed: &ObservedArtifacts,
    host: &HostCapabilities,
    verifier: &dyn ReleaseSignatureVerifier,
) -> ReleaseVerification {
    let mut facts = BTreeSet::new();
    let manifest = ImageReleaseManifest::parse(manifest_bytes);
    let (artifacts, checks) = match &manifest {
        Ok(manifest) => {
            let artifacts = artifact_checks(manifest, observed);
            let checks = host_checks(manifest, host);
            binding_facts(manifest, &artifacts, &checks, &mut facts);
            (artifacts, checks)
        }
        Err(_) => {
            facts.insert(ImageReleaseFact::ReleaseManifestMalformed);
            (Vec::new(), Vec::new())
        }
    };
    let signature = signature_outcome(manifest_bytes, envelope, verifier);
    match &signature {
        SignatureOutcome::Verified { .. } => {}
        SignatureOutcome::Unavailable => {
            facts.insert(ImageReleaseFact::SignatureUnavailable);
        }
        SignatureOutcome::Unverifiable { .. } => {
            facts.insert(ImageReleaseFact::SignatureUnverifiable);
        }
        SignatureOutcome::Invalid { .. } => {
            facts.insert(ImageReleaseFact::SignatureInvalid);
        }
    }
    ReleaseVerification {
        manifest_digest: Blake3Digest::from_bytes(*blake3::hash(manifest_bytes).as_bytes()),
        manifest,
        artifacts,
        host: checks,
        signature,
        facts: facts.into_iter().collect(),
    }
}

fn compare<T: PartialEq>(observed: Option<&T>, listed: Option<&T>) -> Option<CheckOutcome> {
    let observed = observed?;
    Some(match listed {
        None => CheckOutcome::NotInManifest,
        Some(listed) if listed == observed => CheckOutcome::Matched,
        Some(_) => CheckOutcome::Mismatched,
    })
}

fn binary(hash: Option<&BinaryHash>) -> Option<&Sha256Digest> {
    hash.map(|b| &b.sha256)
}

fn artifact_checks(m: &ImageReleaseManifest, o: &ObservedArtifacts) -> Vec<ArtifactCheck> {
    let a = &m.artifacts;
    let kernel = a.kernel.image.as_ref();
    let image = o.oci_image_digest.as_ref().map(|digest| {
        if *digest == a.oci.config_digest
            || *digest == a.oci.manifest_digest
            || *digest == a.oci.index_digest
        {
            CheckOutcome::Matched
        } else {
            CheckOutcome::Mismatched
        }
    });
    [
        (
            ArtifactRole::Variant,
            compare(o.variant.as_ref(), Some(&m.variant)),
        ),
        (ArtifactRole::Arch, compare(o.arch.as_ref(), Some(&m.arch))),
        (ArtifactRole::OciImage, image),
        (
            ArtifactRole::OciConfig,
            compare(o.oci_config_digest.as_ref(), Some(&a.oci.config_digest)),
        ),
        (
            ArtifactRole::OciArchive,
            compare(o.oci_archive_sha256.as_ref(), Some(&a.oci.archive.sha256)),
        ),
        (
            ArtifactRole::RootfsExt4Sha256,
            compare(o.rootfs_ext4_sha256.as_ref(), Some(&a.rootfs_ext4.sha256)),
        ),
        (
            ArtifactRole::RootfsExt4Blake3,
            compare(o.rootfs_ext4_blake3.as_ref(), a.rootfs_ext4.blake3.as_ref()),
        ),
        (
            ArtifactRole::KernelSha256,
            compare(o.kernel_sha256.as_ref(), kernel.map(|k| &k.sha256)),
        ),
        (
            ArtifactRole::KernelBlake3,
            compare(
                o.kernel_blake3.as_ref(),
                kernel.and_then(|k| k.blake3.as_ref()),
            ),
        ),
        (
            ArtifactRole::Guest,
            compare(o.guest_sha256.as_ref(), binary(m.binaries.guest.as_ref())),
        ),
        (
            ArtifactRole::Fence,
            compare(o.fence_sha256.as_ref(), binary(m.binaries.fence.as_ref())),
        ),
        (
            ArtifactRole::Relay,
            compare(o.relay_sha256.as_ref(), binary(m.binaries.relay.as_ref())),
        ),
    ]
    .into_iter()
    .filter_map(|(role, outcome)| outcome.map(|outcome| ArtifactCheck { role, outcome }))
    .collect()
}

fn met(observed: Option<bool>) -> HostOutcome {
    match observed {
        Some(true) => HostOutcome::Met,
        Some(false) => HostOutcome::Missing,
        None => HostOutcome::Unobserved,
    }
}

fn host_checks(m: &ImageReleaseManifest, h: &HostCapabilities) -> Vec<HostCheck> {
    let need = &m.host;
    let mut checks = vec![(HostRequirement::Arch, met(h.arch.map(|a| a == m.arch)))];
    if need.kvm {
        checks.push((HostRequirement::Kvm, met(h.kvm)));
    }
    if let Some(floor) = need.kernel_floor {
        checks.push((
            HostRequirement::KernelFloor,
            met(h.kernel.map(|k| k >= floor)),
        ));
    }
    if let Some(floor) = need.landlock_abi_floor {
        let abi = h.landlock_abi.map(|abi| abi >= floor);
        checks.push((HostRequirement::LandlockAbi, met(abi)));
    }
    if need.seccomp_user_notify {
        checks.push((
            HostRequirement::SeccompUserNotify,
            met(h.seccomp_user_notify),
        ));
    }
    if let Some(storage) = m.contracts.storage {
        // An engine older than the data it would open is a downgrade.
        let abi = h.storage_abi.map(|data| storage.abi_version >= data);
        checks.push((HostRequirement::StorageAbi, met(abi)));
    }
    checks
        .into_iter()
        .map(|(requirement, outcome)| HostCheck {
            requirement,
            outcome,
        })
        .collect()
}

fn binding_facts(
    manifest: &ImageReleaseManifest,
    artifacts: &[ArtifactCheck],
    host: &[HostCheck],
    facts: &mut BTreeSet<ImageReleaseFact>,
) {
    let identity = |role: ArtifactRole| matches!(role, ArtifactRole::Variant | ArtifactRole::Arch);
    for check in artifacts {
        if check.outcome == CheckOutcome::Mismatched {
            facts.insert(if identity(check.role) {
                ImageReleaseFact::IdentityMismatch
            } else {
                ImageReleaseFact::ArtifactMismatch
            });
        }
    }
    if !artifacts
        .iter()
        .any(|c| !identity(c.role) && c.outcome == CheckOutcome::Matched)
    {
        facts.insert(ImageReleaseFact::ArtifactsUnbound);
    }
    for check in host {
        match (check.requirement, check.outcome) {
            (_, HostOutcome::Met) => {}
            (HostRequirement::StorageAbi, HostOutcome::Missing) => {
                facts.insert(ImageReleaseFact::StorageAbiOlderThanHost);
            }
            (_, HostOutcome::Missing) => {
                facts.insert(ImageReleaseFact::HostCapabilityMissing);
            }
            (_, HostOutcome::Unobserved) => {
                facts.insert(ImageReleaseFact::HostCapabilityUnobserved);
            }
        }
    }
    if manifest.facts.contains(&ManifestFact::Blake3Unmeasured) {
        facts.insert(ImageReleaseFact::Blake3Unmeasured);
    }
}
