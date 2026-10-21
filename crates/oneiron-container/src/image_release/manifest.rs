//! The release manifest payload, `image-release.json`: closed, typed, and
//! read only through [`ImageReleaseManifest::parse`].

use serde::{Deserialize, Serialize};
use std::fmt;

/// The manifest schema this engine reads.
pub const IMAGE_RELEASE_SCHEMA: u32 = 1;
/// The manifest's `kind`, so a release manifest is never read as a build
/// receipt, a pack list or a vault release.
pub const IMAGE_RELEASE_KIND: &str = "oneiron-image-release";

/// A digest string that is not `<algorithm>:<64 lowercase hex>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("expected {0}:<64 lowercase hex>")]
pub struct DigestError(&'static str);

fn lower_hex64(hex: &str) -> bool {
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

macro_rules! labeled_digest {
    ($(#[$doc:meta])* $name:ident, $label:literal) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Parses the labeled wire form.
            pub fn parse(labeled: &str) -> Result<Self, DigestError> {
                labeled
                    .strip_prefix(concat!($label, ":"))
                    .filter(|hex| lower_hex64(hex))
                    .map(|hex| Self(hex.to_owned()))
                    .ok_or(DigestError($label))
            }

            /// A digest the caller computed.
            #[must_use]
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(to_hex(&bytes))
            }

            /// The 64 lowercase hex characters, without the label.
            #[must_use]
            pub fn hex(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = DigestError;

            fn try_from(labeled: String) -> Result<Self, DigestError> {
                Self::parse(&labeled)
            }
        }

        impl From<$name> for String {
            fn from(digest: $name) -> String {
                format!(concat!($label, ":{}"), digest.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($label, ":{}"), self.0)
            }
        }
    };
}

labeled_digest!(
    /// SHA-256, on the wire as `sha256:<64 lowercase hex>`.
    Sha256Digest,
    "sha256"
);
labeled_digest!(
    /// BLAKE3, on the wire as `blake3:<64 lowercase hex>`. The Firecracker
    /// host pins compare BLAKE3, so a rootfs or kernel carries both.
    Blake3Digest,
    "blake3"
);

/// The image family's variants, spelled as `images/release.toml` spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageVariant {
    Base,
    Vault,
    Browser,
    DesktopCua,
    Checker,
    GenericAgent,
}

impl ImageVariant {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Vault => "vault",
            Self::Browser => "browser",
            Self::DesktopCua => "desktop-cua",
            Self::Checker => "checker",
            Self::GenericAgent => "generic-agent",
        }
    }
}

/// The platform one release is built for. Another architecture is its own
/// release, never a field of this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ImageArch {
    #[serde(rename = "linux/amd64")]
    LinuxAmd64,
}

/// A Linux kernel version floor, on the wire as `"<major>.<minor>"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
}

impl KernelVersion {
    #[must_use]
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }
}

impl TryFrom<String> for KernelVersion {
    type Error = ManifestError;

    fn try_from(text: String) -> Result<Self, ManifestError> {
        let number = |part: &str| {
            if part.is_empty() || part.len() > 4 || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            part.parse::<u32>().ok()
        };
        text.split_once('.')
            .and_then(|(major, minor)| Some(Self::new(number(major)?, number(minor)?)))
            .ok_or(ManifestError::Field("host.kernel_floor"))
    }
}

impl From<KernelVersion> for String {
    fn from(version: KernelVersion) -> String {
        format!("{}.{}", version.major, version.minor)
    }
}

/// Why manifest bytes are not a release manifest this engine reads.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("not the closed manifest shape: {0}")]
    Decode(String),
    #[error("manifest schema {0} is not 1")]
    Schema(u32),
    #[error("manifest kind is not oneiron-image-release")]
    Kind,
    #[error("manifest field {0} is malformed")]
    Field(&'static str),
}

/// The signed payload: one image generation of one variant on one platform.
/// The signature covers this file's exact bytes, so no canonical JSON form
/// exists or is needed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageReleaseManifest {
    pub schema: u32,
    pub kind: String,
    pub variant: ImageVariant,
    pub arch: ImageArch,
    /// The generation id: the engine commit's first 12 hex, then the build
    /// receipt's sha256 first 16 hex. Two builds of one commit differ.
    pub generation: String,
    pub engine: EngineRelease,
    pub contracts: ContractRevisions,
    pub artifacts: ReleaseArtifacts,
    pub binaries: GuestBinaries,
    /// No SBOM is produced yet: `null`, never a placeholder.
    pub sbom: Option<DocumentRef>,
    /// The build receipt (`receipt.json`), the build's provenance record.
    pub provenance: Option<DocumentRef>,
    pub host: HostRequirements,
    pub snapshot: SnapshotCompatibility,
    /// What the emitter could not measure, named rather than left as a gap.
    pub facts: Vec<ManifestFact>,
}

/// A measurement the emitter could not make.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestFact {
    /// The emitter ran outside a builder work dir with no BLAKE3 hasher: no
    /// BLAKE3 is listed, so the Firecracker pins cannot bind to this manifest.
    Blake3Unmeasured,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineRelease {
    /// The full 40-hex engine commit every native binary is built from.
    pub commit: String,
    /// The workspace version at that commit.
    pub version: String,
}

/// Contract revisions exactly as `images/release.toml` pins them for the
/// engine commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractRevisions {
    /// The code guest protocol's `Hello { version }`.
    pub guest_protocol: u32,
    /// The checker helper's header version.
    pub checker_helper: u32,
    /// The code-run WIT world, e.g. `oneiron:code-run/guest@1.0.0`.
    pub wit_world: String,
    pub vault: VaultContractRevisions,
    /// The vault storage ABI the image's engine writes; `null` for a variant
    /// that keeps no vault storage.
    pub storage: Option<StorageAbi>,
    /// Contracts with no version constant, named by their source file.
    pub unversioned: UnversionedContracts,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultContractRevisions {
    pub contract_version: u32,
    pub vm_provision_revision: u32,
    pub vm_outbox_wire_revision: u32,
    pub vm_restore_wire_revision: u32,
    pub vm_anchor_wire_revision: u32,
    pub vm_anchor_proxy_revision: u32,
    pub vm_network_revision: u32,
    pub vm_managed_profile_revision: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAbi {
    pub abi_version: u32,
    pub schema_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnversionedContracts {
    pub native_session: SourcePin,
    pub fence_wire: SourcePin,
    pub fence_supervisor: SourcePin,
    pub relay: SourcePin,
}

/// A repo file at the engine commit, by path and sha256.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePin {
    pub path: String,
    pub sha256: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifacts {
    pub oci: OciArtifacts,
    pub rootfs_ext4: FileArtifact,
    pub kernel: KernelRef,
}

/// The OCI form. The image ID (config digest), the distribution manifest
/// digest, the index digest and the saved archive's sha256 are distinct
/// identities and never stand in for one another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciArtifacts {
    /// The tag the archive loads as: a name, not an identity.
    pub reference: String,
    pub index_digest: Sha256Digest,
    pub manifest_digest: Sha256Digest,
    pub config_digest: Sha256Digest,
    pub layer_digest: Sha256Digest,
    pub layer_diff_id: Sha256Digest,
    pub archive: FileArtifact,
}

/// One file of the release, relative to the manifest's directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: Sha256Digest,
    /// `null` only beside the manifest fact `blake3_unmeasured`.
    pub blake3: Option<Blake3Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRef {
    /// The kernel config fragment the kernel is built from.
    pub config: SourcePin,
    /// The kernel image, when the release ships one. The family builder
    /// builds no kernel; an operator-supplied one is listed here.
    pub image: Option<FileArtifact>,
}

/// Engine binaries inside the image, by in-image path and sha256.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestBinaries {
    pub guest: Option<BinaryHash>,
    pub fence: Option<BinaryHash>,
    pub relay: Option<BinaryHash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryHash {
    pub path: String,
    pub sha256: Sha256Digest,
}

/// A document bound by digest, never by URL alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRef {
    pub media_type: String,
    pub path: String,
    pub sha256: Sha256Digest,
}

/// What a host must offer. The manifest states needs; only the host observes
/// what it has.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequirements {
    /// Every launch form needs `/dev/kvm` (the vault boots only as a
    /// microVM). `false` when the OCI form runs without KVM; that variant's
    /// Firecracker form still needs it.
    pub kvm: bool,
    pub kernel_floor: Option<KernelVersion>,
    /// The fence's Landlock ABI floor; `null` without fence plumbing.
    pub landlock_abi_floor: Option<u32>,
    /// The fence's seccomp user notification.
    pub seccomp_user_notify: bool,
}

/// The image half of a snapshot's compatibility tuple: a snapshot restores
/// only onto these exact values, and anything else cold-boots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCompatibility {
    /// No snapshot of this generation is qualified yet.
    pub qualified: bool,
    pub rootfs_ext4_blake3: Option<Blake3Digest>,
    pub kernel_blake3: Option<Blake3Digest>,
    pub guest_protocol: u32,
    pub storage_abi: Option<u32>,
}

impl ImageReleaseManifest {
    /// Decodes and checks the closed shape. Unknown fields, another schema
    /// or kind, a short commit and any absolute or parent-escaping path are
    /// refused.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|e| ManifestError::Decode(e.to_string()))?;
        if manifest.schema != IMAGE_RELEASE_SCHEMA {
            return Err(ManifestError::Schema(manifest.schema));
        }
        if manifest.kind != IMAGE_RELEASE_KIND {
            return Err(ManifestError::Kind);
        }
        let commit = &manifest.engine.commit;
        if commit.len() != 40
            || !commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ManifestError::Field("engine.commit"));
        }
        if !token(&manifest.generation) {
            return Err(ManifestError::Field("generation"));
        }
        let a = &manifest.artifacts;
        let paths = [
            ("artifacts.oci.archive.path", Some(&a.oci.archive.path)),
            ("artifacts.rootfs_ext4.path", Some(&a.rootfs_ext4.path)),
            ("artifacts.kernel.config.path", Some(&a.kernel.config.path)),
            (
                "artifacts.kernel.image.path",
                a.kernel.image.as_ref().map(|k| &k.path),
            ),
            ("sbom.path", manifest.sbom.as_ref().map(|d| &d.path)),
            (
                "provenance.path",
                manifest.provenance.as_ref().map(|d| &d.path),
            ),
        ];
        for (field, path) in paths {
            if path.is_some_and(|p| !relative(p)) {
                return Err(ManifestError::Field(field));
            }
        }
        Ok(manifest)
    }
}

fn token(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

/// A path relative to the manifest's directory: no root, no `..`, no empty
/// or `.` component.
fn relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
