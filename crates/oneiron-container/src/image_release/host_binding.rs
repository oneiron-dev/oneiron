//! The host side of a launch's release observation (FIX 9135, 9137): the
//! release documents the host bound to the selected image, read at launch,
//! and a read-only probe of this host. [`super::verify_release`] stays pure;
//! this child is the one place the release family reads files.
//!
//! [`IMAGE_RELEASE_BINDINGS_ENV`] names a JSON map the host provisioner
//! writes (LC, FIX 9427). It is one closed object from a selected immutable
//! image identity to that image's host-staged documents:
//!
//! ```json
//! {
//!   "sha256:<64 hex>": {
//!     "manifest": "/srv/oneiron/images/browser/image-release.json",
//!     "envelope": null
//!   },
//!   "blake3:<kernel 64 hex>,blake3:<rootfs 64 hex>": {
//!     "manifest": "code/image-release.json",
//!     "envelope": "code/image-release.sig.json"
//!   }
//! }
//! ```
//!
//! An OCI launch is keyed by the digest its pinned reference names: the
//! local image id, or the digest after `@`. A raw Firecracker boot is keyed
//! by the kernel and rootfs BLAKE3 its host pins verified. `envelope` may be
//! `null` or left out (unsigned). A path is absolute, or relative to the
//! map's directory. No guest claim, tag or directory scan selects a document.
//!
//! Nothing here refuses or fails a launch. No map, or no entry for the
//! identity, is `image_release_manifest_absent`. A map that cannot be read
//! or parsed, or a bound document that cannot be read, is
//! `image_release_documents_unavailable`.

use super::{
    Blake3Digest, HostCapabilities, IMAGE_RELEASE_ENVELOPE_FILE, IMAGE_RELEASE_FILE,
    IMAGE_SIGNATURE_POLICY, ImageReleaseObservation, ObservedArtifacts, ReleaseDocuments,
    ReleaseSignatureVerifier, observe_release,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The host config that names the binding map's path.
pub const IMAGE_RELEASE_BINDINGS_ENV: &str = "ONEIRON_IMAGE_RELEASE_BINDINGS";

/// The immutable identity a launch door selected, exactly as the host chose
/// it.
#[derive(Clone, Copy, Debug)]
pub enum SelectedImage<'a> {
    /// A pinned OCI reference, bound by the digest it names.
    Oci(&'a crate::ImageRef),
    /// A raw Firecracker boot: the kernel and rootfs BLAKE3 the host pins
    /// verified against the files about to boot.
    Boot { kernel: [u8; 32], rootfs: [u8; 32] },
}

impl SelectedImage<'_> {
    /// The map key; `None` when the reference names no digest.
    fn key(self) -> Option<String> {
        match self {
            Self::Oci(image) => ObservedArtifacts::from_image_ref(image)
                .oci_image_digest
                .map(String::from),
            Self::Boot { kernel, rootfs } => {
                let kernel = Blake3Digest::from_bytes(kernel);
                let rootfs = Blake3Digest::from_bytes(rootfs);
                Some(format!("{kernel},{rootfs}"))
            }
        }
    }
}

/// One identity's host-staged release documents.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundDocuments {
    manifest: PathBuf,
    #[serde(default)]
    envelope: Option<PathBuf>,
}

/// What the host bound to one selected identity.
enum Binding {
    Unbound,
    Documents {
        manifest: Vec<u8>,
        envelope: Option<Vec<u8>>,
    },
    Unavailable(String),
}

/// The ONE launch-door entry: reads the documents the host bound to
/// `selected`, probes this host when there are documents to check it
/// against, and observes. Infallible: it never refuses or fails a launch.
#[must_use]
pub fn observe_bound_release(
    selected: SelectedImage<'_>,
    observed: &ObservedArtifacts,
    verifier: &dyn ReleaseSignatureVerifier,
) -> ImageReleaseObservation {
    match binding(selected) {
        Binding::Unbound => observe_release(None, observed, &HostCapabilities::default(), verifier),
        Binding::Unavailable(reason) => {
            ImageReleaseObservation::documents_unavailable(reason, IMAGE_SIGNATURE_POLICY)
        }
        Binding::Documents { manifest, envelope } => observe_release(
            Some(ReleaseDocuments {
                manifest: &manifest,
                envelope: envelope.as_deref(),
            }),
            observed,
            &probe_host(),
            verifier,
        ),
    }
}

/// Reads the map at launch. A reason names the document and the error,
/// never a host path.
fn binding(selected: SelectedImage<'_>) -> Binding {
    let Some(map_path) = std::env::var_os(IMAGE_RELEASE_BINDINGS_ENV).filter(|p| !p.is_empty())
    else {
        return Binding::Unbound;
    };
    let map_path = PathBuf::from(map_path);
    let bytes = match read_host_file(&map_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Binding::Unbound,
        Err(error) => return Binding::Unavailable(format!("binding map: {error}")),
    };
    let mut map: BTreeMap<String, BoundDocuments> = match serde_json::from_slice(&bytes) {
        Ok(map) => map,
        Err(error) => return Binding::Unavailable(format!("binding map: {error}")),
    };
    let Some(bound) = selected.key().and_then(|key| map.remove(&key)) else {
        return Binding::Unbound;
    };
    // `join` keeps an absolute path as it is.
    let directory = map_path.parent().unwrap_or(Path::new(""));
    let manifest = match read_host_file(&directory.join(&bound.manifest)) {
        Ok(bytes) => bytes,
        Err(error) => return Binding::Unavailable(format!("{IMAGE_RELEASE_FILE}: {error}")),
    };
    let envelope = match bound
        .envelope
        .map(|path| read_host_file(&directory.join(path)))
        .transpose()
    {
        Ok(envelope) => envelope,
        Err(error) => {
            return Binding::Unavailable(format!("{IMAGE_RELEASE_ENVELOPE_FILE}: {error}"));
        }
    };
    Binding::Documents { manifest, envelope }
}

/// Reads one host-owned regular file whole. A FIFO or a device is not
/// opened, so a misprovisioned path cannot stall a launch.
fn read_host_file(path: &Path) -> std::io::Result<Vec<u8>> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    std::fs::read(path)
}

/// This host's capabilities, measured read-only: the machine and kernel
/// release from `uname`, a usable `/dev/kvm`, the Landlock ABI from the
/// query-only version call, and seccomp user notification from
/// `SECCOMP_GET_ACTION_AVAIL`. Nothing is installed or restricted, and no
/// VM is created. What it cannot measure stays `None`, and `storage_abi`
/// (the vault data owner's) is always `None`. It describes the host that
/// runs the engine and its containers: a microVM guest runs its own kernel,
/// which this does not observe. Off Linux every field is `None`.
#[must_use]
pub fn probe_host() -> HostCapabilities {
    #[cfg(target_os = "linux")]
    {
        probe::host()
    }
    #[cfg(not(target_os = "linux"))]
    {
        HostCapabilities::default()
    }
}

#[cfg(target_os = "linux")]
mod probe {
    use crate::image_release::{HostCapabilities, ImageArch, KernelVersion};
    use std::ffi::CStr;
    use std::io;
    use std::os::fd::AsRawFd;

    /// `_IO(KVMIO, 0x00)` (linux/kvm.h).
    const KVM_GET_API_VERSION: libc::c_ulong = 0xae00;
    /// The one KVM API version Linux ships (linux/kvm.h).
    const KVM_API_VERSION: libc::c_int = 12;
    /// linux/landlock.h.
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    /// linux/seccomp.h.
    const SECCOMP_GET_ACTION_AVAIL: libc::c_uint = 2;
    /// linux/seccomp.h.
    const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

    pub(super) fn host() -> HostCapabilities {
        let (arch, kernel) = uname();
        HostCapabilities {
            arch,
            kvm: kvm(),
            kernel,
            landlock_abi: landlock_abi(),
            seccomp_user_notify: seccomp_user_notify(),
            storage_abi: None,
        }
    }

    /// The machine (only `x86_64` has an [`ImageArch`]) and the kernel
    /// release's `<major>.<minor>`.
    fn uname() -> (Option<ImageArch>, Option<KernelVersion>) {
        // SAFETY: utsname is plain C data, for which all-zero bytes are valid.
        let mut name: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: `name` is a live, writable utsname.
        if unsafe { libc::uname(&mut name) } != 0 {
            return (None, None);
        }
        // SAFETY: uname wrote NUL-terminated fields into the zeroed struct.
        let machine = unsafe { CStr::from_ptr(name.machine.as_ptr()) };
        // SAFETY: as above.
        let release = unsafe { CStr::from_ptr(name.release.as_ptr()) };
        let arch = (machine.to_bytes() == b"x86_64").then_some(ImageArch::LinuxAmd64);
        (arch, release.to_str().ok().and_then(kernel_version))
    }

    /// `6.8` from a release such as `6.8.0-45-generic`.
    fn kernel_version(release: &str) -> Option<KernelVersion> {
        let (major, rest) = release.split_once('.')?;
        let minor = rest.split(|c: char| !c.is_ascii_digit()).next()?;
        Some(KernelVersion::new(major.parse().ok()?, minor.parse().ok()?))
    }

    /// Opens `/dev/kvm` read-write, as a VM needs it, and asks its API
    /// version. A missing or denied device is known unusable; any other
    /// failure stays unobserved.
    fn kvm() -> Option<bool> {
        let device = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
        {
            Ok(device) => device,
            Err(error) => {
                return matches!(
                    error.raw_os_error(),
                    Some(libc::ENOENT | libc::ENODEV | libc::ENXIO | libc::EACCES | libc::EPERM)
                )
                .then_some(false);
            }
        };
        // SAFETY: KVM_GET_API_VERSION takes a zero argument and only returns
        // a value; the fd is live for the call.
        let version = unsafe {
            libc::ioctl(
                device.as_raw_fd(),
                KVM_GET_API_VERSION,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        (version >= 0).then_some(version == KVM_API_VERSION)
    }

    /// The Landlock ABI from the version query, which creates no ruleset.
    /// A kernel with Landlock disabled answers ABI 0.
    fn landlock_abi() -> Option<u32> {
        // SAFETY: the version query takes null attributes and zero size.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0_usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if abi >= 0 {
            return u32::try_from(abi).ok();
        }
        (io::Error::last_os_error().raw_os_error() == Some(libc::EOPNOTSUPP)).then_some(0)
    }

    /// Whether the kernel offers `SECCOMP_RET_USER_NOTIF`, from a query that
    /// installs no filter.
    fn seccomp_user_notify() -> Option<bool> {
        let action = SECCOMP_RET_USER_NOTIF;
        // SAFETY: GET_ACTION_AVAIL reads the one live u32 and changes nothing.
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_GET_ACTION_AVAIL,
                0_u32,
                &raw const action,
            )
        };
        if result == 0 {
            return Some(true);
        }
        (io::Error::last_os_error().raw_os_error() == Some(libc::EOPNOTSUPP)).then_some(false)
    }
}
